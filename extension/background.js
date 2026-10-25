// DemiPass background service worker — the only part of the extension that
// talks to the API, holds tokens, or touches a secret value.
//
// Value hygiene: a value lives in a local variable (or, for a pending save,
// in the in-memory `pending` map with a TTL) and nowhere else. It is never
// logged, stored, put in a badge/title/notification, or sent to UI pages.

import { ApiClient, ApiError, NotPairedError, waitForFill, waitForPairing } from './lib/api.js';
import { normalizeOrigin, normalizeApiBase, DEFAULT_API_BASE, suggestLoginName } from './lib/origin.js';
import { chromeTokenStore } from './lib/token-store.js';

const EXT_ORIGIN = new URL(chrome.runtime.getURL('')).origin;
const CLIENT_LABEL = 'DemiPass browser extension';
const PENDING_TTL_MS = 3 * 60 * 1000;
const MAX_PENDING = 20;
const MAX_VALUE = 10000;

const tokens = chromeTokenStore();
let apiBase = DEFAULT_API_BASE;
let client = new ApiClient({ base: apiBase, fetch: (...a) => fetch(...a), tokens });

const ready = (async () => {
  const r = await chrome.storage.local.get('dp_api_base');
  const base = normalizeApiBase(r.dp_api_base);
  if (base && base !== apiBase) {
    apiBase = base;
    client = new ApiClient({ base, fetch: (...a) => fetch(...a), tokens });
  }
})();

// ---- keepalive ---------------------------------------------------------------
// An idle MV3 worker is stopped after ~30 s, which would drop a pending save
// (memory only) long before its TTL. While something is in flight, a cheap
// extension API call every 20 s resets the idle timer. It stops on its own.
let keepAliveTimer = null;
function busy() {
  if (pending.size > 0) return true;
  if (pairing && pairing.state === 'pending') return true;
  for (const j of fills.values()) if (['requesting', 'pending', 'approved', 'filling'].includes(j.state)) return true;
  return false;
}
function keepAlive() {
  if (keepAliveTimer) return;
  keepAliveTimer = setInterval(() => {
    if (!busy()) { clearInterval(keepAliveTimer); keepAliveTimer = null; return; }
    chrome.runtime.getPlatformInfo().catch(() => {});
  }, 20_000);
}

// ---- frames: what the browser told us about each document ------------------
// tabId -> Map(documentId -> { frameId, origin, hasLogin })
const frames = new Map();

function recordFrame(sender, hasLogin) {
  const origin = normalizeOrigin(sender.origin || '');
  const tabId = sender.tab.id;
  if (!frames.has(tabId)) frames.set(tabId, new Map());
  const m = frames.get(tabId);
  for (const [doc, rec] of m) if (rec.frameId === sender.frameId && doc !== sender.documentId) m.delete(doc);
  m.set(sender.documentId, { frameId: sender.frameId, origin, hasLogin: !!hasLogin });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  frames.delete(tabId);
  for (const [id, p] of pending) if (p.tabId === tabId) dropPending(id);
});

// ---- pending ingress (memory only, short TTL) -------------------------------
// id -> { kind: 'login' | 'selection', value, login, origin, tabId, expiresAt, timer }
const pending = new Map();

function newId() {
  return Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, '0')).join('');
}

function addPending(item) {
  if (item.kind === 'login') {
    for (const [id, p] of pending) if (p.kind === 'login' && p.tabId === item.tabId) dropPending(id);
  }
  while (pending.size >= MAX_PENDING) dropPending(pending.keys().next().value);
  const id = newId();
  item.expiresAt = Date.now() + PENDING_TTL_MS;
  item.timer = setTimeout(() => dropPending(id), PENDING_TTL_MS);
  pending.set(id, item);
  if (item.kind === 'login') setSaveBadge(item.tabId, true);
  keepAlive();
  return id;
}

function dropPending(id) {
  const p = pending.get(id);
  if (!p) return;
  clearTimeout(p.timer);
  p.value = null;
  pending.delete(id);
  if (p.kind === 'login') setSaveBadge(p.tabId, false);
}

function takePending(id) {
  const p = pending.get(id);
  if (!p || p.expiresAt < Date.now()) { dropPending(id); return null; }
  const value = p.value;
  const meta = { kind: p.kind, login: p.login, origin: p.origin, tabId: p.tabId };
  dropPending(id);
  return { value, ...meta };
}

function pendingLoginFor(tabId) {
  for (const [id, p] of pending) {
    if (p.kind === 'login' && p.tabId === tabId && p.expiresAt > Date.now()) return { id, origin: p.origin, login: p.login };
  }
  return null;
}

function setSaveBadge(tabId, on) {
  if (typeof tabId !== 'number') return;
  chrome.action.setBadgeText({ tabId, text: on ? 'SAVE' : '' }).catch(() => {});
  if (on) chrome.action.setBadgeBackgroundColor({ tabId, color: '#2563eb' }).catch(() => {});
}

chrome.tabs.onUpdated.addListener((tabId, info) => {
  // A top-level navigation replaces every document in the tab; the new ones
  // announce themselves again. An in-flight fill for an old document is refused.
  if (info.status === 'loading') frames.delete(tabId);
  if (info.status === 'complete' && pendingLoginFor(tabId)) setSaveBadge(tabId, true);
});

// ---- pairing ---------------------------------------------------------------
let pairing = null; // { device_code, user_code, verification_url, verification_url_complete, expires_at, state, loop }

function agentLabel() {
  const p = (navigator.userAgentData && navigator.userAgentData.platform) || '';
  return p ? `${CLIENT_LABEL} (${p})` : CLIENT_LABEL;
}

async function startPairing() {
  await ready;
  cancelPairing();
  const p = await client.startPairing(agentLabel());
  pairing = { ...p, expires_at: Date.now() + p.expires_in * 1000, state: 'pending' };
  // storage.session: memory only, trusted contexts only; lets a restarted worker resume.
  await chrome.storage.session.set({ dp_pairing: { ...pairing } });
  runPairingLoop();
  keepAlive();
  return publicPairing();
}

function runPairingLoop() {
  if (!pairing || pairing.loop) return;
  const mine = pairing;
  mine.loop = waitForPairing(client, mine.device_code, {
    interval: mine.interval,
    expiresIn: Math.max(0, (mine.expires_at - Date.now()) / 1000),
    isCancelled: () => pairing !== mine,
  }).then((r) => { mine.state = r.state; })
    .catch((e) => { mine.state = 'error'; mine.error = safeError(e); })
    .finally(() => {
      mine.loop = null;
      if (mine.state !== 'pending') chrome.storage.session.remove('dp_pairing').catch(() => {});
    });
}

function cancelPairing() {
  pairing = null;
  chrome.storage.session.remove('dp_pairing').catch(() => {});
}

async function resumePairing() {
  if (pairing) return;
  const r = await chrome.storage.session.get('dp_pairing');
  if (r.dp_pairing && r.dp_pairing.expires_at > Date.now()) {
    pairing = { ...r.dp_pairing, loop: null, state: 'pending' };
    runPairingLoop();
    keepAlive();
  }
}

function publicPairing() {
  if (!pairing) return null;
  return {
    state: pairing.state,
    user_code: pairing.user_code,
    verification_url: pairing.verification_url,
    verification_url_complete: pairing.verification_url_complete,
    expires_at: pairing.expires_at,
    error: pairing.error || null,
  };
}

// ---- page context ------------------------------------------------------------

async function askFramesToAnnounce(tabId) {
  try { await chrome.tabs.sendMessage(tabId, { type: 'dp:announce' }); } catch {}
  if (!frames.get(tabId) || frames.get(tabId).size === 0) {
    // No content script yet (tab opened before install): inject it. Needs the
    // activeTab grant from opening the popup.
    try {
      await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, files: ['content/form-detect.js', 'content/content.js'] });
    } catch {}
  }
  await new Promise((r) => setTimeout(r, 250));
}

// One fill target per origin: a frame with a login form if any, else the top frame.
function fillTargets(tabId) {
  const m = frames.get(tabId);
  if (!m) return [];
  const byOrigin = new Map();
  for (const [documentId, rec] of m) {
    if (!rec.origin) continue;
    const cur = byOrigin.get(rec.origin);
    const score = (r) => (r.hasLogin ? 2 : 0) + (r.frameId === 0 ? 1 : 0);
    if (!cur || score(rec) > score(cur.rec)) byOrigin.set(rec.origin, { documentId, rec });
  }
  return [...byOrigin.values()]
    .filter(({ rec }) => rec.hasLogin || rec.frameId === 0)
    .sort((a, b) => a.rec.frameId - b.rec.frameId)
    .map(({ documentId, rec }) => ({ documentId, frameId: rec.frameId, origin: rec.origin, hasLogin: rec.hasLogin }));
}

async function topOrigin(tabId) {
  const m = frames.get(tabId);
  if (m) for (const rec of m.values()) if (rec.frameId === 0 && rec.origin) return rec.origin;
  try {
    const tab = await chrome.tabs.get(tabId);
    return normalizeOrigin(tab.url || '');
  } catch { return null; }
}

async function pageContext(tabId) {
  await ready;
  await resumePairing();
  const paired = await client.isPaired();
  const out = {
    paired,
    apiBase,
    devServer: apiBase !== DEFAULT_API_BASE,
    pairing: publicPairing(),
    topOrigin: null,
    targets: [],
    pendingLogin: null,
    error: null,
  };
  if (typeof tabId !== 'number') return out;
  if (!frames.get(tabId) || frames.get(tabId).size === 0) await askFramesToAnnounce(tabId);
  out.topOrigin = await topOrigin(tabId);
  const pl = pendingLoginFor(tabId);
  out.targets = fillTargets(tabId);
  if (!paired) {
    if (pl) out.pendingLogin = { ...pl, suggestedName: suggestLoginName(pl.origin, pl.login), existing: null };
    return out;
  }
  try {
    for (const t of out.targets) t.candidates = await client.candidates(t.origin);
  } catch (e) {
    out.error = safeError(e);
    if (e instanceof NotPairedError) out.paired = false;
  }
  if (pl) {
    const all = out.targets.filter((t) => t.origin === pl.origin).flatMap((t) => t.candidates || []);
    const existing = all.find((c) => c.username && c.username === pl.login) || null;
    out.pendingLogin = { ...pl, suggestedName: existing ? existing.name : suggestLoginName(pl.origin, pl.login), existing: existing ? existing.name : null };
  }
  return out;
}

// ---- fill ------------------------------------------------------------------
// fillId -> { state, origin, name, error, cancelled }
const fills = new Map();

// Runs inside the target frame, in the extension's isolated world. The origin
// check here runs in the same task as the fill, so nothing can navigate the
// frame between the check and the write.
function injectedFill(expectedOrigin, username, password) {
  if (location.origin !== expectedOrigin) return { ok: false, error: 'origin_changed' };
  const D = globalThis.DemiPassFormDetect;
  if (!D) return { ok: false, error: 'detector_missing' };
  const f = D.findLoginFields(document);
  if (!f || !f.password) return { ok: false, error: 'no_login_form' };
  let user = false;
  if (f.username && username) { D.setInputValue(f.username, username); user = true; }
  D.setInputValue(f.password, password);
  return { ok: true, username: user, password: true };
}

function startFill(tabId, documentId, ref) {
  const fillId = newId();
  const job = { state: 'requesting', origin: null, name: null, error: null, cancelled: false };
  fills.set(fillId, job);
  keepAlive();
  setTimeout(() => fills.delete(fillId), 10 * 60 * 1000);
  runFill(job, tabId, documentId, ref).catch((e) => {
    job.state = e instanceof NotPairedError ? 'unpaired' : 'error';
    job.error = safeError(e);
  });
  return fillId;
}

async function runFill(job, tabId, documentId, ref) {
  await ready;
  const rec = frames.get(tabId)?.get(documentId);
  if (!rec || !rec.origin) { job.state = 'error'; job.error = 'That page is gone or cannot be filled.'; return; }
  const origin = rec.origin; // set by the browser (MessageSender.origin), never by the page
  job.origin = origin;

  let req;
  try {
    req = await client.requestFill(ref, origin, CLIENT_LABEL);
  } catch (e) {
    if (e instanceof ApiError && e.status === 403) {
      job.state = 'refused';
      job.error = `This entry is not bound to ${origin}.`;
      return;
    }
    throw e;
  }
  job.state = req.status === 'approved' ? 'approved' : 'pending';

  // Stop polling (and never redeem) once the document is gone or changed origin.
  const docGone = () => frames.get(tabId)?.get(documentId)?.origin !== origin;
  const r = await waitForFill(client, req.request_id, {
    expiresIn: req.expires_in,
    isCancelled: () => job.cancelled || docGone(),
  });
  if (r.state === 'cancelled' && !job.cancelled) {
    job.state = 'refused'; job.error = 'The page changed before the fill; nothing was filled.'; return;
  }
  if (r.state !== 'approved') { job.state = r.state; return; }

  let fill = r.fill;
  r.fill = null;
  try {
    job.name = fill.name || null;
    job.state = 'filling';
    if (normalizeOrigin(fill.origin) !== origin || (fill.ref && fill.ref !== ref)) {
      job.state = 'refused'; job.error = 'The server answered for a different site; nothing was filled.'; return;
    }
    // Re-check against the browser's view: same document, same origin.
    const now = frames.get(tabId)?.get(documentId);
    if (!now || now.origin !== origin) {
      job.state = 'refused'; job.error = 'The page changed before the fill; nothing was filled.'; return;
    }
    const target = { tabId, documentIds: [documentId] };
    await chrome.scripting.executeScript({ target, files: ['content/form-detect.js'] });
    const [res] = await chrome.scripting.executeScript({ target, func: injectedFill, args: [origin, fill.username, fill.value] });
    const out = res && res.result;
    if (out && out.ok) { job.state = 'done'; job.filledUsername = !!out.username; }
    else { job.state = 'refused'; job.error = fillErrorText(out && out.error); }
  } catch {
    job.state = 'error'; job.error = 'Could not reach the page to fill it.';
  } finally {
    if (fill) fill.value = null;
    fill = null;
  }
}

function fillErrorText(code) {
  if (code === 'origin_changed') return 'The page changed before the fill; nothing was filled.';
  if (code === 'no_login_form') return 'No login form found on the page.';
  return 'The fill did not complete.';
}

// ---- store -----------------------------------------------------------------

async function storeEntry(entry) {
  await ready;
  try {
    const out = await client.store(entry);
    return { ok: true, name: out.name, ref: out.ref };
  } finally {
    entry.value = null;
  }
}

function cleanName(name) {
  const n = String(name || '').trim();
  if (!n || n.length > 64) throw new UserError('Name must be 1–64 characters.');
  return n;
}

class UserError extends Error {}

// ---- context menu: store selected text -----------------------------------

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: 'dp-store-selection', title: 'Store in DemiPass', contexts: ['selection'] }, () => void chrome.runtime.lastError);
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'dp-store-selection') return;
  const value = typeof info.selectionText === 'string' ? info.selectionText.trim() : '';
  if (!value || value.length > MAX_VALUE) return;
  const origin = normalizeOrigin(info.frameUrl || info.pageUrl || '');
  const id = addPending({ kind: 'selection', value, login: '', origin, tabId: tab ? tab.id : null });
  await chrome.windows.create({ url: chrome.runtime.getURL('ui/save.html#' + id), type: 'popup', width: 440, height: 520 });
});

// ---- messages --------------------------------------------------------------

function isExtensionPage(sender) {
  return sender.id === chrome.runtime.id && typeof sender.url === 'string' && new URL(sender.url).origin === EXT_ORIGIN;
}

function isContentScript(sender) {
  return sender.id === chrome.runtime.id && sender.tab && typeof sender.tab.id === 'number'
    && typeof sender.frameId === 'number' && typeof sender.documentId === 'string'
    && !(typeof sender.url === 'string' && sender.url.startsWith(EXT_ORIGIN));
}

function safeError(e) {
  if (e instanceof UserError) return e.message;
  if (e instanceof NotPairedError) return 'Not paired with DemiPass.';
  if (e instanceof ApiError) {
    if (e.status === 0) return 'Could not reach DemiPass.';
    return `DemiPass said: ${e.code || 'HTTP ' + e.status}`;
  }
  return 'Something went wrong.';
}

async function handleContent(msg, sender) {
  if (msg.type === 'dp:frame') {
    recordFrame(sender, msg.hasLogin);
    return { ok: true };
  }
  if (msg.type === 'dp:capture') {
    const origin = normalizeOrigin(sender.origin || '');
    const password = typeof msg.password === 'string' ? msg.password : '';
    const login = typeof msg.login === 'string' ? msg.login.slice(0, 256) : '';
    if (!origin || !password || password.length > MAX_VALUE) return { ok: false };
    recordFrame(sender, true);
    addPending({ kind: 'login', value: password, login, origin, tabId: sender.tab.id });
    return { ok: true };
  }
  return { ok: false };
}

async function handleUi(msg) {
  switch (msg.type) {
    case 'ui:context':
      return { ok: true, ...(await pageContext(msg.tabId)) };
    case 'ui:pair':
      return { ok: true, pairing: await startPairing() };
    case 'ui:pairCancel':
      cancelPairing();
      return { ok: true };
    case 'ui:signOut': {
      await ready;
      cancelPairing();
      return { ok: true, ...(await client.signOut()) };
    }
    case 'ui:fill':
      if (typeof msg.tabId !== 'number' || typeof msg.documentId !== 'string' || typeof msg.ref !== 'string') throw new UserError('Bad fill request.');
      return { ok: true, fillId: startFill(msg.tabId, msg.documentId, msg.ref) };
    case 'ui:fillStatus': {
      const j = fills.get(msg.fillId);
      if (!j) return { ok: false, error: 'Unknown fill.' };
      return { ok: true, state: j.state, origin: j.origin, name: j.name, error: j.error, filledUsername: !!j.filledUsername };
    }
    case 'ui:fillCancel': {
      const j = fills.get(msg.fillId);
      if (j) j.cancelled = true;
      return { ok: true };
    }
    case 'ui:addManual': {
      const origin = await topOrigin(msg.tabId);
      if (!origin) throw new UserError('This page cannot hold a DemiPass login (https only, or http on localhost).');
      const value = typeof msg.password === 'string' ? msg.password : '';
      if (!value || value.length > MAX_VALUE) throw new UserError('Password is required.');
      const login = String(msg.login || '').trim().slice(0, 256);
      return storeEntry({ name: cleanName(msg.name), value, secret_type: 'password', login, origins: [origin] });
    }
    case 'ui:pendingInfo': {
      const p = pending.get(msg.id);
      if (!p || p.expiresAt < Date.now()) return { ok: false, error: 'This save has expired. Select the text and try again.' };
      return { ok: true, kind: p.kind, origin: p.origin, login: p.login, length: p.value.length, expiresAt: p.expiresAt };
    }
    case 'ui:savePending': {
      const name = cleanName(msg.name);
      const types = new Set(['api_key', 'oauth_token', 'password', 'other']);
      const p = takePending(msg.id);
      if (!p) throw new UserError('This save has expired.');
      const entry = { name, value: p.value, secret_type: p.kind === 'login' ? 'password' : (types.has(msg.secret_type) ? msg.secret_type : 'api_key') };
      if (p.kind === 'login') { entry.login = p.login; entry.origins = [p.origin]; }
      else if (msg.bindOrigin && p.origin) entry.origins = [p.origin];
      p.value = null;
      return storeEntry(entry);
    }
    case 'ui:dismissPending':
      dropPending(msg.id);
      return { ok: true };
    case 'ui:getSettings':
      await ready;
      return { ok: true, apiBase, defaultBase: DEFAULT_API_BASE };
    case 'ui:setApiBase': {
      await ready;
      const base = normalizeApiBase(msg.base);
      if (!base) throw new UserError('Only https://api.dustforge.com or a localhost / 127.0.0.1 dev server.');
      if (base !== apiBase) {
        cancelPairing();
        await client.signOut().catch(() => {});
        apiBase = base;
        client = new ApiClient({ base, fetch: (...a) => fetch(...a), tokens });
        await chrome.storage.local.set({ dp_api_base: base });
      }
      return { ok: true, apiBase };
    }
    default:
      throw new UserError('Unknown request.');
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg.type !== 'string') return false;
  let p;
  if (msg.type.startsWith('dp:') && isContentScript(sender)) p = handleContent(msg, sender);
  else if (msg.type.startsWith('ui:') && isExtensionPage(sender)) p = handleUi(msg);
  else return false;
  p.then(sendResponse, (e) => sendResponse({ ok: false, error: safeError(e) }));
  return true;
});
