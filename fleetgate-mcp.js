#!/usr/bin/env node
'use strict';
/**
 * FLEETGATE MCP server — any agent pane onto the FLEETGATE release gate, as its own DemiPass wallet.
 *
 * FLEETGATE is a DemiPass service tenant (dustforge docs/service-tenants.md); the door (atlas/boltcluster fleet/door)
 * takes pull requests from any wallet that consents to pay it. Onboarding is the same path as Conduit's
 * (services().onboard): a consent the wallet's person approves in the DemiPass app, then a service token
 * (aud svc:fleetgate) minted from this pane's own session. The token lives in this process's memory only: it is never
 * printed, returned or written to disk, and is re-minted when it expires (24 h at most) or the door answers 401.
 *
 *   fleetgate_onboard({daily_cap_dd?, approval_id?})   consent (one app approval, once per wallet) + token
 *   fleetgate_prices()                                  the door's public price list
 *   fleetgate_submit({repo, title, files, body?, submission_id?})   one PR into atlas/<repo>; charged once (submit + review round)
 *   fleetgate_status()                                  onboarded? token expiry, consent, door health
 *
 * The gate decides: a submitted PR is evaluated by the release controller under the signed charter like any other.
 * Nothing here merges, approves, reviews or touches a charter.
 *
 * Env: DEMIPASS_TOKEN (this pane's DemiPass session), DEMIPASS_URL, FLEETGATE_DOOR_URL
 *      (default https://repo.dustroot.com/-/fleetgate/door), FLEETGATE_DAILY_CAP_DD (default 3000).
 */
const crypto = require('crypto');
const { services } = require('./services.js');
// This machine's live DemiPass session (DEMIPASS_TOKEN, else the demipass MCP entry, else the SDK login), read each
// time it is needed: the MCP config entry holds no copy of it (#17 review M2).
const { sessionToken, consentAtLeast } = require('./onboard.js');

const DEMIPASS_URL = (process.env.DEMIPASS_URL || 'https://api.dustforge.com').replace(/\/$/, '');
const DOOR_DEFAULT = 'https://repo.dustroot.com/-/fleetgate/door';
// The door: FLEETGATE_DOOR_URL, else the endpoint FLEETGATE registered with DemiPass (GET /api/services/fleetgate),
// else the default. https only, except a loopback host (tests) — the service token goes there (#17 review L2).
function doorRefusal(u) {
  let x; try { x = new URL(u); } catch (_) { return 'not a URL'; }
  if (x.protocol === 'https:') return null;
  if (x.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(x.hostname)) return null;
  return 'the door must be https';
}
let doorCached = null;
async function door() {
  if (doorCached) return doorCached;
  let u = process.env.FLEETGATE_DOOR_URL || '';
  if (!u) { try { const r = await http('GET', DEMIPASS_URL + '/api/services/fleetgate'); if (r.status === 200 && r.data && r.data.endpoint) u = r.data.endpoint; } catch (_) {} }
  u = (u || DOOR_DEFAULT).replace(/\/+$/, '');
  const bad = doorRefusal(u); if (bad) throw new Error(`FLEETGATE door ${u}: ${bad}`);
  return (doorCached = u);
}
const DEFAULT_CAP = Number(process.env.FLEETGATE_DAILY_CAP_DD || 3000);   // one submission is ~700 DD (submit + review round)
const SERVICE = 'fleetgate';

function dp() { return services({ token: sessionToken(), baseUrl: DEMIPASS_URL }); }

// The service token: memory only.
let held = null;   // { token, token_id, expires_at, cap_dd }
let consentSeen = null;
const pendingCaps = new Map();   // approval_id → the daily cap asked for: redeeming must repeat it (#17 review L4)
// Token check before holding it: what the door accepts, so a malformed mint can never end up in a header error (L1).
const TOKEN_RE = /^[A-Za-z0-9_.-]{20,4096}$/;
const live = () => held && Date.parse(held.expires_at) - Date.now() > 60 * 1000;

async function onboard({ daily_cap_dd, approval_id } = {}, { fileConsent = true } = {}) {
  if (!sessionToken()) return { ok: false, error: process.env.DEMIPASS_EXPECT_DID ? `no DemiPass session for ${process.env.DEMIPASS_EXPECT_DID} (the wallet this server was onboarded as) on this machine` : 'no DemiPass session on this machine: sign in first (demipass_login, or set DEMIPASS_TOKEN)' };
  if (approval_id && !daily_cap_dd && pendingCaps.has(Number(approval_id))) daily_cap_dd = pendingCaps.get(Number(approval_id));
  if (!fileConsent) {
    // Submitting never files a consent (#17 review L3): after a person said no, a submit must not ask their phone again.
    const all = await dp().consents();
    if (!(all.mine || []).some(c => c.service === SERVICE && c.status === 'active')) return { ok: false, status: 'not_onboarded', error: 'not onboarded: run fleetgate_onboard and approve it in the DemiPass app' };
  }
  // services().onboard's two steps; the token carries a follow-up budget so the submission's review rounds can bill.
  const api = dp();
  const c = await consentAtLeast(api, { service: SERVICE, cap: daily_cap_dd || DEFAULT_CAP, explicit: Boolean(daily_cap_dd), approvalId: approval_id });
  let r = c;
  if (!c.pending) {
    // Ordinary charges (the door's intake) stay under the server's default cap; the review rounds a submission starts
    // bill afterwards against the follow-up budget, up to the whole daily consent (the door needs at least ~one round).
    const t = await api.mintToken({ service: SERVICE, ttl: '24h', followUpDd: c.consent.daily_cap_dd });
    r = { consent: c.consent, existing: c.existing, token: { token: t.token, token_id: t.token_id, expires_at: t.expires_at, cap_dd: t.cap_dd } };
  }
  if (r.pending) {
    pendingCaps.set(Number(r.pending.approval_id), r.pending.daily_cap_dd);
    return { ok: false, status: 'approval_pending', approval_id: r.pending.approval_id, expires_at: r.pending.expires_at, daily_cap_dd: r.pending.daily_cap_dd,
             next: `Approve "let a wallet pay fleetgate" (${r.pending.daily_cap_dd} DD/day) in the DemiPass app (Requests), then call fleetgate_onboard again with approval_id ${r.pending.approval_id} and daily_cap_dd ${r.pending.daily_cap_dd}.` };
  }
  if (!TOKEN_RE.test(String(r.token.token || ''))) return { ok: false, error: 'DemiPass returned a malformed service token; not held' };
  held = { token: r.token.token, token_id: r.token.token_id, expires_at: r.token.expires_at, cap_dd: r.token.cap_dd };
  consentSeen = r.consent || consentSeen;
  const price = await submitPrice();
  const low = price && r.consent && r.consent.daily_cap_dd < price;
  return { ok: true, service: SERVICE, consent: r.consent ? { id: r.consent.id, daily_cap_dd: r.consent.daily_cap_dd, existing: Boolean(r.existing) } : null,
           token_id: held.token_id, expires_at: held.expires_at, cap_dd: held.cap_dd,
           ...(low ? { warning: `your daily consent (${r.consent.daily_cap_dd} DD) is below one submission (${price} DD): every submit would be refused. Call fleetgate_onboard with a higher daily_cap_dd to replace it (one approval).` } : {}) };
}

// A live token, minting one when the consent already exists; an onboarding that needs an approval is reported, not waited on.
async function submitPrice() {
  try { const r = await http('GET', (await door()) + '/v1/prices'); const a = ((r.data && r.data.actions) || []); return a.filter(x => ['submit', 'review'].includes(x.action)).reduce((n, x) => n + (x.price_dd || 0), 0) || null; }
  catch (_) { return null; }
}
async function token() {
  if (live()) return held.token;
  const r = await onboard({}, { fileConsent: false });
  if (!r.ok) throw Object.assign(new Error(r.error || 'not onboarded: run fleetgate_onboard and approve it in the DemiPass app'), { result: r });
  return held.token;
}

async function http(method, url, { auth, body } = {}) {
  const headers = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (auth) headers.authorization = 'Bearer ' + auth;
  const r = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(180000) });
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch (_) { data = { raw: text.slice(0, 500) }; }
  return { status: r.status, data };
}

const SUBMISSION_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;   // the door's own pattern
async function submit({ repo, title, body, files, submission_id }) {
  if (!repo || !/^[A-Za-z0-9._-]{1,100}$/.test(repo)) return { ok: false, error: 'repo: the name of a repo under atlas/ (e.g. boltcluster)' };
  if (!title) return { ok: false, error: 'title required' };
  if (!Array.isArray(files) || !files.length) return { ok: false, error: 'files: [{path, content}] (the whole new content of each file)' };
  const sid = submission_id || crypto.randomBytes(12).toString('hex');
  if (!SUBMISSION_RE.test(sid)) return { ok: false, error: 'submission_id: 8-64 letters, digits, _ or -, starting with a letter or digit' };
  const payload = { submission_id: sid, repo, title, ...(body ? { body } : {}), files };
  const url = (await door()) + '/v1/pulls';
  let r;
  try {
    r = await http('POST', url, { auth: await token(), body: payload });
    if (r.status === 401) { held = null; r = await http('POST', url, { auth: await token(), body: payload }); }   // expired or revoked: re-mint once
  } catch (e) {
    // The door may have charged before the connection dropped: hand back the id, so the retry replays (#17 review H1).
    if (e.result) return { ...e.result, submission_id: sid };
    return { ok: false, submission_id: sid, error: e.name === 'TimeoutError' ? 'the door timed out' : 'the door could not be reached',
             next: `Retry fleetgate_submit with submission_id "${sid}": if the door already charged, it replays that charge and finds the PR.` };
  }
  if (r.status === 201) return { ok: true, submission_id: sid, ...r.data, note: 'The release controller evaluates it under the signed charter. A retry with the same submission_id replays, never double-charges.' };
  return { ok: false, http_status: r.status, submission_id: sid, ...(r.data || {}),
           ...(r.status === 402 ? { hint: 'DemiPass refused the charge: no consent, not enough DD, or a cap. Nothing was created.' } : {}) };
}

async function status() {
  const health = await http('GET', (await door()) + '/health').catch(e => ({ status: 0, data: { error: e.message } }));
  return { ok: true, door: await door(), door_health: health.status === 200 ? health.data : { http_status: health.status, ...(health.data || {}) },
           onboarded: Boolean(live()), token_id: live() ? held.token_id : null, expires_at: live() ? held.expires_at : null,
           consent: consentSeen ? { id: consentSeen.id, daily_cap_dd: consentSeen.daily_cap_dd } : null };
}

const TOOLS = [
  { name: 'fleetgate_onboard',
    description: 'FLEETGATE: put this pane on the FLEETGATE release gate as its own DemiPass wallet. Checks for a consent to pay fleetgate; if there is none it files one (status approval_pending + approval_id) — the person approves it in the DemiPass app, then call again with approval_id. Then mints a fleetgate service token held only inside this MCP server (never shown). Run once per pane; re-minting after expiry is automatic.',
    inputSchema: { type: 'object', properties: {
      daily_cap_dd: { type: 'integer', description: `Most fleetgate may charge this wallet per 24 h (default ${DEFAULT_CAP}; one submission is about 700 DD)` },
      approval_id: { type: 'integer', description: 'The approval_id from an earlier approval_pending answer, once approved in the app' } } } },
  { name: 'fleetgate_prices', description: 'FLEETGATE: the door\'s public price list (DD per action, margin included).', inputSchema: { type: 'object', properties: {} } },
  { name: 'fleetgate_submit',
    description: 'FLEETGATE: submit a pull request to a chartered repo under atlas/ through the door. Charged once (submit + one review round, see fleetgate_prices) to this pane\'s wallet. The gate evaluates it under the signed charter; this never merges or reviews. Not allowed: dotfiles, charters/, fleet/{controller,review,ci,door}/; at most 20 files, 128 KB each, 384 KB in all.',
    inputSchema: { type: 'object', required: ['repo', 'title', 'files'], properties: {
      repo: { type: 'string', description: 'Repo name under atlas/ (e.g. boltcluster)' },
      title: { type: 'string' }, body: { type: 'string', description: 'PR description' },
      files: { type: 'array', items: { type: 'object', required: ['path', 'content'], properties: { path: { type: 'string' }, content: { type: 'string', description: 'The whole new file content' } } } },
      submission_id: { type: 'string', description: 'Idempotency key (8-64 of A-Z a-z 0-9 _ -). Reuse it to retry the same submission without a second charge; omitted → a fresh one, returned.' } } } },
  { name: 'fleetgate_status', description: 'FLEETGATE: is this pane onboarded (token id and expiry, consent), and is the door up.', inputSchema: { type: 'object', properties: {} } },
];
const HANDLERS = {
  fleetgate_onboard: onboard,
  fleetgate_prices: async () => { const r = await http('GET', (await door()) + '/v1/prices'); return r.status === 200 ? { ok: true, ...r.data } : { ok: false, http_status: r.status, ...(r.data || {}) }; },
  fleetgate_submit: submit,
  fleetgate_status: status,
};

// Errors never carry the token: a ServiceError's body is DemiPass's answer, and our own errors name no secret.
function scrub(x) { const t = held && held.token; return t ? JSON.parse(JSON.stringify(x).split(t).join('[token]')) : x; }
function errBody(e) { return { ok: false, error: e.message, ...(e.result || {}), ...(e.body && typeof e.body === 'object' ? { demipass: e.body } : {}), ...(e.status ? { http_status: e.status } : {}) }; }

async function handleMessage(msg) {
  const { id, method, params } = msg;
  if (method === 'initialize') return { jsonrpc: '2.0', id, result: { protocolVersion: (params && params.protocolVersion) || '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'fleetgate', version: require('./package.json').version } } };
  if (method === 'notifications/initialized' || (method && method.startsWith('notifications/'))) return null;
  if (method === 'ping') return { jsonrpc: '2.0', id, result: {} };
  if (method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
  if (method === 'tools/call') {
    const h = HANDLERS[params && params.name];
    if (!h) return { jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${params && params.name}` } };
    let out; try { out = await h((params && params.arguments) || {}); } catch (e) { out = errBody(e); }
    out = scrub(out);
    return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }], ...(out && out.ok === false ? { isError: true } : {}) } };
  }
  if (id === undefined) return null;
  return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
}

module.exports = { handleMessage, _reset: () => { held = null; consentSeen = null; doorCached = null; pendingCaps.clear(); } };

if (require.main === module) {
  // Messages are answered in order through one queue; stdin closing waits for the queue (a call in flight is answered).
  let buf = '', queue = Promise.resolve();
  const answer = line => async () => {
    let msg; try { msg = JSON.parse(line); if (!msg || typeof msg !== 'object' || Array.isArray(msg)) throw new Error('not a request'); } catch (_) { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n'); return; }
    const r = await handleMessage(msg).catch(e => ({ jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32603, message: String(scrub(e.message)) } }));
    if (r) process.stdout.write(JSON.stringify(r) + '\n');
  };
  process.stdin.setEncoding('utf-8');
  process.stdin.on('data', chunk => {
    buf += chunk; let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
      if (line) queue = queue.then(answer(line));
    }
  });
  process.stdin.on('end', () => { const last = buf.trim(); if (last) queue = queue.then(answer(last)); queue.then(() => process.exit(0)); });
  process.stdout.on('error', () => process.exit(0));
}
