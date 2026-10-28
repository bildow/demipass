// Popup. It never sees a stored value: it shows names and usernames, and the
// only value it handles is the password a person types into "Add for this site",
// which goes straight to the background worker.

import { ext } from '../lib/browser.js';

const $ = (id) => document.getElementById(id);
const send = (msg) => ext.runtime.sendMessage(msg);

// ?tab=<id> lets the popup be opened as a page for a given tab (tests,
// pop-out). Extension pages are not web-accessible, so a site cannot open it.
async function targetTabId() {
  const q = new URLSearchParams(location.search).get('tab');
  if (q && /^\d+$/.test(q)) return Number(q);
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  return tab ? tab.id : null;
}

let tabId = null;
let ctx = null;
let pairTimer = null;
let fillTimer = null;

function setMsg(el, text, cls) {
  el.textContent = text || '';
  el.className = cls || '';
}

function show(id, on) { $(id).hidden = !on; }

async function refresh() {
  const r = await send({ type: 'ui:context', tabId });
  if (!r || !r.ok) { setMsg($('status'), (r && r.error) || 'Could not load.', 'err'); return; }
  ctx = r;
  render();
}

function render() {
  const c = ctx;
  if (c.devServer) { $('dev').textContent = `Dev server: ${c.apiBase}`; show('dev', true); } else show('dev', false);
  show('signout', c.paired);

  // Pairing
  const p = c.pairing;
  show('pair', !c.paired);
  if (!c.paired) {
    const waiting = p && p.state === 'pending';
    show('pair-code', waiting);
    show('pair-btn', !waiting);
    show('pair-cancel', waiting);
    if (waiting) {
      $('user-code').textContent = p.user_code;
      $('pair-link').href = p.verification_url_complete;
    }
    if (p && p.state === 'denied') setMsg($('status'), 'Pairing was denied.', 'err');
    else if (p && p.state === 'expired') setMsg($('status'), 'The pairing code expired. Try again.', 'err');
    else if (p && p.state === 'error') setMsg($('status'), p.error || 'Pairing failed.', 'err');
    else setMsg($('status'), 'Not paired.', 'muted');
    if (waiting && !pairTimer) pairTimer = setInterval(refresh, 2000);
  } else {
    if (pairTimer) { clearInterval(pairTimer); pairTimer = null; }
    setMsg($('status'), c.error ? c.error : (c.topOrigin ? c.topOrigin : 'This page cannot be filled.'), c.error ? 'err' : 'muted');
  }

  renderAccess(c);

  // Pending login capture
  const pl = c.pendingLogin;
  show('capture', !!pl);
  if (pl) {
    $('cap-origin').textContent = pl.origin;
    $('cap-user').textContent = pl.login;
    show('cap-user-wrap', !!pl.login);
    if (!$('cap-name').value) $('cap-name').value = pl.suggestedName;
    // A username carried over from the previous step of a multi-step login may not be the account signed in to
    // (an account chooser): say so, and ask before replacing (see cap-save).
    if (pl.existing) { $('cap-existing').textContent = pl.loginFromHint ? `Username from the previous step. Saving under “${pl.existing}” replaces its password; you'll be asked first.` : `Replaces the saved password in “${pl.existing}”.`; show('cap-existing', true); }
    else show('cap-existing', false);
    $('cap-save').disabled = !c.paired;
    if (!c.paired) setMsg($('cap-msg'), 'Pair first, then save.', 'muted');
  }

  // Entries
  show('entries', c.paired && c.targets.length > 0);
  show('add', c.paired && !!c.topOrigin);
  const list = $('entry-list');
  list.replaceChildren();
  if (c.paired) {
    let n = 0;
    for (const t of c.targets) {
      for (const cand of t.candidates || []) {
        n++;
        const row = document.createElement('div');
        row.className = 'entry row';
        const info = document.createElement('div');
        info.className = 'grow';
        const name = document.createElement('div');
        name.className = 'name';
        name.textContent = cand.name;
        const user = document.createElement('div');
        user.className = 'user';
        user.textContent = (cand.username || '(no username)') + (t.frameId !== 0 ? ` · in frame ${t.origin}` : '');
        info.append(name, user);
        const btn = document.createElement('button');
        btn.textContent = 'Fill';
        btn.className = 'primary';
        btn.dataset.ref = cand.ref;
        btn.addEventListener('click', () => fill(t.docKey, cand.ref, btn));
        row.append(info, btn);
        list.append(row);
      }
    }
    if (n === 0) {
      const p = document.createElement('div');
      p.className = 'muted';
      p.textContent = 'No entries are bound to this site.';
      list.append(p);
    }
  }
}

// Host access (Firefox / Zen mostly: there, site access and the API host are
// the person's choice and can be off). The background says what is missing
// and which origins to ask for; the request runs from the click itself, which
// permissions.request() requires.
function renderAccess(c) {
  const a = c.access;
  let text = '';
  if (a && a.requestApi) {
    text = `DemiPass is not allowed to connect to ${c.apiBase}, so it cannot pair, save or fill.`;
  } else if (a && c.topOrigin && a.site === false) {
    text = `Site access is off for ${new URL(c.topOrigin).hostname}. DemiPass can fill here when you open it from the toolbar, but it does not watch this site's login forms, so it cannot offer to save a login you type.`;
  }
  show('access', !!text);
  $('access-text').textContent = text;
  const set = (id, origins) => {
    show(id, !!(text && origins));
    $(id).dataset.origins = origins ? JSON.stringify(origins) : '';
  };
  const apiOnly = !!(a && a.requestApi) && !(c.topOrigin && a.site === false);
  set('access-api', apiOnly ? a.requestApi : null);
  set('access-site', !apiOnly && a ? a.requestSite : null);
  set('access-all', !apiOnly && a ? a.requestAll : null);
}

function requestAccess(e) {
  const origins = JSON.parse(e.currentTarget.dataset.origins || '[]');
  if (!origins.length) return;
  // No await before this call: it must run inside the click's user gesture.
  ext.permissions.request({ origins }).then(
    (granted) => { setMsg($('access-msg'), granted ? 'Access granted.' : 'Access was not granted.', granted ? 'ok' : 'err'); return refresh(); },
    () => setMsg($('access-msg'), 'Could not ask for access.', 'err'),
  );
}
for (const id of ['access-site', 'access-all', 'access-api']) $(id).addEventListener('click', requestAccess);

const FILL_TEXT = {
  requesting: 'Asking DemiPass…',
  pending: 'Approve on your phone…',
  approved: 'Approved. Filling…',
  filling: 'Filling…',
  done: 'Filled.',
  denied: 'Denied on your phone.',
  expired: 'The request expired.',
  already_redeemed: 'That request was already used.',
  cancelled: 'Cancelled.',
  withdrawn: 'Withdrawn.',
  unpaired: 'Not paired with DemiPass.',
};

async function fill(docKey, ref, btn) {
  if (fillTimer) return;
  for (const b of document.querySelectorAll('#entry-list button')) b.disabled = true;
  const msg = $('fill-msg');
  const r = await send({ type: 'ui:fill', tabId, docKey, ref });
  if (!r || !r.ok) { setMsg(msg, (r && r.error) || 'Fill failed.', 'err'); done(); return; }
  setMsg(msg, FILL_TEXT.requesting, 'muted');
  fillTimer = setInterval(async () => {
    const s = await send({ type: 'ui:fillStatus', fillId: r.fillId });
    if (!s || !s.ok) { setMsg(msg, 'Fill failed.', 'err'); done(); return; }
    let text = s.error || FILL_TEXT[s.state] || s.state;
    if (s.state === 'pending' && s.asks > 1) text += ' (new request: the first one ended with a token refresh)';
    const terminal = !['requesting', 'pending', 'approved', 'filling'].includes(s.state);
    setMsg(msg, text, s.state === 'done' ? 'ok' : (terminal ? 'err' : 'muted'));
    if (terminal) done();
  }, 1000);
  function done() {
    if (fillTimer) { clearInterval(fillTimer); fillTimer = null; }
    for (const b of document.querySelectorAll('#entry-list button')) b.disabled = false;
  }
}

$('pair-btn').addEventListener('click', async () => {
  $('pair-btn').disabled = true;
  const r = await send({ type: 'ui:pair' });
  $('pair-btn').disabled = false;
  if (!r || !r.ok) { setMsg($('status'), (r && r.error) || 'Pairing failed.', 'err'); return; }
  await refresh();
});

$('pair-cancel').addEventListener('click', async () => {
  await send({ type: 'ui:pairCancel' });
  if (pairTimer) { clearInterval(pairTimer); pairTimer = null; }
  await refresh();
});

$('signout').addEventListener('click', async () => {
  $('signout').disabled = true;
  await send({ type: 'ui:signOut' });
  $('signout').disabled = false;
  await refresh();
});

// A save under a name that already exists replaces that secret's value. The
// background answers { conflict } instead of saving; the button then turns
// into "Replace" for that exact name, and only a second click sends replace.
// The capture card's "Replaces the saved password in X" line is that warning
// already, so saving under that shown name counts as confirmed.
const TYPE_TEXT = { password: 'password', api_key: 'API key', oauth_token: 'token', other: 'secret' };
function conflictText(c) {
  return `“${c.name}” already exists in your vault (${TYPE_TEXT[c.secret_type] || c.secret_type || 'secret'}). Saving replaces its value. Click Replace to do that, or change the name.`;
}
// The server said the name was rotated and named its current version: put
// that name in the box and make the button "Save to <current>", which
// replaces the current version (keeping its origins, adding this one).
function offerRotated(rot, nameId, btnId, msgId, setReplace) {
  $(nameId).value = rot.current;
  setReplace(rot.current);
  $(btnId).textContent = `Save to “${rot.current}”`;
  setMsg($(msgId), `“${rot.name}” was rotated; its current version is “${rot.current}”. Save there instead?`, 'err');
}
let capReplace = null;
let addReplace = null;
$('cap-name').addEventListener('input', () => { capReplace = null; $('cap-save').textContent = 'Save to DemiPass'; });
$('add-name').addEventListener('input', () => { addReplace = null; $('add-submit').textContent = 'Add'; });

$('cap-save').addEventListener('click', async () => {
  const pl = ctx && ctx.pendingLogin;
  if (!pl) return;
  const name = $('cap-name').value.trim(); // the background trims too; compare what it compares
  const replace = capReplace === name || (!!pl.existing && !pl.loginFromHint && name === pl.existing);
  $('cap-save').disabled = true;
  const r = await send({ type: 'ui:savePending', id: pl.id, name, replace });
  $('cap-save').disabled = false;
  if (r && r.ok) { setMsg($('cap-msg'), `Saved as “${r.name}”.`, 'ok'); $('cap-name').value = ''; capReplace = null; setTimeout(refresh, 600); }
  else if (r && r.conflict) { capReplace = r.conflict.name; $('cap-save').textContent = 'Replace'; setMsg($('cap-msg'), conflictText(r.conflict), 'err'); }
  else if (r && r.rotated) offerRotated(r.rotated, 'cap-name', 'cap-save', 'cap-msg', (n) => { capReplace = n; });
  else setMsg($('cap-msg'), (r && r.error) || 'Save failed.', 'err');
});

$('cap-dismiss').addEventListener('click', async () => {
  const pl = ctx && ctx.pendingLogin;
  if (pl) await send({ type: 'ui:dismissPending', id: pl.id });
  await refresh();
});

$('add-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('add-password');
  const name = $('add-name').value.trim();
  // origin: what this popup showed; the background refuses if the tab has moved on.
  const r = await send({ type: 'ui:addManual', tabId, origin: ctx && ctx.topOrigin, name, login: $('add-login').value, password: pw.value, replace: addReplace === name });
  if (r && r.conflict) { addReplace = r.conflict.name; $('add-submit').textContent = 'Replace'; setMsg($('add-msg'), conflictText(r.conflict), 'err'); return; }
  if (r && r.rotated) { offerRotated(r.rotated, 'add-name', 'add-submit', 'add-msg', (n) => { addReplace = n; }); return; }
  pw.value = '';
  addReplace = null; $('add-submit').textContent = 'Add';
  if (r && r.ok) { setMsg($('add-msg'), `${r.replaced ? 'Replaced' : 'Added'} “${r.name}”.`, 'ok'); $('add-name').value = ''; $('add-login').value = ''; await refresh(); }
  else setMsg($('add-msg'), (r && r.error) || 'Add failed.', 'err');
});

(async () => {
  tabId = await targetTabId();
  await refresh();
})();
