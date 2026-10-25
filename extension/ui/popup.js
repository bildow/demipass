// Popup. It never sees a stored value: it shows names and usernames, and the
// only value it handles is the password a person types into "Add for this site",
// which goes straight to the background worker.

const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);

// ?tab=<id> lets the popup be opened as a page for a given tab (tests,
// pop-out). Extension pages are not web-accessible, so a site cannot open it.
async function targetTabId() {
  const q = new URLSearchParams(location.search).get('tab');
  if (q && /^\d+$/.test(q)) return Number(q);
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
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

  // Pending login capture
  const pl = c.pendingLogin;
  show('capture', !!pl);
  if (pl) {
    $('cap-origin').textContent = pl.origin;
    $('cap-user').textContent = pl.login;
    show('cap-user-wrap', !!pl.login);
    if (!$('cap-name').value) $('cap-name').value = pl.suggestedName;
    if (pl.existing) { $('cap-existing').textContent = `Replaces the saved password in “${pl.existing}”.`; show('cap-existing', true); }
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
        btn.addEventListener('click', () => fill(t.documentId, cand.ref, btn));
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
  unpaired: 'Not paired with DemiPass.',
};

async function fill(documentId, ref, btn) {
  if (fillTimer) return;
  for (const b of document.querySelectorAll('#entry-list button')) b.disabled = true;
  const msg = $('fill-msg');
  const r = await send({ type: 'ui:fill', tabId, documentId, ref });
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

$('cap-save').addEventListener('click', async () => {
  const pl = ctx && ctx.pendingLogin;
  if (!pl) return;
  $('cap-save').disabled = true;
  const r = await send({ type: 'ui:savePending', id: pl.id, name: $('cap-name').value });
  if (r && r.ok) { setMsg($('cap-msg'), `Saved as “${r.name}”.`, 'ok'); $('cap-name').value = ''; setTimeout(refresh, 600); }
  else { setMsg($('cap-msg'), (r && r.error) || 'Save failed.', 'err'); $('cap-save').disabled = false; }
});

$('cap-dismiss').addEventListener('click', async () => {
  const pl = ctx && ctx.pendingLogin;
  if (pl) await send({ type: 'ui:dismissPending', id: pl.id });
  await refresh();
});

$('add-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('add-password');
  const r = await send({ type: 'ui:addManual', tabId, name: $('add-name').value, login: $('add-login').value, password: pw.value });
  pw.value = '';
  if (r && r.ok) { setMsg($('add-msg'), `Added “${r.name}”.`, 'ok'); $('add-name').value = ''; $('add-login').value = ''; await refresh(); }
  else setMsg($('add-msg'), (r && r.error) || 'Add failed.', 'err');
});

(async () => {
  tabId = await targetTabId();
  await refresh();
})();
