// DemiPass content script (every frame, isolated world).
//
// It holds no token and never receives a value. It does two things:
//  1. Tells the background whether this frame has a login form (no values).
//  2. On login submit, hands the typed username + password straight to the
//     background with runtime.sendMessage. The background keeps it in
//     memory for a few minutes and stores it only if the person clicks Save in
//     the extension popup. Nothing is injected into the page's DOM.
(function () {
  'use strict';
  if (globalThis.__demipassContent) return;
  globalThis.__demipassContent = true;
  const D = globalThis.DemiPassFormDetect;
  if (!D) return;
  // Firefox / Zen: browser.* (promises). Chromium: chrome.* (promises in MV3).
  const ext = globalThis.browser || globalThis.chrome;

  // Per-document nonce, in this isolated world only (the page cannot read it).
  // The background uses it to tell this document from a later one in the same
  // frame, and the fill re-checks it in the frame right before writing.
  const DOC = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
  globalThis.__demipassDoc = DOC;
  const send = (msg) => ext.runtime.sendMessage({ ...msg, doc: DOC, origin: location.origin }).catch(() => {});

  let lastHasLogin = null;
  function announce(force) {
    let has = false;
    try { has = !!D.findLoginFields(document); } catch (_) {}
    if (!force && has === lastHasLogin) return;
    lastHasLogin = has;
    send({ type: 'dp:frame', hasLogin: has });
  }

  let lastCapture = 0;
  function capture(form) {
    let f = null;
    try { f = D.findLoginFields(document, form || undefined); } catch (_) {}
    if (!f || !f.password) return;
    const pwEl = f.newPassword || f.password;
    const password = pwEl.value;
    if (!password) return;
    const now = Date.now();
    if (now - lastCapture < 800) return; // submit + click on the same action
    lastCapture = now;
    const login = f.username ? String(f.username.value || '').trim() : '';
    send({ type: 'dp:capture', login, password });
  }

  // Native form submit.
  window.addEventListener('submit', (e) => {
    const form = e.target instanceof HTMLFormElement ? e.target : null;
    capture(form);
  }, true);

  // Script-driven logins that never fire submit: a click on a submit-ish
  // button, or Enter in a password field.
  window.addEventListener('click', (e) => {
    const t = e.target instanceof Element ? e.target.closest('button, input[type=submit], input[type=button], [role=button]') : null;
    if (!t) return;
    if (t.form && t.type === 'submit') return; // the submit listener handles it
    const label = (t.textContent || t.value || '').toLowerCase();
    if (/log\s*in|sign\s*in|continue|submit|next|enter/.test(label)) capture(t.form || null);
  }, true);

  window.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const t = e.target;
    if (t instanceof HTMLInputElement && t.type === 'password' && !t.form) capture(null);
  }, true);

  ext.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg && msg.type === 'dp:announce') { announce(true); sendResponse({ ok: true }); }
    return false;
  });

  announce(true);
  let t = null;
  new MutationObserver(() => {
    if (t) return;
    t = setTimeout(() => { t = null; announce(false); }, 500);
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['type', 'style', 'class', 'hidden'] });
})();
