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

  // A save is offered only for a password the person entered themselves.
  // An input event counts only when all of these hold:
  //  - it is trusted (not dispatchEvent);
  //  - the page has transient user activation (navigator.userActivation);
  //  - a trusted keydown, paste, drop or compositionend (IMEs) hit that same
  //    field within the last second. execCommand('insertText') makes trusted
  //    input events with no person involved; it makes none of those.
  // At capture the field must still hold the value from its last counted
  // input. So a page that sets .value, dispatches events, calls
  // execCommand() or requestSubmit() on its own gets no SAVE prompt, and
  // neither does a value DemiPass (or another password manager, or the
  // browser's own autofill) put there; for those, "Add for this site".
  // Every input field is tracked, not only type=password, so typing while a
  // show-password toggle has made it type=text still counts.
  const GESTURE_MS = 1000;
  const gesture = new WeakMap(); // input -> time of the last trusted keydown / paste / drop on it
  const typed = new WeakMap(); // input -> value after its last counted input event
  const noteGesture = (e) => {
    if (e.isTrusted && e.target instanceof HTMLInputElement) gesture.set(e.target, Date.now());
  };
  for (const ev of ['keydown', 'paste', 'drop', 'compositionend']) window.addEventListener(ev, noteGesture, true);
  const activated = () => !navigator.userActivation || navigator.userActivation.isActive;
  window.addEventListener('input', (e) => {
    const t = e.target;
    if (!e.isTrusted || !(t instanceof HTMLInputElement)) return;
    const g = gesture.get(t);
    if (g && Date.now() - g <= GESTURE_MS && activated()) typed.set(t, t.value);
    else typed.delete(t);
  }, true);

  let lastCapture = 0;
  function capture(form) {
    let f = null;
    try { f = D.findLoginFields(document, form || undefined); } catch (_) {}
    if (!f || !f.password) return;
    const pwEl = f.newPassword || f.password;
    const password = pwEl.value;
    if (!password || typed.get(pwEl) !== password) return;
    const now = Date.now();
    if (now - lastCapture < 800) return; // submit + click on the same action
    lastCapture = now;
    const login = f.username ? String(f.username.value || '').trim() : '';
    send({ type: 'dp:capture', login, password });
  }

  // Native form submit.
  window.addEventListener('submit', (e) => {
    if (!e.isTrusted) return; // dispatchEvent(new Event('submit'))
    const form = e.target instanceof HTMLFormElement ? e.target : null;
    capture(form);
  }, true);

  // Script-driven logins that never fire submit: a click on a submit-ish
  // button, or Enter in a password field.
  window.addEventListener('click', (e) => {
    if (!e.isTrusted) return; // element.click() / dispatched clicks
    const t = e.target instanceof Element ? e.target.closest('button, input[type=submit], input[type=button], [role=button]') : null;
    if (!t) return;
    if (t.form && t.type === 'submit') return; // the submit listener handles it
    const label = (t.textContent || t.value || '').toLowerCase();
    if (/log\s*in|sign\s*in|continue|submit|next|enter/.test(label)) capture(t.form || null);
  }, true);

  window.addEventListener('keydown', (e) => {
    if (!e.isTrusted || e.key !== 'Enter') return;
    const t = e.target;
    if (t instanceof HTMLInputElement && t.type === 'password' && !t.form) capture(null);
  }, true);

  ext.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg && msg.type === 'dp:announce') { announce(true); sendResponse({ ok: true }); }
    return false;
  });

  // This document is going away (navigation, reload, removed iframe): drop
  // its record now, so a fill waiting for it stops and is withdrawn. Coming
  // back from the back/forward cache, announce again.
  window.addEventListener('pagehide', (e) => { if (e.isTrusted) send({ type: 'dp:gone' }); }, true);
  window.addEventListener('pageshow', (e) => { if (e.isTrusted && e.persisted) announce(true); }, true);

  announce(true);
  let t = null;
  new MutationObserver(() => {
    if (t) return;
    t = setTimeout(() => { t = null; announce(false); }, 500);
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['type', 'style', 'class', 'hidden'] });
})();
