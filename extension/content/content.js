// DemiPass content script (every frame, isolated world).
//
// It holds no token and never receives a value. It does two things:
//  1. Tells the background whether this frame has a login form (no values).
//  2. When the person sends a login form (their own click or Enter), hands
//     the username + the password they typed straight to the background
//     with runtime.sendMessage (rules below). The background keeps it in
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

  // ---- what counts as the person's own password --------------------------
  // A save is offered only for a password the person entered themselves, at
  // the moment they themselves sent the form. The rules:
  //
  //  1. One gesture, one edit. A trusted keydown (a character, Backspace or
  //     Delete, without Ctrl/Meta), paste or drop on a field issues one
  //     token for that field. The token lives until the end of the current
  //     task. The next trusted input event on that field must spend it, and
  //     must be the edit that gesture makes:
  //       - a key K must give inputType 'insertText' with data === K;
  //       - Backspace/Delete must give a delete;
  //       - paste must give 'insertFromPaste', and drop 'insertFromDrop'.
  //     Composition (IME) input counts while a trusted composition is open
  //     on that field. The page must also have transient user activation.
  //     So execCommand('insertText') counts never: not on its own, not from
  //     a timer, and not nested inside the person's own keystroke, where the
  //     token is already spent. Synthetic events and .value writes do not
  //     count either. An input that does not count makes the field
  //     "not the person's" until they type in it again.
  //  2. The value sent is the one left by the field's last counted input.
  //     If the page changed it since (a swap before submit), nothing is
  //     offered.
  //  3. Capture happens only on the person's own send: a trusted click on
  //     a button of the page (any submit control, or any other button that
  //     is not a show-password toggle or a forgot/cancel/back link), or a
  //     trusted Enter in a field. Labels are not required: icon-only and
  //     unlabeled buttons count. submit events are not used, so
  //     requestSubmit() and form.submit() from page script offer nothing.
  //     A send with no password on the page (step one of a multi-step
  //     login) hands the username the person typed to the background, which
  //     uses it for a capture with no username on the same origin.
  //  4. The password field must be rendered and visible at a usable size
  //     (at least 16x8 CSS px, not hidden by CSS, display or opacity), so a
  //     1px field that grabbed focus while the person typed elsewhere is
  //     ignored.
  // Every input field is tracked, whatever its type, so typing while a
  // show-password toggle has made the field type=text still counts.
  // Not offered, on purpose: another password manager's fill, the browser's
  // autofill, DemiPass's own fill, and text committed with no key, paste,
  // drop or composition (some dictation tools and on-screen keyboards). For
  // those, "Add for this site".
  const tokens = new WeakMap(); // input -> { kind, key }, valid for the current task only
  const composing = new WeakSet(); // inputs with an open trusted composition
  const typed = new WeakMap(); // input -> value after its last counted input event
  const issue = (el, tok) => {
    tokens.set(el, tok);
    setTimeout(() => { if (tokens.get(el) === tok) tokens.delete(el); }, 0);
  };
  window.addEventListener('keydown', (e) => {
    const t = e.target;
    if (!e.isTrusted || !(t instanceof HTMLInputElement) || e.ctrlKey || e.metaKey) return;
    if (e.key.length === 1 || e.key === 'Backspace' || e.key === 'Delete') issue(t, { kind: 'key', key: e.key });
  }, true);
  window.addEventListener('paste', (e) => { if (e.isTrusted && e.target instanceof HTMLInputElement) issue(e.target, { kind: 'paste' }); }, true);
  window.addEventListener('drop', (e) => { if (e.isTrusted && e.target instanceof HTMLInputElement) issue(e.target, { kind: 'drop' }); }, true);
  window.addEventListener('compositionstart', (e) => { if (e.isTrusted && e.target instanceof HTMLInputElement) composing.add(e.target); }, true);
  window.addEventListener('compositionend', (e) => {
    if (!e.isTrusted || !(e.target instanceof HTMLInputElement)) return;
    composing.delete(e.target);
    issue(e.target, { kind: 'commit' }); // some browsers send the committing input after compositionend
  }, true);
  const activated = () => !navigator.userActivation || navigator.userActivation.isActive;
  function matches(tok, e) {
    const it = e.inputType || '';
    if (tok.kind === 'paste') return it === 'insertFromPaste';
    if (tok.kind === 'drop') return it === 'insertFromDrop';
    if (tok.kind === 'commit') return it === 'insertCompositionText' || it === 'insertFromComposition' || it === 'insertText';
    if (tok.key === 'Backspace' || tok.key === 'Delete') return it.startsWith('delete');
    return it === 'insertText' && e.data === tok.key;
  }
  window.addEventListener('input', (e) => {
    const t = e.target;
    if (!e.isTrusted || !(t instanceof HTMLInputElement)) return;
    const tok = tokens.get(t);
    tokens.delete(t); // spent either way
    const ime = composing.has(t) && (e.isComposing || /Composition/.test(e.inputType || ''));
    if (activated() && (ime || (tok && matches(tok, e)))) typed.set(t, t.value);
    else typed.delete(t);
  }, true);

  function usable(el) {
    const r = el.getBoundingClientRect();
    if (r.width < 16 || r.height < 8) return false;
    if (typeof el.checkVisibility === 'function') return el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true, opacityProperty: true, visibilityProperty: true });
    const cs = getComputedStyle(el);
    return cs.visibility !== 'hidden' && Number(cs.opacity) > 0.05;
  }

  // Step one of a multi-step login: the username the person typed (not one a
  // page or another manager wrote), from the field they sent, else from the
  // form or page.
  function typedUsername(form, target) {
    const own = (el) => el instanceof HTMLInputElement && typed.get(el) === el.value && String(el.value).trim() !== '' && usable(el);
    const userish = (el) => /^(text|email|tel)$/.test(el.type) || /username|email/.test(el.autocomplete || '');
    if (target && own(target) && userish(target)) return String(target.value).trim();
    const pool = [...(form || document).querySelectorAll('input')].filter((el) => userish(el) && own(el));
    const best = pool.find((el) => /username|email/.test(el.autocomplete || '')) || pool.find((el) => el.type === 'email') || pool[0];
    return best ? String(best.value).trim() : '';
  }

  let lastCapture = 0;
  function capture(form, target) {
    let f = null;
    try { f = D.findLoginFields(document, form || undefined); } catch (_) {}
    if (!f || !f.password) {
      const login = typedUsername(form, target);
      if (login) send({ type: 'dp:loginHint', login: login.slice(0, 256) });
      return;
    }
    const pwEl = f.newPassword || f.password;
    const password = pwEl.value;
    if (!password || typed.get(pwEl) !== password || !usable(pwEl)) return;
    const now = Date.now();
    if (now - lastCapture < 800) return; // one action, one capture
    lastCapture = now;
    const login = f.username ? String(f.username.value || '').trim() : '';
    send({ type: 'dp:capture', login, password });
  }

  // The person's own send: a click on a submit control or another button,
  // labeled or not (icon-only, outside the form), except the buttons that
  // are clearly not a send.
  const NOT_A_SEND = /show|hide|reveal|peek|eye|visib|toggle|forgot|reset|cancel|back|clear|help|close/;
  window.addEventListener('click', (e) => {
    if (!e.isTrusted) return; // element.click() / dispatched clicks
    const t = e.target instanceof Element ? e.target.closest('button, input[type=submit], input[type=image], input[type=button], [role=button]') : null;
    if (!t) return;
    if (t.form && (t.type === 'submit' || t.type === 'image')) { capture(t.form); return; }
    const label = [t.textContent, t.value, t.getAttribute('aria-label'), t.getAttribute('title'), t.id, t.className]
      .map((x) => (typeof x === 'string' ? x : '')).join(' ').toLowerCase();
    if (NOT_A_SEND.test(label) || t.getAttribute('aria-pressed') != null) return;
    capture(t.form || null);
  }, true);

  // ... or Enter in a field (of a form, or of a page with no form).
  window.addEventListener('keydown', (e) => {
    if (!e.isTrusted || e.key !== 'Enter' || e.isComposing) return;
    const t = e.target;
    if (!(t instanceof HTMLInputElement)) return;
    capture(t.form || null, t);
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
