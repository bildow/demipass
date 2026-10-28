// Login-form detection. Classic script (no import/export) so it can run as a
// content script and inside the fill injection; it also loads under node:test,
// where it only defines globalThis.DemiPassFormDetect.
//
// The core (pickLoginFields) works on plain descriptors so it is testable
// without a DOM. The DOM helpers build those descriptors from real inputs.
(function () {
  'use strict';
  if (globalThis.DemiPassFormDetect) return;

  const USERNAME_TYPES = new Set(['text', 'email', 'tel', '']);
  const USERNAME_HINT = /user|login|email|e-mail|account|ident|nick|handle|phone|mail/i;
  const NOT_USERNAME_HINT = /search|captcha|otp|totp|2fa|mfa|code|token|query|coupon|zip|postal|pass|pwd|\bpin\b/i;

  function hintText(d) {
    return [d.name, d.id, d.placeholder, d.ariaLabel, d.label].filter(Boolean).join(' ');
  }

  function usable(d) {
    return d && d.visible !== false && !d.disabled && !d.readOnly;
  }

  function isPassword(d) {
    return d.type === 'password';
  }

  function ac(d) {
    return String(d.autocomplete || '').toLowerCase().split(/\s+/).filter(Boolean);
  }

  function usernameScore(d) {
    if (!usable(d) || !USERNAME_TYPES.has(d.type || '')) return -1;
    const a = ac(d);
    if (a.includes('username')) return 100;
    if (a.includes('email')) return 90;
    if (a.includes('one-time-code')) return -1;
    const hint = hintText(d);
    if (NOT_USERNAME_HINT.test(hint)) return 0;
    if (d.type === 'email') return 80;
    if (USERNAME_HINT.test(hint)) return 60;
    return 10; // a plain text box before the password is still a fair guess
  }

  // descriptors: inputs in document order, each
  //   { type, name, id, autocomplete, placeholder, ariaLabel, label,
  //     visible, disabled, readOnly, formIndex }
  // formIndex groups inputs by <form> (-1 = not in a form).
  //
  // Returns null when there is no usable password field, else
  //   { kind: 'login' | 'signup' | 'change', usernameIndex (or -1),
  //     passwordIndex (field to fill), newPasswordIndex (field to capture
  //     on submit for signup/change, or -1) }
  function pickLoginFields(descriptors, opts) {
    const list = Array.isArray(descriptors) ? descriptors : [];
    const scopeForm = opts && Number.isInteger(opts.formIndex) ? opts.formIndex : null;
    const inScope = (d) => scopeForm === null || d.formIndex === scopeForm;

    const pw = [];
    list.forEach((d, i) => { if (inScope(d) && isPassword(d) && usable(d)) pw.push(i); });
    if (pw.length === 0) return null;

    // Prefer the form that holds the first password field, so a page with a
    // login form and an unrelated signup form does not get mixed up.
    const form = list[pw[0]].formIndex;
    const group = pw.filter((i) => list[i].formIndex === form);

    const current = group.find((i) => ac(list[i]).includes('current-password'));
    const fresh = group.filter((i) => ac(list[i]).includes('new-password'));

    let kind = 'login';
    let passwordIndex = group[0];
    let newPasswordIndex = -1;
    if (group.length >= 3 || (current !== undefined && fresh.length > 0)) {
      kind = 'change';
      passwordIndex = current !== undefined ? current : group[0];
      newPasswordIndex = fresh.length ? fresh[0] : group[1];
    } else if (group.length === 2 || fresh.length > 0) {
      kind = 'signup';
      passwordIndex = fresh.length ? fresh[0] : group[0];
      newPasswordIndex = passwordIndex;
    } else if (current !== undefined) {
      passwordIndex = current;
    }

    // Username: best-scoring usable field before the first password field,
    // in the same form; ties go to the nearest one.
    let usernameIndex = -1;
    let best = 0;
    for (let i = group[0] - 1; i >= 0; i--) {
      const d = list[i];
      if (d.formIndex !== form) continue;
      const s = usernameScore(d);
      if (s > best) { best = s; usernameIndex = i; }
    }
    return { kind, usernameIndex, passwordIndex, newPasswordIndex };
  }

  // ---- DOM helpers (browser only) -----------------------------------------

  function isVisible(el) {
    if (!el.isConnected) return false;
    if (el.type === 'hidden') return false;
    const r = el.getClientRects();
    if (!r || r.length === 0) return false;
    const st = el.ownerDocument.defaultView.getComputedStyle(el);
    return st.visibility !== 'hidden' && st.display !== 'none' && Number(st.opacity) !== 0;
  }

  function labelFor(el) {
    try {
      if (el.labels && el.labels.length) return el.labels[0].textContent.trim().slice(0, 80);
    } catch (_) {}
    return '';
  }

  function collectInputs(root) {
    const doc = root.ownerDocument || root;
    const forms = Array.from(doc.forms || []);
    const els = Array.from(root.querySelectorAll('input'));
    const descriptors = els.map((el) => ({
      type: String(el.type || 'text').toLowerCase(),
      name: el.name || '',
      id: el.id || '',
      autocomplete: el.getAttribute('autocomplete') || '',
      placeholder: el.placeholder || '',
      ariaLabel: el.getAttribute('aria-label') || '',
      label: labelFor(el),
      visible: isVisible(el),
      disabled: !!el.disabled,
      readOnly: !!el.readOnly,
      formIndex: el.form ? forms.indexOf(el.form) : -1,
    }));
    return { els, descriptors, forms };
  }

  // How much one input looks like a username field (100 = says so, 80 email,
  // 60 named like one, 10 a plain text box, 0/-1 not one).
  function usernameScoreOf(el) {
    const doc = el.ownerDocument;
    const forms = Array.from(doc.forms || []);
    return usernameScore({
      type: String(el.type || 'text').toLowerCase(), name: el.name || '', id: el.id || '',
      autocomplete: el.getAttribute('autocomplete') || '', placeholder: el.placeholder || '',
      ariaLabel: el.getAttribute('aria-label') || '', label: labelFor(el), visible: isVisible(el),
      disabled: !!el.disabled, readOnly: !!el.readOnly, formIndex: el.form ? forms.indexOf(el.form) : -1,
    });
  }

  // Finds the login fields in a document (or inside one <form>).
  function findLoginFields(doc, form) {
    const { els, descriptors, forms } = collectInputs(doc);
    const opts = form ? { formIndex: forms.indexOf(form) } : undefined;
    const pick = pickLoginFields(descriptors, opts);
    if (!pick) return null;
    const at = (i) => (i >= 0 ? els[i] : null);
    return {
      kind: pick.kind,
      username: at(pick.usernameIndex),
      password: at(pick.passwordIndex),
      newPassword: at(pick.newPasswordIndex),
      form: at(pick.passwordIndex).form || null,
    };
  }

  // Sets a value the way typing would, so framework-controlled inputs
  // (React, Vue) see the change.
  function setInputValue(el, value) {
    const proto = Object.getPrototypeOf(el);
    const desc = Object.getOwnPropertyDescriptor(proto, 'value')
      || Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    el.focus();
    desc.set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  globalThis.DemiPassFormDetect = Object.freeze({ pickLoginFields, findLoginFields, setInputValue, usernameScoreOf });
})();
