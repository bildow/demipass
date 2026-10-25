'use strict';
/**
 * The in-page half of a browser fill. One self-contained function, serialized with .toString() and run
 * in the page: over CDP in an isolated world (page scripts cannot tamper with its globals), in Lightpanda through
 * the wrapper's internal `evaluate`. It never returns a value it was given.
 *
 *   mode 'find'    locate the login fields (no secret involved); with `mark`, tag them data-demipass-fill="<mark>:u|p|s"
 *   mode 'fill'    origin re-check, then set the fields the way a typing user would (input + change), optional submit
 *   mode 'submit'  submit the form around the marked password field
 *   mode 'check'   lengths (never values) of the marked fields — verifies what a field accepted after a fill
 *   mode 'clear'   empty the marked password field with the native setter and no events (a page cannot refill it)
 *   mode 'residue' the marked password field's current value. Only for the Lightpanda wrapper's internal evaluate,
 *                  whose reply never reaches the agent: it feeds the Redactor what a field kept of a refused value.
 *   mode 'unmark'  remove the tags
 */

/* eslint-disable no-var */
function dpBrowserFill(a) {
  var ATTR = 'data-demipass-fill';
  function fail(code, field) { return { ok: false, code: code, field: field || null }; }
  if (a.expectedOrigin && location.origin !== a.expectedOrigin) return fail('origin_changed');

  function hidden(el) {
    for (var n = el; n && n.nodeType === 1; n = n.parentElement) {
      if (n.hidden) return true;
      var cs = null;
      try { cs = getComputedStyle(n); } catch (e) { cs = null; }
      if (cs && (cs.display === 'none' || (n === el && cs.visibility === 'hidden'))) return true;
    }
    return false;
  }
  function usable(el) {
    if (!el || !el.tagName) return false;
    var tag = el.tagName.toLowerCase();
    if (tag !== 'input' && tag !== 'textarea') return false;
    if (el.disabled || el.readOnly) return false;
    if (tag === 'input' && (el.type || '').toLowerCase() === 'hidden') return false;
    return !hidden(el);
  }
  function before(x, y) { return Boolean(x.compareDocumentPosition(y) & 4); } // y follows x
  function pick(sel, field) {
    var el = null;
    try { el = document.querySelector(sel); } catch (e) { return { err: fail('bad_selector', field) }; }
    if (!el) return { err: fail('selector_not_found', field) };
    if (!usable(el)) return { err: fail('field_not_usable', field) };
    return { el: el };
  }

  if (a.mode === 'unmark') {
    var tagged = document.querySelectorAll('[' + ATTR + ']');
    for (var t = 0; t < tagged.length; t++) if (String(tagged[t].getAttribute(ATTR)).indexOf(a.mark + ':') === 0) tagged[t].removeAttribute(ATTR);
    return { ok: true };
  }
  if (a.mode === 'check') {
    var cp = document.querySelector('[' + ATTR + '="' + a.mark + ':p"]');
    if (!cp) return fail('field_gone', 'password');
    var cu = document.querySelector('[' + ATTR + '="' + a.mark + ':u"]');
    return { ok: true, password_chars: String(cp.value).length, username_chars: cu ? String(cu.value).length : null };
  }
  if (a.mode === 'clear' || a.mode === 'residue') {
    var rp = document.querySelector('[' + ATTR + '="' + a.mark + ':p"]');
    if (!rp) return fail('field_gone', 'password');
    if (a.mode === 'residue') return { ok: true, value: String(rp.value) };
    var rd = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (rd && rd.set && rp.tagName.toLowerCase() === 'input') rd.set.call(rp, ''); else rp.value = '';
    return { ok: true, password_chars: String(rp.value).length };
  }
  if (a.mode === 'submit') {
    var marked = document.querySelector('[' + ATTR + '="' + a.mark + ':p"]');
    if (!marked) return fail('field_gone', 'password');
    return doSubmit(marked);
  }

  // ── locate ──
  var pw = null;
  if (a.passwordSelector) {
    var pp = pick(a.passwordSelector, 'password'); if (pp.err) return pp.err; pw = pp.el;
  } else {
    var all = document.querySelectorAll('input[type=password]');
    var vis = [];
    for (var i = 0; i < all.length; i++) if (usable(all[i])) vis.push(all[i]);
    if (vis.length === 0) return fail('no_password_field', 'password');
    if (vis.length > 1) {
      var cur = vis.filter(function (e) { return /current-password/i.test(e.getAttribute('autocomplete') || ''); });
      if (cur.length === 1) vis = cur;
      else return { ok: false, code: 'ambiguous_password_field', field: 'password', count: vis.length };
    }
    pw = vis[0];
  }

  var user = null;
  if (a.usernameSelector) {
    var pu = pick(a.usernameSelector, 'username'); if (pu.err) return pu.err; user = pu.el;
  } else {
    var scope = pw.form || document;
    var inputs = scope.querySelectorAll('input');
    var best = null, bestScore = -1;
    for (var j = 0; j < inputs.length; j++) {
      var el = inputs[j];
      if (el === pw || !usable(el) || !before(el, pw)) continue;
      var type = (el.getAttribute('type') || 'text').toLowerCase();
      var ac = (el.getAttribute('autocomplete') || '').toLowerCase();
      if (['text', 'email', 'tel'].indexOf(type) < 0 && ac.indexOf('username') < 0) continue;
      var score = 1;
      if (type === 'email') score = 3;
      if (/user|email|login|account|ident/i.test((el.name || '') + ' ' + (el.id || ''))) score = Math.max(score, 3);
      if (ac.indexOf('username') >= 0 || ac === 'email') score = 5;
      if (score >= bestScore) { best = el; bestScore = score; } // ties → the field nearest the password
    }
    user = best;
  }

  function submitter(form) {
    if (!form) return null;
    var b = form.querySelector('button[type=submit], input[type=submit], button:not([type])');
    return b && !b.disabled ? b : null;
  }

  if (a.mode === 'find') {
    if (a.mark) {
      pw.setAttribute(ATTR, a.mark + ':p');
      if (user) user.setAttribute(ATTR, a.mark + ':u');
      var sb = submitter(pw.form);
      if (sb) sb.setAttribute(ATTR, a.mark + ':s');
    }
    return { ok: true, username_field: Boolean(user), password_field: true, has_form: Boolean(pw.form), has_submit: Boolean(submitter(pw.form)) };
  }

  if (a.mode !== 'fill') return fail('bad_mode');

  // ── fill ── the native setter (from this world's prototype, so a page override cannot intercept it), then the
  // events a typing user produces. React and friends track the value per element and see this as a change.
  function setValue(el, v) {
    try { el.focus(); } catch (e) { /* not focusable */ }
    var proto = el.tagName.toLowerCase() === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    var d = Object.getOwnPropertyDescriptor(proto, 'value');
    if (d && d.set) d.set.call(el, v); else el.value = v;
    var ev;
    try { ev = new InputEvent('input', { bubbles: true, composed: true, inputType: 'insertReplacementText' }); }
    catch (e) { ev = new Event('input', { bubbles: true }); }
    el.dispatchEvent(ev);
    el.dispatchEvent(new Event('change', { bubbles: true }));
    try { el.blur(); } catch (e) { /* ignore */ }
    return el.value.length === v.length;
  }

  var userFilled = false;
  if (user && typeof a.username === 'string' && a.username.length > 0) userFilled = setValue(user, a.username);
  var pwFilled = setValue(pw, a.password);
  // A field that kept only part of the value is cleared: a prefix of the password is not something the redactor knows.
  // First as a user would (events, so page state follows), then, if the page refilled it, with no events at all.
  if (!pwFilled) {
    setValue(pw, '');
    if (pw.value.length !== 0) {
      var cd = Object.getOwnPropertyDescriptor(pw.tagName.toLowerCase() === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype, 'value');
      if (cd && cd.set) cd.set.call(pw, ''); else pw.value = '';
    }
    return fail(pw.value.length === 0 ? 'value_not_accepted' : 'clear_failed', 'password');
  }
  var out = { ok: true, username_filled: userFilled, password_filled: true, chars: a.password.length, submitted: false };
  if (a.submit) {
    var s = doSubmit(pw);
    out.submitted = Boolean(s.ok);
    if (!s.ok) out.submit_error = s.code;
  }
  return out;

  function doSubmit(field) {
    var form = field.form;
    var btn = submitter(form);
    if (form && typeof form.requestSubmit === 'function') {
      try { form.requestSubmit(btn || undefined); return { ok: true }; } catch (e) { /* fall through */ }
    }
    if (btn) { btn.click(); return { ok: true }; }
    if (form) { form.submit(); return { ok: true }; }
    return fail('no_form', 'password');
  }
}
/* eslint-enable no-var */

const PAGE_FUNCTION = dpBrowserFill.toString();

/** An expression that runs the page function with `args` (JSON-serialized) — for evaluate-style APIs. */
function pageExpression(args) {
  return `(${PAGE_FUNCTION})(${JSON.stringify(args)})`;
}

module.exports = { PAGE_FUNCTION, pageExpression, dpBrowserFill };
