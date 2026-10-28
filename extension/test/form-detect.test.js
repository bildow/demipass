import test from 'node:test';
import assert from 'node:assert/strict';
import '../content/form-detect.js';

const { pickLoginFields } = globalThis.DemiPassFormDetect;
const inp = (o) => ({ type: 'text', name: '', id: '', autocomplete: '', visible: true, disabled: false, readOnly: false, formIndex: 0, ...o });

test('no password field -> not a login form', () => {
  assert.equal(pickLoginFields([inp({ name: 'q', type: 'search' })]), null);
  assert.equal(pickLoginFields([]), null);
  assert.equal(pickLoginFields(undefined), null);
});

test('classic email + password login', () => {
  const r = pickLoginFields([inp({ type: 'email', name: 'email' }), inp({ type: 'password', name: 'password' })]);
  assert.deepEqual(r, { kind: 'login', usernameIndex: 0, passwordIndex: 1, newPasswordIndex: -1 });
});

test('username picked by autocomplete over position', () => {
  const r = pickLoginFields([
    inp({ name: 'login', autocomplete: 'username' }),
    inp({ name: 'remember_label' }),
    inp({ type: 'password' }),
  ]);
  assert.equal(r.usernameIndex, 0);
});

test('search and OTP boxes are not usernames', () => {
  const r = pickLoginFields([inp({ name: 'search', type: 'search' }), inp({ name: 'otp_code' }), inp({ type: 'password' })]);
  assert.equal(r.usernameIndex, -1);
});

test('hidden, disabled and read-only password fields are ignored', () => {
  assert.equal(pickLoginFields([inp({ type: 'password', visible: false })]), null);
  assert.equal(pickLoginFields([inp({ type: 'password', disabled: true })]), null);
  assert.equal(pickLoginFields([inp({ type: 'password', readOnly: true })]), null);
});

test('username must be in the same form as the password', () => {
  const r = pickLoginFields([
    inp({ name: 'newsletter_email', type: 'email', formIndex: 0 }),
    inp({ name: 'user', formIndex: 1 }),
    inp({ type: 'password', formIndex: 1 }),
  ]);
  assert.equal(r.usernameIndex, 1);
});

test('login form is preferred over a later signup form on the same page', () => {
  const r = pickLoginFields([
    inp({ name: 'user', formIndex: 0 }), inp({ type: 'password', formIndex: 0 }),
    inp({ name: 'new_user', formIndex: 1 }), inp({ type: 'password', formIndex: 1 }), inp({ type: 'password', formIndex: 1 }),
  ]);
  assert.equal(r.kind, 'login');
  assert.equal(r.passwordIndex, 1);
});

test('signup: password + confirm captures the new password', () => {
  const r = pickLoginFields([inp({ type: 'email' }), inp({ type: 'password' }), inp({ type: 'password' })]);
  assert.equal(r.kind, 'signup');
  assert.equal(r.newPasswordIndex, 1);
});

test('change password: current fills, new is captured', () => {
  const r = pickLoginFields([
    inp({ name: 'user', autocomplete: 'username' }),
    inp({ type: 'password', autocomplete: 'current-password' }),
    inp({ type: 'password', autocomplete: 'new-password' }),
    inp({ type: 'password', autocomplete: 'new-password' }),
  ]);
  assert.equal(r.kind, 'change');
  assert.equal(r.passwordIndex, 1);
  assert.equal(r.newPasswordIndex, 2);
});

test('a single new-password field is a signup', () => {
  const r = pickLoginFields([inp({ type: 'email' }), inp({ type: 'password', autocomplete: 'new-password' })]);
  assert.equal(r.kind, 'signup');
  assert.equal(r.newPasswordIndex, 1);
});

test('formIndex option scopes detection to one form', () => {
  const list = [inp({ type: 'password', formIndex: 0 }), inp({ name: 'email', type: 'email', formIndex: 1 }), inp({ type: 'password', formIndex: 1 })];
  const r = pickLoginFields(list, { formIndex: 1 });
  assert.equal(r.passwordIndex, 2);
  assert.equal(r.usernameIndex, 1);
});

test('form-less login (formIndex -1) still pairs username and password', () => {
  const r = pickLoginFields([inp({ name: 'username', formIndex: -1 }), inp({ type: 'password', formIndex: -1 })]);
  assert.equal(r.usernameIndex, 0);
});

test('a text field named or labelled as a password is never the username', () => {
  // a show-password toggle that swaps in a new type=text field, a CSS-masked text field
  for (const f of [inp({ placeholder: 'Account password' }), inp({ name: 'user[password]' }), inp({ id: 'login-pwd' }), inp({ label: 'PIN' })]) {
    const r = pickLoginFields([f, inp({ type: 'password' })]);
    assert.notEqual(r.usernameIndex, 0, JSON.stringify(f));
  }
});

test('passport, compass and passkey fields are still usernames', () => {
  for (const f of [inp({ placeholder: 'Email or passport number' }), inp({ name: 'compass_id' }), inp({ type: 'email', name: 'passkey_email' })]) {
    assert.equal(pickLoginFields([f, inp({ type: 'password' })]).usernameIndex, 0, JSON.stringify(f));
  }
});
