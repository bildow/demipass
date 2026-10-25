import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeOrigin, isFillableOrigin, sameOrigin, normalizeApiBase, suggestLoginName, DEFAULT_API_BASE } from '../lib/origin.js';

test('https origins normalize to scheme://host[:port]', () => {
  assert.equal(normalizeOrigin('https://example.com/login?x=1#y'), 'https://example.com');
  assert.equal(normalizeOrigin('https://EXAMPLE.com:443/'), 'https://example.com');
  assert.equal(normalizeOrigin('https://example.com:8443/a'), 'https://example.com:8443');
  assert.equal(normalizeOrigin('https://user:pw@example.com/'), 'https://example.com');
  assert.equal(normalizeOrigin('https://bücher.example/'), 'https://xn--bcher-kva.example');
});

test('plain http only for localhost and 127.0.0.1', () => {
  assert.equal(normalizeOrigin('http://localhost:8788/login.html'), 'http://localhost:8788');
  assert.equal(normalizeOrigin('http://127.0.0.1/'), 'http://127.0.0.1');
  assert.equal(normalizeOrigin('http://example.com/'), null);
  assert.equal(normalizeOrigin('http://10.0.0.1/'), null);
  assert.equal(normalizeOrigin('http://[::1]:80/'), null);
  assert.equal(normalizeOrigin('http://localhost.evil.com/'), null);
  assert.equal(normalizeOrigin('http://127.0.0.2/'), null);
});

test('non-web and opaque origins are refused', () => {
  for (const x of ['about:blank', 'data:text/html,hi', 'file:///etc/passwd', 'chrome://settings', 'javascript:alert(1)',
    'chrome-extension://abc/popup.html', 'blob:https://example.com/uuid', 'null', '', 'not a url', null, undefined, 42]) {
    assert.equal(normalizeOrigin(x), null, String(x));
    assert.equal(isFillableOrigin(x), false);
  }
});

test('matching is exact: subdomains and ports differ', () => {
  assert.equal(sameOrigin('https://login.example.com/a', 'https://login.example.com/b'), true);
  assert.equal(sameOrigin('https://login.example.com', 'https://example.com'), false);
  assert.equal(sameOrigin('https://example.com', 'https://example.com:8443'), false);
  assert.equal(sameOrigin('http://localhost:1', 'http://127.0.0.1:1'), false);
  assert.equal(sameOrigin('http://example.com', 'http://example.com'), false, 'both unfillable');
});

test('API base: production or loopback dev server only', () => {
  assert.equal(normalizeApiBase(''), DEFAULT_API_BASE);
  assert.equal(normalizeApiBase(undefined), DEFAULT_API_BASE);
  assert.equal(normalizeApiBase('https://api.dustforge.com/'), DEFAULT_API_BASE);
  assert.equal(normalizeApiBase('http://127.0.0.1:8787'), 'http://127.0.0.1:8787');
  assert.equal(normalizeApiBase('http://localhost:8787/'), 'http://localhost:8787');
  assert.equal(normalizeApiBase('https://api.dustforge.com.evil.com'), null);
  assert.equal(normalizeApiBase('https://evil.example'), null);
  assert.equal(normalizeApiBase('http://127.0.0.1:8787/api'), null);
});

test('suggested login names fit the 64-char limit', () => {
  assert.equal(suggestLoginName('https://example.com', 'me@example.com'), 'example.com (me@example.com)');
  assert.equal(suggestLoginName('http://localhost:8788', ''), 'localhost:8788');
  assert.equal(suggestLoginName('https://example.com', 'x'.repeat(100)).length, 64);
});
