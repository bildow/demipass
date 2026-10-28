import test from 'node:test';
import assert from 'node:assert/strict';
import { senderFrame, injectionTarget, injectedFill, sitePermissionPattern, patternCoversOrigin, originsCover, coversAllSites } from '../lib/compat.js';

const NONCE = 'a'.repeat(32);
const NONCE2 = 'b'.repeat(32);
const tab = { id: 7 };

test('senderFrame: Chromium sender (documentId + origin) is keyed by documentId', () => {
  const f = senderFrame({ tab, frameId: 0, documentId: 'DOC1', origin: 'https://example.com', url: 'https://example.com/login' }, { doc: NONCE, origin: 'https://example.com' });
  assert.deepEqual(f, { key: 'd:DOC1', documentId: 'DOC1', nonce: NONCE, tabId: 7, frameId: 0, origin: 'https://example.com' });
});

test('senderFrame: Firefox 153+ sender is handled the same way', () => {
  const f = senderFrame({ tab, frameId: 12, documentId: '9e2c-…', origin: 'https://login.example.com', url: 'https://login.example.com/' }, { doc: NONCE, origin: 'https://login.example.com' });
  assert.equal(f.key, 'd:9e2c-…');
  assert.equal(f.frameId, 12);
  assert.equal(f.origin, 'https://login.example.com');
});

test('senderFrame: no documentId / no sender.origin (older Gecko) falls back to the nonce and sender.url', () => {
  const f = senderFrame({ tab, frameId: 3, url: 'https://example.com:8443/a?b#c' }, { doc: NONCE, origin: 'https://example.com:8443' });
  assert.equal(f.key, 'n:' + NONCE);
  assert.equal(f.documentId, null);
  assert.equal(f.origin, 'https://example.com:8443');
});

test('senderFrame: a different document in the same frame gets a different key', () => {
  const a = senderFrame({ tab, frameId: 3, url: 'https://example.com/' }, { doc: NONCE, origin: 'https://example.com' });
  const b = senderFrame({ tab, frameId: 3, url: 'https://example.com/' }, { doc: NONCE2, origin: 'https://example.com' });
  assert.notEqual(a.key, b.key);
});

test('senderFrame: origin is unfillable when the content script and the browser disagree', () => {
  // e.g. a sandboxed frame: URL says https://example.com, the document's origin is opaque.
  const f = senderFrame({ tab, frameId: 1, url: 'https://example.com/' }, { doc: NONCE, origin: 'null' });
  assert.equal(f.origin, null);
  const g = senderFrame({ tab, frameId: 1, documentId: 'D', origin: 'https://a.example', url: 'https://a.example/' }, { doc: NONCE, origin: 'https://b.example' });
  assert.equal(g.origin, null);
});

test('senderFrame: browser-set opaque / non-fillable origins stay unfillable', () => {
  assert.equal(senderFrame({ tab, frameId: 1, documentId: 'D', origin: 'null', url: 'https://x.example/' }, { doc: NONCE, origin: 'null' }).origin, null);
  assert.equal(senderFrame({ tab, frameId: 0, url: 'http://example.com/' }, { doc: NONCE, origin: 'http://example.com' }).origin, null);
  assert.equal(senderFrame({ tab, frameId: 0, url: 'about:blank' }, { doc: NONCE, origin: 'https://example.com' }).origin, null);
  // sender.origin wins over sender.url when present.
  assert.equal(senderFrame({ tab, frameId: 0, origin: 'null', url: 'https://x.example/' }, { doc: NONCE, origin: 'https://x.example' }).origin, null);
});

test('senderFrame: rejects messages without a tab, frame or well-formed nonce', () => {
  const s = { tab, frameId: 0, url: 'https://example.com/' };
  assert.equal(senderFrame({ frameId: 0, url: 'https://example.com/' }, { doc: NONCE }), null);
  assert.equal(senderFrame({ tab, url: 'https://example.com/' }, { doc: NONCE }), null);
  assert.equal(senderFrame(s, {}), null);
  assert.equal(senderFrame(s, { doc: 'short' }), null);
  assert.equal(senderFrame(s, { doc: 'A'.repeat(32) }), null);
  assert.equal(senderFrame(s, null), null);
});

test('injectionTarget: documentIds when known, else frameIds', () => {
  assert.deepEqual(injectionTarget(7, { documentId: 'D', frameId: 4 }), { tabId: 7, documentIds: ['D'] });
  assert.deepEqual(injectionTarget(7, { documentId: null, frameId: 4 }), { tabId: 7, frameIds: [4] });
});

test('sitePermissionPattern drops the port and refuses unfillable origins', () => {
  assert.equal(sitePermissionPattern('https://example.com'), 'https://example.com/*');
  assert.equal(sitePermissionPattern('https://example.com:8443'), 'https://example.com/*');
  assert.equal(sitePermissionPattern('http://localhost:8788'), 'http://localhost/*');
  assert.equal(sitePermissionPattern('http://example.com'), null);
  assert.equal(sitePermissionPattern('null'), null);
});

test('patternCoversOrigin / originsCover / coversAllSites', () => {
  const o = 'https://a.example.com';
  assert.equal(patternCoversOrigin('<all_urls>', o), true);
  assert.equal(patternCoversOrigin('*://*/*', o), true);
  assert.equal(patternCoversOrigin('https://*/*', o), true);
  assert.equal(patternCoversOrigin('http://*/*', o), false);
  assert.equal(patternCoversOrigin('https://a.example.com/*', o), true);
  assert.equal(patternCoversOrigin('https://*.example.com/*', o), true);
  assert.equal(patternCoversOrigin('https://*.example.com/*', 'https://example.com'), true);
  assert.equal(patternCoversOrigin('https://*.example.com/*', 'https://badexample.com'), false);
  assert.equal(patternCoversOrigin('https://example.com/*', o), false);
  assert.equal(patternCoversOrigin('https://a.example.com/login/*', o), false, 'path-limited grant');
  assert.equal(patternCoversOrigin('http://localhost:8788/*', 'http://localhost:8788'), true);
  assert.equal(patternCoversOrigin('http://localhost:9999/*', 'http://localhost:8788'), false);
  assert.equal(patternCoversOrigin('https://a.example.com:443/*', o), true);
  assert.equal(patternCoversOrigin('garbage', o), false);
  assert.equal(originsCover(['https://api.dustforge.com/*', 'http://localhost/*'], 'http://localhost:1234'), true);
  assert.equal(originsCover(['https://api.dustforge.com/*'], 'http://localhost:1234'), false);
  assert.equal(originsCover(undefined, o), false);
  assert.equal(coversAllSites(['https://api.dustforge.com/*', '<all_urls>']), true);
  assert.equal(coversAllSites(['*://*/*']), true);
  assert.equal(coversAllSites(['https://*/*']), false);
});

// injectedFill runs in the page's isolated world; emulate the globals it reads.
function withFrame({ origin, nonce, fields }, fn) {
  const saved = { location: globalThis.location, document: globalThis.document, doc: globalThis.__demipassDoc, D: globalThis.DemiPassFormDetect };
  const writes = [];
  Object.defineProperty(globalThis, 'location', { value: { origin }, configurable: true, writable: true });
  globalThis.document = {};
  globalThis.__demipassDoc = nonce;
  globalThis.DemiPassFormDetect = {
    findLoginFields: () => fields,
    setInputValue: (el, v) => writes.push([el.name, v]),
  };
  try { return { out: fn(), writes }; } finally {
    Object.defineProperty(globalThis, 'location', { value: saved.location, configurable: true, writable: true });
    globalThis.document = saved.document;
    globalThis.__demipassDoc = saved.doc;
    globalThis.DemiPassFormDetect = saved.D;
  }
}

const FIELDS = { username: { name: 'user' }, password: { name: 'pass' } };

test('injectedFill fills only when origin and document nonce both match', () => {
  const ok = withFrame({ origin: 'https://example.com', nonce: NONCE, fields: FIELDS }, () => injectedFill('https://example.com', NONCE, 'me', 'pw'));
  assert.deepEqual(ok.out, { ok: true, username: true, password: true });
  assert.deepEqual(ok.writes, [['user', 'me'], ['pass', 'pw']]);

  const wrongOrigin = withFrame({ origin: 'https://evil.example', nonce: NONCE, fields: FIELDS }, () => injectedFill('https://example.com', NONCE, 'me', 'pw'));
  assert.deepEqual(wrongOrigin.out, { ok: false, error: 'origin_changed' });
  assert.deepEqual(wrongOrigin.writes, []);

  const newDoc = withFrame({ origin: 'https://example.com', nonce: NONCE2, fields: FIELDS }, () => injectedFill('https://example.com', NONCE, 'me', 'pw'));
  assert.deepEqual(newDoc.out, { ok: false, error: 'document_changed' });
  assert.deepEqual(newDoc.writes, []);

  const noScript = withFrame({ origin: 'https://example.com', nonce: undefined, fields: FIELDS }, () => injectedFill('https://example.com', NONCE, 'me', 'pw'));
  assert.equal(noScript.out.error, 'document_changed');

  const noForm = withFrame({ origin: 'https://example.com', nonce: NONCE, fields: null }, () => injectedFill('https://example.com', NONCE, 'me', 'pw'));
  assert.deepEqual(noForm.out, { ok: false, error: 'no_login_form' });
});

test('injectedFill is self-contained (executeScript serializes it)', () => {
  // Rebuild it from its source alone, as the browser does, and run it.
  const rebuilt = new Function(`return (${injectedFill.toString()})`)();
  const r = withFrame({ origin: 'https://example.com', nonce: NONCE, fields: { password: { name: 'pass' } } }, () => rebuilt('https://example.com', NONCE, 'me', 'pw'));
  assert.deepEqual(r.out, { ok: true, username: false, password: true });
});
