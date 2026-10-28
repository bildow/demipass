import test from 'node:test';
import assert from 'node:assert/strict';
import { extensionTokenStore, openSession, LEGACY_BASE_KEY } from '../lib/token-store.js';
import { normalizeApiBase, DEFAULT_API_BASE } from '../lib/origin.js';

// storage.local / storage.session doubles, and an in-memory stand-in for the
// extension's IndexedDB (CryptoKey objects are kept as is, like structured clone).
function area() {
  const m = new Map();
  return {
    m,
    async get(k) { if (k === null) return Object.fromEntries(m); return m.has(k) ? { [k]: structuredClone(m.get(k)) } : {}; },
    async set(o) { for (const [k, v] of Object.entries(o)) m.set(k, structuredClone(v)); },
    async remove(k) { m.delete(k); },
  };
}
function fakeExt() { return { storage: { local: area(), session: area() } }; }
function memKeys() { const m = new Map(); return { m, get: async (k) => m.get(k), put: async (k, v) => { m.set(k, v); } }; }
const opts = (revoked = []) => ({ normalize: normalizeApiBase, defaultBase: DEFAULT_API_BASE, revoke: async (base, rt) => { revoked.push([base, rt]); } });
const DEV = 'http://127.0.0.1:8787';

test('tokens are sealed with their API base and only returned under that base', async () => {
  const ext = fakeExt();
  const keys = memKeys();
  const s = extensionTokenStore(ext, { keyStore: keys });
  s.bindBase(DEV);
  await s.setRefresh('dpr_refresh_one');
  await s.setAccess('eyJ.access.one');
  assert.equal(await s.getRefresh(), 'dpr_refresh_one');
  assert.equal(await s.getAccess(), 'eyJ.access.one');
  assert.equal(JSON.stringify([...ext.storage.local.m.values()]).includes('dpr_'), false, 'sealed, not plaintext');
  s.bindBase(DEFAULT_API_BASE);
  assert.equal(await s.getRefresh(), null, 'not handed out under another base');
  assert.equal(await s.getAccess(), null);
});

test('openSession: the API base comes from IndexedDB; a storage.local dp_api_base is deleted unread (audit P5)', async () => {
  const ext = fakeExt();
  const keys = memKeys();
  const s = extensionTokenStore(ext, { keyStore: keys });
  await s.saveBase(DEV);
  s.bindBase(DEV);
  await s.setRefresh('dpr_keep');
  // What a content script can do: write storage.local.
  await ext.storage.local.set({ [LEGACY_BASE_KEY]: 'http://127.0.0.1:9999' });
  const fresh = extensionTokenStore(ext, { keyStore: keys }); // background restart
  const revoked = [];
  const out = await openSession(fresh, ext, opts(revoked));
  assert.deepEqual(out, { base: DEV, signedOut: false });
  assert.equal(await fresh.getRefresh(), 'dpr_keep');
  assert.equal(ext.storage.local.m.has(LEGACY_BASE_KEY), false);
  assert.deepEqual(revoked, []);
});

test('openSession: a session sealed for another base is signed out and revoked at its own base', async () => {
  const ext = fakeExt();
  const keys = memKeys();
  const s = extensionTokenStore(ext, { keyStore: keys });
  s.bindBase(DEV);
  await s.setRefresh('dpr_dev');
  await s.setAccess('eyJ.dev');
  await s.saveBase(DEFAULT_API_BASE); // the setting and the session disagree
  const fresh = extensionTokenStore(ext, { keyStore: keys });
  const revoked = [];
  const out = await openSession(fresh, ext, opts(revoked));
  assert.deepEqual(out, { base: DEFAULT_API_BASE, signedOut: true });
  assert.equal(await fresh.getRefresh(), null);
  assert.equal(ext.storage.local.m.has('dp_refresh_sealed'), false);
  assert.equal(ext.storage.session.m.has('dp_access'), false);
  assert.deepEqual(revoked, [[DEV, 'dpr_dev']]);
});

test('openSession: no saved base means production; a junk saved base also means production', async () => {
  const ext = fakeExt();
  const keys = memKeys();
  assert.equal((await openSession(extensionTokenStore(ext, { keyStore: keys }), ext, opts())).base, DEFAULT_API_BASE);
  await keys.put('api-base-v1', 'https://evil.example');
  assert.equal((await openSession(extensionTokenStore(ext, { keyStore: keys }), ext, opts())).base, DEFAULT_API_BASE);
});

// Pre-seeded legacy profile: what a build before this change left behind.
test('migration: a v1 sealed refresh token + storage.local dp_api_base are signed out, not trusted', async () => {
  const ext = fakeExt();
  const keys = memKeys();
  await ext.storage.local.set({
    dp_api_base: DEV,
    dp_refresh_sealed: { v: 1, iv: 'AAAAAAAAAAAAAAAA', ct: 'AAAA' },
  });
  await ext.storage.session.set({ dp_access: 'eyJ.legacy.plain-string' });
  const s = extensionTokenStore(ext, { keyStore: keys });
  const revoked = [];
  const out = await openSession(s, ext, opts(revoked));
  assert.deepEqual(out, { base: DEFAULT_API_BASE, signedOut: true });
  assert.equal(ext.storage.local.m.size, 0, 'legacy base and v1 blob both gone');
  assert.equal(ext.storage.session.m.has('dp_access'), false);
  assert.equal(await s.getAccess(), null);
  assert.deepEqual(revoked, [], 'a v1 blob does not say where it came from, so nothing is sent anywhere');
});

test('a tampered or foreign sealed blob reads as not paired', async () => {
  const ext = fakeExt();
  const s = extensionTokenStore(ext, { keyStore: memKeys() });
  s.bindBase(DEV);
  await s.setRefresh('dpr_x');
  const other = extensionTokenStore(ext, { keyStore: memKeys() }); // a different key
  other.bindBase(DEV);
  assert.equal(await other.getRefresh(), null);
});
