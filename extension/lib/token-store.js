// Token storage for the background (Chromium service worker / Firefox event page).
//
//   access token  -> storage.session (memory only; trusted contexts only —
//                    Chromium's default access level, and Firefox never
//                    exposes storage.session to content scripts)
//   refresh token -> storage.local, sealed with AES-GCM
//   API base      -> the extension's own IndexedDB (not storage.local)
//
// storage.local is readable AND writable from content scripts by default, so
// nothing there is trusted: the refresh token is sealed (a content script
// can delete or replay the blob, which only signs the person out, but cannot
// read it or make a new one), and the API server setting is not kept there
// at all. The AES key is a non-extractable CryptoKey in this extension's own
// IndexedDB, which only extension-origin contexts (the background and
// extension pages) can open; the API base lives next to it.
// Firefox: the extension origin is moz-extension://<per-install UUID>, and
// IndexedDB stores the CryptoKey by structured clone like Chromium does.
//
// Tokens are bound to the API base they were issued by: the sealed refresh
// token and the session access token both carry it, a token read under a
// different base is not returned, and openSession() signs out at startup if
// the stored session belongs to another base.

const ACCESS_KEY = 'dp_access';
const REFRESH_KEY = 'dp_refresh_sealed';
export const LEGACY_BASE_KEY = 'dp_api_base'; // pre-audit builds kept the API base in storage.local
const DB_NAME = 'demipass-keys';
const STORE = 'keys';
const KEY_ID = 'refresh-seal-v1';
const BASE_ID = 'api-base-v1';

function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(new Error('key store unavailable'));
  });
}

function idbOp(mode, fn) {
  return idb().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const r = fn(tx.objectStore(STORE));
    tx.oncomplete = () => { db.close(); resolve(r && r.result); };
    tx.onerror = () => { db.close(); reject(new Error('key store failed')); };
  }));
}

// { get(id), put(id, value) } over the extension's IndexedDB.
export function idbKeyStore() {
  return {
    get: (id) => idbOp('readonly', (s) => s.get(id)),
    put: (id, v) => idbOp('readwrite', (s) => s.put(v, id)),
  };
}

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function extensionTokenStore(ext, { keyStore = idbKeyStore() } = {}) {
  let base = null; // the API base tokens are bound to (bindBase)
  let keyPromise = null;

  function sealKey() {
    if (!keyPromise) {
      keyPromise = (async () => {
        const existing = await keyStore.get(KEY_ID);
        if (existing) return existing;
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        await keyStore.put(KEY_ID, key);
        return key;
      })().catch((e) => { keyPromise = null; throw e; });
    }
    return keyPromise;
  }

  async function seal(payload) {
    const key = await sealKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(payload)));
    return { v: 2, iv: b64(iv), ct: b64(ct) };
  }

  // -> { state: 'none' } | { state: 'legacy' } (v1: no base inside) | { state: 'bound', rt, base }
  async function readSealed() {
    const r = await ext.storage.local.get(REFRESH_KEY);
    const box = r[REFRESH_KEY];
    if (!box) return { state: 'none' };
    if (box.v === 1) return { state: 'legacy' };
    if (box.v !== 2) return { state: 'none' };
    try {
      const key = await sealKey();
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.ct));
      const p = JSON.parse(new TextDecoder().decode(pt));
      if (typeof p.rt !== 'string' || typeof p.base !== 'string') return { state: 'none' };
      return { state: 'bound', rt: p.rt, base: p.base };
    } catch {
      return { state: 'none' }; // key lost (profile reset) or tampered -> treat as not paired
    }
  }

  return {
    bindBase(b) { base = b; },
    boundBase: () => base,
    async loadBase() {
      const v = await keyStore.get(BASE_ID);
      return typeof v === 'string' ? v : null;
    },
    async saveBase(b) { await keyStore.put(BASE_ID, b); },
    readSealed,
    async getAccess() {
      const r = await ext.storage.session.get(ACCESS_KEY);
      const v = r[ACCESS_KEY];
      return v && typeof v === 'object' && v.base === base && typeof v.t === 'string' ? v.t : null;
    },
    async setAccess(t) {
      await ext.storage.session.set({ [ACCESS_KEY]: { t, base } });
    },
    async getRefresh() {
      const s = await readSealed();
      return s.state === 'bound' && s.base === base ? s.rt : null;
    },
    async setRefresh(t) {
      if (!base) throw new Error('token store has no API base');
      await ext.storage.local.set({ [REFRESH_KEY]: await seal({ rt: t, base }) });
    },
    async clear() {
      await ext.storage.session.remove(ACCESS_KEY);
      await ext.storage.local.remove(REFRESH_KEY);
    },
  };
}

// Startup: decide the API base and make the stored session agree with it.
//  - The base comes only from IndexedDB. A dp_api_base left in storage.local
//    (older builds, or anything a content script wrote) is deleted unread.
//  - A session sealed for another base, or an old v1 blob that says nothing
//    about its base, is signed out locally. A bound one is also revoked at
//    the base it was issued by (that base came out of the sealed blob, so it
//    is ours, and only a loopback dev server or production passes normalize).
// -> { base, signedOut }
export async function openSession(store, ext, { normalize, defaultBase, revoke }) {
  try {
    const legacy = await ext.storage.local.get(LEGACY_BASE_KEY);
    if (legacy && LEGACY_BASE_KEY in legacy) await ext.storage.local.remove(LEGACY_BASE_KEY);
  } catch {}
  const base = normalize(await store.loadBase()) || defaultBase;
  store.bindBase(base);
  const s = await store.readSealed();
  if (s.state === 'legacy' || (s.state === 'bound' && s.base !== base)) {
    await store.clear();
    const issuer = s.state === 'bound' ? normalize(s.base) : null;
    if (issuer && revoke) { try { await revoke(issuer, s.rt); } catch {} }
    return { base, signedOut: true };
  }
  return { base, signedOut: false };
}
