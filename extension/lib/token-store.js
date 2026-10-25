// Token storage for the background (Chromium service worker / Firefox event page).
//
//   access token  -> storage.session (memory only; trusted contexts only —
//                    Chromium's default access level, and Firefox never
//                    exposes storage.session to content scripts)
//   refresh token -> storage.local, sealed with AES-GCM
//
// storage.local is readable from content scripts by default, so the
// refresh token is not stored there in the clear. The AES key is a
// non-extractable CryptoKey kept in this extension's own IndexedDB, which only
// extension-origin contexts (the background and extension pages) can open.
// Firefox: the extension origin is moz-extension://<per-install UUID>, and
// IndexedDB stores the CryptoKey by structured clone like Chromium does.

const ACCESS_KEY = 'dp_access';
const REFRESH_KEY = 'dp_refresh_sealed';
const DB_NAME = 'demipass-keys';
const STORE = 'keys';
const KEY_ID = 'refresh-seal-v1';

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

let keyPromise = null;
function sealKey() {
  if (!keyPromise) {
    keyPromise = (async () => {
      const existing = await idbOp('readonly', (s) => s.get(KEY_ID));
      if (existing) return existing;
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      await idbOp('readwrite', (s) => s.put(key, KEY_ID));
      return key;
    })().catch((e) => { keyPromise = null; throw e; });
  }
  return keyPromise;
}

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function seal(plain) {
  const key = await sealKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plain));
  return { v: 1, iv: b64(iv), ct: b64(ct) };
}

async function unseal(box) {
  if (!box || box.v !== 1) return null;
  try {
    const key = await sealKey();
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.ct));
    return new TextDecoder().decode(pt);
  } catch {
    return null; // key lost (profile reset) -> treat as not paired
  }
}

export function extensionTokenStore(ext) {
  return {
    async getAccess() {
      const r = await ext.storage.session.get(ACCESS_KEY);
      return r[ACCESS_KEY] || null;
    },
    async setAccess(t) {
      await ext.storage.session.set({ [ACCESS_KEY]: t });
    },
    async getRefresh() {
      const r = await ext.storage.local.get(REFRESH_KEY);
      return unseal(r[REFRESH_KEY]);
    },
    async setRefresh(t) {
      await ext.storage.local.set({ [REFRESH_KEY]: await seal(t) });
    },
    async clear() {
      await ext.storage.session.remove(ACCESS_KEY);
      await ext.storage.local.remove(REFRESH_KEY);
    },
  };
}
