// Cross-browser pieces of the fill path, kept free of extension globals so
// they can be unit tested in Node.
//
// Document identity. The content script makes a random 128-bit nonce per
// document, in its isolated world (the page cannot read it), and sends it
// with every message. The background keys each document by the browser's
// MessageSender.documentId when the browser sets one (Chromium 106+,
// Firefox 153+), and by the nonce otherwise. At fill time the injected
// function checks the nonce and location.origin in the same task as the
// write, so a navigated frame (new document, new nonce) is refused in every
// browser, whether the injection targeted documentIds or only frameIds.

import { normalizeOrigin } from './origin.js';

const NONCE_RE = /^[0-9a-f]{32}$/;

// The document a content-script message came from, or null when it cannot be
// identified. Only browser-set MessageSender fields decide the origin:
// sender.origin when present (Chromium 80+, Firefox 126+), else the origin of
// sender.url. The content script's own location.origin must agree with it.
export function senderFrame(sender, msg) {
  if (!sender || !sender.tab || typeof sender.tab.id !== 'number' || typeof sender.frameId !== 'number') return null;
  const nonce = msg && typeof msg.doc === 'string' && NONCE_RE.test(msg.doc) ? msg.doc : null;
  if (!nonce) return null;
  const documentId = typeof sender.documentId === 'string' && sender.documentId.length > 0 ? sender.documentId : null;
  let origin = typeof sender.origin === 'string' ? normalizeOrigin(sender.origin) : normalizeOrigin(sender.url || '');
  if (origin && msg.origin !== origin) origin = null;
  return {
    key: documentId ? 'd:' + documentId : 'n:' + nonce,
    documentId,
    nonce,
    tabId: sender.tab.id,
    frameId: sender.frameId,
    origin,
  };
}

// scripting.executeScript target for a recorded document: the exact document
// when the browser gave us its id, else the frame (the nonce check in
// injectedFill then rejects a different document in that frame).
export function injectionTarget(tabId, rec) {
  if (rec.documentId) return { tabId, documentIds: [rec.documentId] };
  return { tabId, frameIds: [rec.frameId] };
}

// Host-permission match pattern for a fillable origin. Match patterns carry
// no port (Firefox rejects one; Chromium would narrow to it), so the pattern
// covers every port on that scheme + host.
export function sitePermissionPattern(origin) {
  const o = normalizeOrigin(origin);
  if (!o) return null;
  const u = new URL(o);
  return `${u.protocol}//${u.hostname}/*`;
}

// Runs inside the target frame, in the extension's isolated world (shared
// with the content script, so it sees the nonce and the detector). Must stay
// self-contained: executeScript serializes it.
export function injectedFill(expectedOrigin, expectedNonce, username, password) {
  if (location.origin !== expectedOrigin) return { ok: false, error: 'origin_changed' };
  if (globalThis.__demipassDoc !== expectedNonce) return { ok: false, error: 'document_changed' };
  const D = globalThis.DemiPassFormDetect;
  if (!D) return { ok: false, error: 'detector_missing' };
  const f = D.findLoginFields(document);
  if (!f || !f.password) return { ok: false, error: 'no_login_form' };
  let user = false;
  if (f.username && username) { D.setInputValue(f.username, username); user = true; }
  D.setInputValue(f.password, password);
  return { ok: true, username: user, password: true };
}

// Does a granted host match pattern give access to every page of `origin`?
// permissions.contains() is not usable for this: Chromium answers false for
// hosts granted through content_scripts matches even though getAll() lists
// them, so the background matches getAll().origins itself.
export function patternCoversOrigin(pattern, origin) {
  const o = normalizeOrigin(origin);
  if (!o || typeof pattern !== 'string') return false;
  if (pattern === '<all_urls>') return true;
  const m = /^(\*|https?):\/\/(\*|\*\.[^/:*]+|[^/:*]+)(?::(\d+|\*))?(\/.*)$/.exec(pattern);
  if (!m) return false;
  const [, scheme, host, port, pathPart] = m;
  if (pathPart !== '/*') return false; // a path-limited grant does not cover the whole origin
  const u = new URL(o);
  if (scheme !== '*' && scheme + ':' !== u.protocol) return false;
  if (port && port !== '*' && port !== (u.port || (u.protocol === 'https:' ? '443' : '80'))) return false;
  if (host === '*') return true;
  if (host.startsWith('*.')) return u.hostname === host.slice(2) || u.hostname.endsWith(host.slice(1));
  return u.hostname === host;
}

export function originsCover(granted, origin) {
  return Array.isArray(granted) && granted.some((p) => patternCoversOrigin(p, origin));
}

// Every http(s) origin, i.e. "all sites".
export function coversAllSites(granted) {
  return Array.isArray(granted) && granted.some((p) => p === '<all_urls>' || p === '*://*/*');
}
