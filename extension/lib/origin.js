// Origin rules from docs/browser-fill-api.md (dustforge feat/browser-fill):
//   origin = new URL(x).origin  ->  scheme://host[:port]
//   https: always; http: only for localhost and 127.0.0.1; matching is exact.

export const MAX_ORIGINS_PER_SECRET = 10;
const HTTP_HOSTS = new Set(['localhost', '127.0.0.1']);

// Returns the normalized origin for a URL or origin string, or null when the
// contract does not allow filling there (opaque origins, other schemes,
// plain http on a non-loopback host).
export function normalizeOrigin(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 2048) return null;
  let u;
  try { u = new URL(input); } catch { return null; }
  if (u.protocol === 'https:') {
    if (!u.hostname) return null;
    return u.origin;
  }
  if (u.protocol === 'http:' && HTTP_HOSTS.has(u.hostname)) return u.origin;
  return null;
}

export function isFillableOrigin(input) {
  return normalizeOrigin(input) !== null;
}

// Exact comparison after normalization. Both sides must be fillable.
export function sameOrigin(a, b) {
  const na = normalizeOrigin(a);
  const nb = normalizeOrigin(b);
  return na !== null && na === nb;
}

// The API base the background is allowed to talk to: production, or a
// loopback dev server (the local mock). Anything else falls back to production.
export const DEFAULT_API_BASE = 'https://api.dustforge.com';
export function normalizeApiBase(input) {
  if (input === undefined || input === null || input === '') return DEFAULT_API_BASE;
  let u;
  try { u = new URL(String(input)); } catch { return null; }
  if (u.pathname !== '/' || u.search || u.hash || u.username || u.password) return null;
  if (u.origin === DEFAULT_API_BASE) return DEFAULT_API_BASE;
  if ((u.protocol === 'http:' || u.protocol === 'https:') && HTTP_HOSTS.has(u.hostname)) return u.origin;
  return null;
}

// Suggested secret name for a site login: "example.com (alice@example.com)".
// The server caps names at 64 characters.
export function suggestLoginName(origin, login) {
  let host = origin;
  try { host = new URL(origin).host; } catch {}
  const base = login ? `${host} (${login})` : host;
  return base.length <= 64 ? base : base.slice(0, 63) + '…';
}
