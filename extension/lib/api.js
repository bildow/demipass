// DemiPass API client for the background service worker. Nothing else in the
// extension talks to the API or sees a token.
//
// Rules this file keeps:
//  - No logging. Errors carry the HTTP status and the server's short error
//    code, never a request or response body (a body can hold a value).
//  - Refresh tokens are single use. Refresh is single-flight, and the new
//    refresh token is persisted before the new access token is used.

export class ApiError extends Error {
  constructor(status, code, extra) {
    super(code ? `${code} (HTTP ${status})` : `HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = code || null;
    // Only whitelisted, non-secret fields from an error body.
    if (extra && Array.isArray(extra.bound_origins)) this.boundOrigins = extra.bound_origins.slice(0, 10).map(String);
  }
}

export class NotPairedError extends Error {
  constructor(reason) {
    super(reason || 'not paired');
    this.name = 'NotPairedError';
  }
}

// Error bodies that mean "your bearer token was not accepted", as opposed to
// a real answer. With ADMIN_API_KEY set, dustforge's getDemiPassActor answers
// a bad bearer with 403 and this text instead of 401.
const AUTH_REJECT_403 = new Set(['admin access or Bearer token required']);

function errCode(body) {
  return body && typeof body.error === 'string' ? body.error.slice(0, 120) : null;
}

// exp (seconds) from a JWT payload, or null. Not a verification — only used
// to refresh ahead of expiry.
export function jwtClaims(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const json = typeof atob === 'function' ? atob(pad) : Buffer.from(pad, 'base64').toString('binary');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

// tokens: { getAccess(), setAccess(t), getRefresh(), setRefresh(t), clear() } — all async.
export class ApiClient {
  constructor({ base, fetch, tokens, now = () => Date.now(), skewMs = 60_000 }) {
    if (!base || !fetch || !tokens) throw new Error('ApiClient needs base, fetch and tokens');
    this.base = base.replace(/\/+$/, '');
    this.fetch = fetch;
    this.tokens = tokens;
    this.now = now;
    this.skewMs = skewMs;
    this.refreshing = null;
  }

  async raw(method, path, body, accessToken) {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
    let res;
    try {
      res = await this.fetch(this.base + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
      });
    } catch {
      throw new ApiError(0, 'network_error');
    }
    let json = null;
    try { json = await res.json(); } catch { json = null; }
    return { status: res.status, body: json };
  }

  async isPaired() {
    return !!(await this.tokens.getRefresh());
  }

  expiringSoon(access) {
    const c = jwtClaims(access);
    if (!c || typeof c.exp !== 'number') return false; // unknown: let the server decide
    return c.exp * 1000 - this.now() < this.skewMs;
  }

  // Single-flight refresh. Two parallel refreshes with one single-use token
  // would revoke the session, so every caller shares one in-flight promise.
  refresh() {
    if (!this.refreshing) {
      this.refreshing = this.doRefresh().finally(() => { this.refreshing = null; });
    }
    return this.refreshing;
  }

  async doRefresh() {
    const rt = await this.tokens.getRefresh();
    if (!rt) throw new NotPairedError();
    const r = await this.raw('POST', '/api/identity/refresh', { refresh_token: rt });
    if (r.status === 200 && r.body && r.body.token && r.body.refresh_token) {
      // Persist the rotated refresh token first: the old one is already spent.
      await this.tokens.setRefresh(r.body.refresh_token);
      await this.tokens.setAccess(r.body.token);
      return r.body.token;
    }
    if (r.status === 401 || r.status === 404 || r.status === 400) {
      await this.tokens.clear();
      throw new NotPairedError('session ended — pair again');
    }
    throw new ApiError(r.status, errCode(r.body) || 'refresh_failed');
  }

  async accessToken() {
    let at = await this.tokens.getAccess();
    if (!at || this.expiringSoon(at)) at = await this.refresh();
    return at;
  }

  // Authenticated call. Refreshes ahead of expiry, and once more if the
  // server rejects the bearer (401, or the 403 text above).
  async call(method, path, body) {
    let at = await this.accessToken();
    let r = await this.raw(method, path, body, at);
    const rejected = r.status === 401 || (r.status === 403 && AUTH_REJECT_403.has(errCode(r.body)));
    if (rejected) {
      at = await this.refresh();
      r = await this.raw(method, path, body, at);
    }
    return r;
  }

  // ---- device flow ---------------------------------------------------------

  async startPairing(agentLabel) {
    const r = await this.raw('POST', '/api/identity/device/code', { agent_label: agentLabel, scope: 'transact' });
    if (r.status !== 200 || !r.body || !r.body.device_code || !r.body.user_code) {
      throw new ApiError(r.status, errCode(r.body) || 'pairing_failed');
    }
    const b = r.body;
    return {
      device_code: b.device_code,
      user_code: String(b.user_code),
      verification_url: 'https://demipass.com/device',
      verification_url_complete: 'https://demipass.com/device?code=' + encodeURIComponent(String(b.user_code)),
      interval: Math.max(2, Number(b.interval) || 5),
      expires_in: Math.max(10, Number(b.expires_in) || 600),
    };
  }

  // One poll. -> { state: 'pending' | 'paired' | 'denied' | 'expired' }
  async pollPairing(deviceCode) {
    const r = await this.raw('POST', '/api/identity/device/token', { device_code: deviceCode });
    const code = errCode(r.body);
    if (r.status === 428) return { state: 'pending' };
    if (r.status === 200 && r.body && r.body.token && r.body.refresh_token) {
      await this.tokens.setRefresh(r.body.refresh_token);
      await this.tokens.setAccess(r.body.token);
      return { state: 'paired', scope: r.body.scope || null, email: r.body.email || null };
    }
    if (r.status === 403) return { state: 'denied' };
    if (r.status === 400 && (code === 'expired_token' || code === 'already_claimed' || code === 'invalid device_code')) {
      return { state: 'expired' };
    }
    throw new ApiError(r.status, code || 'pairing_poll_failed');
  }

  async signOut() {
    const rt = await this.tokens.getRefresh();
    const at = await this.tokens.getAccess();
    await this.tokens.clear();
    const out = { refreshRevoked: false, accessRevoked: false };
    if (rt) {
      try {
        const r = await this.raw('POST', '/api/identity/refresh/revoke', { refresh_token: rt });
        out.refreshRevoked = r.status === 200;
      } catch {}
    }
    // Best effort: kill the live access token too, so it does not outlive sign-out.
    const jti = jwtClaims(at)?.jti;
    if (at && jti) {
      try {
        const r = await this.raw('POST', '/api/identity/tokens/revoke', { jti }, at);
        out.accessRevoked = r.status === 200;
      } catch {}
    }
    return out;
  }

  // ---- vault ---------------------------------------------------------------

  async candidates(origin) {
    const r = await this.call('GET', '/api/blindkey/fill/candidates?origin=' + encodeURIComponent(origin));
    if (r.status !== 200 || !r.body || !Array.isArray(r.body.candidates)) {
      throw new ApiError(r.status, errCode(r.body) || 'candidates_failed');
    }
    return r.body.candidates.map((c) => ({
      ref: String(c.ref),
      name: String(c.name || ''),
      username: c.username == null ? '' : String(c.username),
      secret_type: String(c.secret_type || ''),
    }));
  }

  // { name, value, secret_type, login?, origins?, description? }
  async store(entry) {
    const body = { name: entry.name, value: entry.value, secret_type: entry.secret_type };
    if (entry.login) body.login = entry.login;
    if (entry.origins && entry.origins.length) body.origins = entry.origins;
    if (entry.description) body.description = entry.description;
    const r = await this.call('POST', '/api/blindkey/store', body);
    if (r.status !== 200 || !r.body || !r.body.ok) throw new ApiError(r.status, errCode(r.body) || 'store_failed');
    return { name: r.body.name, ref: r.body.ref, secret_type: r.body.secret_type };
  }

  async requestFill(ref, origin, clientLabel) {
    const r = await this.call('POST', '/api/blindkey/fill/request', { ref, origin, client_label: clientLabel });
    if (r.status === 201 && r.body && r.body.request_id) {
      return { request_id: String(r.body.request_id), status: r.body.status, expires_in: Number(r.body.expires_in) || 120 };
    }
    throw new ApiError(r.status, errCode(r.body) || 'fill_request_failed', r.body);
  }

  // One redeem attempt.
  // -> { state: 'pending' } | { state: 'denied' } | { state: 'expired' } |
  //    { state: 'already_redeemed' } | { state: 'approved', fill: {...value} }
  async redeemOnce(requestId) {
    const r = await this.call('POST', '/api/blindkey/fill/redeem', { request_id: requestId });
    const code = errCode(r.body);
    if (r.status === 428) return { state: 'pending' };
    if (r.status === 403 && code === 'denied') return { state: 'denied' };
    if (r.status === 410) return { state: code === 'already_redeemed' ? 'already_redeemed' : 'expired' };
    if (r.status === 200 && r.body && r.body.ok && typeof r.body.value === 'string') {
      const b = r.body;
      return {
        state: 'approved',
        fill: { value: b.value, username: b.username == null ? '' : String(b.username), origin: String(b.origin || ''), name: String(b.name || ''), ref: String(b.ref || '') },
      };
    }
    throw new ApiError(r.status, code || 'redeem_failed');
  }
}

const realSleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Polls redeem until a terminal state. The deadline is the server's
// expires_in plus a little slack; the server stays authoritative.
export async function waitForFill(client, requestId, { expiresIn = 120, intervalMs = 2000, sleep = realSleep, now = () => Date.now(), isCancelled = () => false, onPending } = {}) {
  const deadline = now() + expiresIn * 1000 + 5000;
  for (;;) {
    if (isCancelled()) return { state: 'cancelled' };
    const r = await client.redeemOnce(requestId);
    if (r.state !== 'pending') return r;
    if (onPending) onPending();
    if (now() >= deadline) return { state: 'expired' };
    await sleep(intervalMs);
  }
}

export async function waitForPairing(client, deviceCode, { interval = 5, expiresIn = 600, sleep = realSleep, now = () => Date.now(), isCancelled = () => false } = {}) {
  const deadline = now() + expiresIn * 1000;
  for (;;) {
    if (isCancelled()) return { state: 'cancelled' };
    const r = await client.pollPairing(deviceCode);
    if (r.state !== 'pending') return r;
    if (now() >= deadline) return { state: 'expired' };
    await sleep(interval * 1000);
  }
}
