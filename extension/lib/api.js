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
    // Sign-out bumps the generation. An operation that started under an older
    // generation (a refresh, a pairing poll) never persists what it got back:
    // it revokes it instead, so a sign-out cannot be undone by a late answer.
    this.generation = 0;
    this.inflight = new Set();
  }

  // Runs a token-writing operation so signOut() can wait for it.
  track(promise) {
    this.inflight.add(promise);
    promise.finally(() => this.inflight.delete(promise)).catch(() => {});
    return promise;
  }

  // Writes a new pair, unless a sign-out happened meanwhile. A sign-out that
  // lands between the check and the write is caught by the check after it:
  // the pair is taken back out (only if it is still the stored one) and revoked.
  async persist(gen, refreshToken, accessToken) {
    if (gen !== this.generation) { await this.discard(refreshToken, accessToken); throw new NotPairedError('signed out'); }
    await this.tokens.setRefresh(refreshToken);
    await this.tokens.setAccess(accessToken);
    if (gen !== this.generation) {
      if ((await this.tokens.getRefresh()) === refreshToken) await this.tokens.clear();
      await this.discard(refreshToken, accessToken);
      throw new NotPairedError('signed out');
    }
  }

  // Best-effort revoke of a token pair this client must not keep.
  async discard(refreshToken, accessToken) {
    if (refreshToken) { try { await this.raw('POST', '/api/identity/refresh/revoke', { refresh_token: refreshToken }); } catch {} }
    const jti = jwtClaims(accessToken)?.jti;
    if (accessToken && jti) { try { await this.raw('POST', '/api/identity/tokens/revoke', { jti }, accessToken); } catch {} }
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
      const gen = this.generation;
      this.refreshing = this.track(this.doRefresh(gen).finally(() => { this.refreshing = null; }));
    }
    return this.refreshing;
  }

  async doRefresh(gen) {
    const rt = await this.tokens.getRefresh();
    if (!rt || gen !== this.generation) throw new NotPairedError();
    const r = await this.raw('POST', '/api/identity/refresh', { refresh_token: rt });
    if (r.status === 200 && r.body && r.body.token && r.body.refresh_token) {
      // Persist the rotated refresh token first: the old one is already spent.
      // If a sign-out (or a server switch) happened while this was in flight,
      // persist() revokes the new pair instead.
      await this.persist(gen, r.body.refresh_token, r.body.token);
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

  // Refresh now if the access token expires within minValidMs. One refresh
  // at most: whatever the server returns is used.
  async ensureFresh(minValidMs) {
    const at = await this.tokens.getAccess();
    const exp = jwtClaims(at)?.exp;
    if (!at || (typeof exp === 'number' && exp * 1000 - this.now() < minValidMs)) await this.refresh();
  }

  async currentJti() {
    return jwtClaims(await this.tokens.getAccess())?.jti || null;
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
  pollPairing(deviceCode) {
    return this.track(this.doPollPairing(deviceCode, this.generation));
  }

  async doPollPairing(deviceCode, gen) {
    const r = await this.raw('POST', '/api/identity/device/token', { device_code: deviceCode });
    const code = errCode(r.body);
    if (r.status === 428) return { state: 'pending' };
    if (r.status === 200 && r.body && r.body.token && r.body.refresh_token) {
      try { await this.persist(gen, r.body.refresh_token, r.body.token); } catch (e) {
        if (e instanceof NotPairedError) return { state: 'cancelled' };
        throw e;
      }
      return { state: 'paired', scope: r.body.scope || null, email: r.body.email || null };
    }
    if (r.status === 403) return { state: 'denied' };
    if (r.status === 400 && (code === 'expired_token' || code === 'already_claimed' || code === 'invalid device_code')) {
      return { state: 'expired' };
    }
    throw new ApiError(r.status, code || 'pairing_poll_failed');
  }

  // Ends the session for good. Bumps the generation before and after clearing
  // so that a refresh or pairing poll in flight at either point discards (and
  // revokes) what it gets back, waits for those, then clears once more and
  // revokes every token it saw.
  async signOut() {
    const refreshes = new Set();
    const accesses = new Set();
    const grab = async () => {
      const rt = await this.tokens.getRefresh();
      const at = await this.tokens.getAccess();
      if (rt) refreshes.add(rt);
      if (at) accesses.add(at);
      await this.tokens.clear();
    };
    this.generation++;
    await grab();
    this.generation++;
    // Give in-flight refreshes / polls a moment to land (they discard and
    // revoke what they get, see persist()); do not hang sign-out on the network.
    await Promise.race([Promise.allSettled([...this.inflight]), new Promise((r) => setTimeout(r, SIGNOUT_WAIT_MS))]);
    await grab();
    const out = { refreshRevoked: false, accessRevoked: false };
    for (const rt of refreshes) {
      try {
        const r = await this.raw('POST', '/api/identity/refresh/revoke', { refresh_token: rt });
        if (r.status === 200) out.refreshRevoked = true;
      } catch {}
    }
    // Best effort: kill the live access token too, so it does not outlive sign-out.
    for (const at of accesses) {
      const jti = jwtClaims(at)?.jti;
      if (!jti) continue;
      try {
        const r = await this.raw('POST', '/api/identity/tokens/revoke', { jti }, at);
        if (r.status === 200) out.accessRevoked = true;
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

  // Names and types of the owner's secrets (never values), for name-collision checks.
  async listSecrets() {
    const r = await this.call('GET', '/api/blindkey/list');
    if (r.status !== 200 || !r.body || !Array.isArray(r.body.secrets)) throw new ApiError(r.status, errCode(r.body) || 'list_failed');
    return r.body.secrets.map((x) => ({ name: String(x.name || ''), ref: String(x.ref_code || ''), secret_type: String(x.secret_type || '') }));
  }

  // Adds origins to an existing secret's binding (mode 'add' keeps the ones it has).
  async addOrigins(name, origins) {
    const r = await this.call('POST', '/api/blindkey/origins', { name, origins, mode: 'add' });
    if (r.status !== 200 || !r.body || !r.body.ok) throw new ApiError(r.status, errCode(r.body) || 'origins_failed');
    return { ref: String(r.body.ref || ''), origins: Array.isArray(r.body.origins) ? r.body.origins.map(String) : [] };
  }

  // Gives up a fill request this session made (the page left, the person
  // cancelled): a pending card leaves the phone, an approved one can no
  // longer be redeemed. By request_id, and only the asking session (its jti)
  // may do it, so another tab's request is never touched.
  // -> { withdrawn: bool, status }
  async withdrawFill(requestId) {
    const r = await this.call('POST', '/api/blindkey/fill/withdraw', { request_id: requestId });
    if (r.status !== 200 || !r.body || !r.body.ok) return { withdrawn: false, status: r.status === 404 ? 'not_found' : 'error' };
    return { withdrawn: r.body.status === 'withdrawn', status: String(r.body.status || '') };
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

  // A carbon fill request belongs to the one access token (jti) that made it:
  // a refreshed token gets 404 on redeem. So make sure the token outlives the
  // approval window before asking.
  async requestFill(ref, origin, clientLabel) {
    await this.ensureFresh(FILL_MIN_TOKEN_MS);
    const r = await this.call('POST', '/api/blindkey/fill/request', { ref, origin, client_label: clientLabel });
    if (r.status === 201 && r.body && r.body.request_id) {
      return { request_id: String(r.body.request_id), status: r.body.status, expires_in: Number(r.body.expires_in) || 120, jti: await this.currentJti() };
    }
    throw new ApiError(r.status, errCode(r.body) || 'fill_request_failed', r.body);
  }

  // One redeem attempt.
  // -> { state: 'pending' } | { state: 'busy' } (429: rate limited, poll slower) |
  //    { state: 'denied' } | { state: 'expired' } | { state: 'already_redeemed' } | { state: 'withdrawn' } |
  //    { state: 'lost' } (404 and the access token changed: the request belonged to the old one) |
  //    { state: 'gone', error } (404 with the same token, e.g. the login was deleted) |
  //    { state: 'approved', fill: {...value} }
  async redeemOnce(requestId, jti = null) {
    const r = await this.call('POST', '/api/blindkey/fill/redeem', { request_id: requestId });
    const code = errCode(r.body);
    if (r.status === 428) return { state: 'pending' };
    if (r.status === 429) return { state: 'busy' };
    if (r.status === 403 && code === 'denied') return { state: 'denied' };
    if (r.status === 410) return { state: code === 'already_redeemed' ? 'already_redeemed' : code === 'withdrawn' ? 'withdrawn' : 'expired' };
    // The request is bound to the token that asked; after a refresh it is gone.
    // With the same token, a 404 is a real answer (the login was deleted or
    // revoked): asking again would only put another card on the phone.
    if (r.status === 404) {
      const now = await this.currentJti();
      if (!jti || now !== jti) return { state: 'lost' };
      return { state: 'gone', error: code };
    }
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

export const FILL_MIN_TOKEN_MS = 5 * 60 * 1000;
const SIGNOUT_WAIT_MS = 3000;

const realSleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Polls redeem until a terminal state. The deadline is the server's
// expires_in plus a little slack; the server stays authoritative.
// isCancelled may be async (the background checks that the document is still there).
// A 429 while polling is not an answer: wait longer (doubling, up to 16 s) and keep going.
export async function waitForFill(client, requestId, { expiresIn = 120, intervalMs = 2000, sleep = realSleep, now = () => Date.now(), isCancelled = () => false, onPending, jti = null } = {}) {
  const deadline = now() + expiresIn * 1000 + 5000;
  let wait = intervalMs;
  for (;;) {
    if (await isCancelled()) return { state: 'cancelled' };
    // A refresh since the request was made means the server will answer 404;
    // skip the wasted round trip.
    if (jti && (await client.currentJti()) !== jti) return { state: 'lost' };
    const r = await client.redeemOnce(requestId, jti);
    if (r.state === 'busy') wait = Math.min(Math.max(wait * 2, 1), 16000);
    else if (r.state !== 'pending') return r;
    else wait = intervalMs;
    if (onPending && r.state === 'pending') onPending();
    if (now() >= deadline) return { state: 'expired' };
    await sleep(wait);
  }
}

// Request a fill and wait for the phone. If the request is lost to a token
// refresh (redeem 404, or the jti changed), ask once more; onAsk runs for
// each request so the UI can show "Approve on your phone…" again.
export async function requestAndWaitForFill(client, { ref, origin, clientLabel, onAsk, isCancelled, sleep, now, intervalMs, maxAsks = 2 }) {
  let last = { state: 'lost' };
  for (let ask = 1; ask <= maxAsks; ask++) {
    const req = await client.requestFill(ref, origin, clientLabel);
    if (onAsk) onAsk(req, ask);
    last = await waitForFill(client, req.request_id, { expiresIn: req.expires_in, jti: req.jti, isCancelled, sleep, now, intervalMs });
    if (last.state !== 'lost') return { ...last, asks: ask };
  }
  return { ...last, asks: maxAsks };
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
