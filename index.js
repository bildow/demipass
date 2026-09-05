/**
 * demipass — DemiPass SDK for Node.js
 * Zero external dependencies. Uses only Node.js built-in https/http.
 *
 * Usage:
 *   const demipass = require('demipass');
 *
 *   demipass.configure({
 *     baseUrl: 'https://api.dustforge.com',
 *     bearerToken: 'my-token',
 *     adminKey: 'optional-admin-key',
 *   });
 *
 *   // Store a secret
 *   await demipass.store({ name: 'OPENROUTER_KEY', value: 'sk-...' });
 *
 *   // Silicon requests a use-token
 *   const { token } = await demipass.requestToken({ secretName: 'OPENROUTER_KEY' });
 *
 *   // Redeem the token
 *   const result = await demipass.execute({ token, action: 'inject_env' });
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

const AGENT_HEADER = 'demipass-sdk/1.0';

// ── Module-level config ──

const config = {
  baseUrl: 'https://api.dustforge.com',
  bearerToken: '',
  adminKey: '',
};

function configure(opts) {
  if (opts.baseUrl) config.baseUrl = opts.baseUrl;
  if (opts.bearerToken) config.bearerToken = opts.bearerToken;
  if (opts.adminKey) config.adminKey = opts.adminKey;
}

// ── Internal HTTP helper ──

function _send(method, path, body, query) {
  return new Promise((resolve, reject) => {
    let url = `${config.baseUrl}${path}`;
    if (query) {
      const qs = Object.entries(query)
        .filter(([, v]) => v !== undefined && v !== null)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&');
      if (qs) url += `?${qs}`;
    }

    const parsed = new URL(url);
    const transport = parsed.protocol === 'https:' ? https : http;
    const payload = body ? JSON.stringify(body) : null;

    const opts = {
      method,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        'X-DemiPass-Agent': AGENT_HEADER,
        'Accept': 'application/json',
      },
    };

    if (config.bearerToken) {
      opts.headers['Authorization'] = `Bearer ${config.bearerToken}`;
    }
    if (config.adminKey) {
      opts.headers['X-Admin-Key'] = config.adminKey;
    }

    if (payload) {
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = transport.request(opts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString();
        let data;
        try { data = JSON.parse(raw); } catch { data = raw; }
        resolve({ status: res.statusCode, data });
      });
    });

    req.on('error', (err) => reject(new Error(`Network error: ${err.message}`)));
    if (payload) req.write(payload);
    req.end();
  });
}

// Throwing wrapper: every SDK method uses this. Non-2xx becomes an Error carrying the server's message.
function _request(method, path, body, query) {
  return _send(method, path, body, query).then(({ status, data }) => {
    if (status >= 400) {
      const msg = (data && data.error) || `HTTP ${status}`;
      throw new Error(`${method} ${path} failed: ${msg}`);
    }
    return data;
  });
}

// ── Secret management (carbon operations) ──

/** POST /api/demipass/store — store a secret */
function store({ name, value, type, secret_type, description, expires_in, ownership, rotatable, metadata, category, labels, rotation_interval_days, username } = {}) {
  if (!name || !value) throw new Error('store() requires name and value');
  const body = { name, value };
  if (type || secret_type) body.secret_type = type || secret_type;
  if (description) body.description = description;
  if (expires_in) body.expires_in = expires_in;
  if (ownership) body.ownership = ownership;
  if (rotatable !== undefined) body.rotatable = rotatable;
  if (metadata) body.metadata = metadata;
  if (category) body.category = category;
  if (labels) body.labels = labels;
  if (rotation_interval_days !== undefined) body.rotation_interval_days = rotation_interval_days;
  if (username !== undefined) body.username = username;
  return _request('POST', '/api/demipass/store', body);
}

/** POST /api/blindkey/set-username — update the account binding without rotating the value.
 *  Account binding (2026-08-24): password secrets carry the identity of the account they're for.
 *  Empty username clears the binding. Does NOT trigger rotation grace period.
 */
function setUsername({ ref, name, username } = {}) {
  if (!ref && !name) throw new Error('setUsername() requires ref or name');
  if (username === undefined || username === null) throw new Error('setUsername() requires username (empty string clears binding)');
  const body = { username };
  if (ref) body.ref = ref;
  if (name) body.name = name;
  return _request('POST', '/api/blindkey/set-username', body);
}

/** POST /api/demipass/deposit — admin deposits a secret for a target silicon */
function deposit({ name, value, targetSilicon, metadata } = {}) {
  if (!name || !value || !targetSilicon) {
    throw new Error('deposit() requires name, value, and targetSilicon');
  }
  return _request('POST', '/api/demipass/deposit', {
    name, value, target_silicon: targetSilicon, metadata,
  });
}

/** POST /api/demipass/rotate — rotate a secret with context transfer */
function rotate({ name, newValue, reason } = {}) {
  if (!name || !newValue) throw new Error('rotate() requires name and newValue');
  return _request('POST', '/api/demipass/rotate', {
    name, new_value: newValue, reason,
  });
}

/** GET /api/demipass/list — list secret names (never values) */
function list({ owner, tag } = {}) {
  return _request('GET', '/api/demipass/list', null, { owner, tag });
}

/** DELETE /api/demipass/delete — permanently retire a secret by name or ref code.
 *  Terminal state: gone from list/search, value never served again. */
function deleteSecret({ name, ref } = {}) {
  if (!name && !ref) throw new Error('deleteSecret() requires name or ref');
  return _request('DELETE', '/api/demipass/delete', { name, ref });
}

// ── Token tracking (revocation surface) ──

/** GET /api/identity/tokens — list access tokens issued to this DID */
function tokens() {
  return _request('GET', '/api/identity/tokens');
}

/** POST /api/identity/tokens/revoke — kill one issued token by jti.
 *  { all: true } hits /revoke-all instead: kills EVERY token for this DID,
 *  including the one making the call. */
function tokenRevoke({ jti, all } = {}) {
  if (all) return _request('POST', '/api/identity/tokens/revoke-all', {});
  if (!jti) throw new Error('tokenRevoke() requires jti (or all: true)');
  return _request('POST', '/api/identity/tokens/revoke', { jti });
}

// ── Context management ──

/** POST /api/demipass/context/add — add context to a secret */
function addContext({ secretName, contextName, actionType, targetHostPattern, targetUrlPattern, targetHost, targetUrl, maxUses, key, value } = {}) {
  if (!secretName) throw new Error('addContext() requires secretName');
  const body = { secret_name: secretName };
  // Support both new API shape (contextName, actionType) and legacy (key, value)
  body.context_name = contextName || key;
  body.action_type = actionType || 'http_header';
  if (!body.context_name) throw new Error('addContext() requires contextName');
  if (targetHostPattern || targetHost) body.target_host_pattern = targetHostPattern || targetHost;
  if (targetUrlPattern || targetUrl) body.target_url_pattern = targetUrlPattern || targetUrl;
  if (maxUses) body.max_uses = maxUses;
  if (value !== undefined) body.value = value;
  return _request('POST', '/api/demipass/context/add', body);
}

/** GET /api/demipass/contexts — list contexts for a secret */
function listContexts({ secretName } = {}) {
  if (!secretName) throw new Error('listContexts() requires secretName');
  return _request('GET', '/api/demipass/contexts', null, {
    secret_name: secretName,
  });
}

/** POST /api/demipass/context/request — silicon requests context, carbon approves */
function requestContext({ secretName, key, reason } = {}) {
  if (!secretName || !key) throw new Error('requestContext() requires secretName and key');
  return _request('POST', '/api/demipass/context/request', {
    secret_name: secretName, key, reason,
  });
}

// ── Use-token flow (silicon operations) ──

// The only action types the server will mint a context for. 'document' was
// advertised by the MCP tools for a long time but is implemented nowhere in
// server.js, and context/add rejects it — so a 'document' action could never
// obtain a context, and use-tokens always require one. It was unreachable by
// construction and failed with an error that named neither problem.
const VALID_ACTIONS = ['http_header', 'ssh_exec', 'http_body', 'git_clone', 'smtp_auth', 'database_connect'];

// Actions the server will mint a context and a token for, then refuse to
// redeem. Rejecting them here turns a late, confusing failure into an
// immediate, explanatory one.
const DISABLED_ACTIONS = {
  document: `'document' is not implemented anywhere in the server, and context/add rejects it as an action_type — it could never be redeemed.`,
  env_inject: `'env_inject' is deliberately DISABLED server-side as fundamentally unsafe: any command can re-encode the env var (base64, hex) to defeat literal-match redaction. The server mints a context and a token for it, then rejects redemption.`,
};

function _assertAction(action) {
  if (!action) return;
  if (DISABLED_ACTIONS[action]) {
    throw new Error(
      `${DISABLED_ACTIONS[action]} Use one of: ${VALID_ACTIONS.join(', ')}. ` +
      `To read a secret value, use a context-bound action such as http_body with a {{SECRET}} placeholder.`
    );
  }
  if (!VALID_ACTIONS.includes(action)) {
    throw new Error(
      `unknown action '${action}'. Valid actions: ${VALID_ACTIONS.join(', ')}.`
    );
  }
}

/** POST /api/demipass/request-token — get a 30s nonce for secret use */
function requestToken({ secretName, name, action, scope, context, target_host, targetHost, target_url, targetUrl, ref, owner_did, ownerDid } = {}) {
  const resolvedName = secretName || name;
  if (!resolvedName && !ref) throw new Error('requestToken() requires secretName/name or ref');
  _assertAction(action);
  const body = { action, scope };
  if (resolvedName) body.name = resolvedName;
  if (ref) body.ref = ref;
  if (context) body.context = context;
  if (target_host || targetHost) body.target_host = target_host || targetHost;
  if (target_url || targetUrl) body.target_url = target_url || targetUrl;
  if (owner_did || ownerDid) body.owner_did = owner_did || ownerDid;
  return _request('POST', '/api/demipass/request-token', body);
}

// Alias for backward compat — MCP tool calls getToken
const getToken = requestToken;

/** POST /api/demipass/use — redeem token, execute action */
function execute({ token, use_token, action, params, target_user, command, override_reason } = {}) {
  const t = token || use_token;
  if (!t) throw new Error('execute() requires token or use_token');
  // Must match use() exactly. This path (get_token -> execute) is the documented
  // two-step MCP flow, and it previously sent ONLY top-level params — so
  // http_body/git_clone/smtp_auth, which read req.body.params, saw no template
  // and silently fell back to {key: secret}. Same bug as use() had, reachable
  // through the other route. Send both shapes.
  const body = { use_token: t, ...(params || {}), params: params || {} };
  if (action) body.action = action;
  if (target_user) body.target_user = target_user;
  if (command) body.command = command;
  // Account-binding override forwarding (2026-08-24 Shadow #2 item 3).
  if (override_reason) {
    body.override_reason = override_reason;
    body.params.override_reason = override_reason;
  }
  return _request('POST', '/api/demipass/use', body);
}

// ── Delegation ──

/** POST /api/demipass/delegate — owner grants scoped access to another silicon */
function delegate({ secretName, targetSilicon, scope, ttl } = {}) {
  if (!secretName || !targetSilicon) {
    throw new Error('delegate() requires secretName and targetSilicon');
  }
  return _request('POST', '/api/demipass/delegate', {
    secret_name: secretName, target_silicon: targetSilicon, scope, ttl,
  });
}

/** POST /api/demipass/delegate/revoke — revoke a delegation */
function revoke({ secretName, targetSilicon } = {}) {
  if (!secretName || !targetSilicon) {
    throw new Error('revoke() requires secretName and targetSilicon');
  }
  return _request('POST', '/api/demipass/delegate/revoke', {
    secret_name: secretName, target_silicon: targetSilicon,
  });
}

/** GET /api/demipass/delegations — list active delegations */
function delegations({ secretName, owner } = {}) {
  return _request('GET', '/api/demipass/delegations', null, {
    secret_name: secretName, owner,
  });
}

// ── Audit ──

/** GET /api/demipass/history — audit log for a secret */
function history({ secretName, limit, offset } = {}) {
  return _request('GET', '/api/demipass/history', null, {
    secret_name: secretName, limit, offset,
  });
}

// ── Identity / onboarding ──

/** POST /api/identity/auth-fingerprint — authenticate with username + password */
function authenticate({ username, password, scope = 'transact', expiresIn = '24h' } = {}) {
  if (!username || !password) throw new Error('authenticate() requires username and password');
  return _request('POST', '/api/identity/auth-fingerprint', { username, password, scope, expires_in: expiresIn });
}

/** POST /api/identity/request-invite — request an invite key */
function requestInvite({ referralCode } = {}) {
  const body = {};
  if (referralCode) body.referral_code = referralCode;
  return _request('POST', '/api/identity/request-invite', body);
}

/** POST /api/identity/create — create account with invite key */
function createWithKey({ username, key } = {}) {
  if (!username || !key) throw new Error('createWithKey() requires username and key');
  return _request('POST', '/api/identity/create', { username, key });
}

/**
 * Full onboarding in one call:
 * 1. requestInvite (with optional referralCode)
 * 2. createWithKey (with username + key from step 1)
 * 3. authenticate (with username + key as password)
 * Returns: { did, email, token, referral_code, key }
 *
 * This replaces the old onboard() flow.
 */
async function fullOnboard({ username, referralCode } = {}) {
  if (!username) throw new Error('fullOnboard() requires username');

  // Step 1: get an invite key
  const invite = await requestInvite({ referralCode });
  const key = invite.key;

  // Step 2: create account — the key IS the password IS referral attribution
  const identity = await createWithKey({ username, key });

  // Step 3: authenticate with the key as password
  const auth = await authenticate({ username, password: key });

  return {
    did: identity.did,
    email: identity.email,
    token: auth.token,
    referral_code: identity.referral_code,
    key,
  };
}

/**
 * Get a self-executing onboarding script URL.
 * The URL contains a pre-baked invite key — share the URL and the recipient
 * runs it with: node <(curl -s 'URL')
 *
 * This does NOT overlap with fullOnboard() — it requests its own unique key
 * and returns a URL. The key is consumed when the script is executed, not when
 * the URL is generated.
 */
async function getOnboardScript({ referralCode } = {}) {
  const invite = await requestInvite({ referralCode });
  const scriptUrl = `${config.baseUrl}/api/identity/onboard?key=${invite.key}&format=script`;
  return {
    url: scriptUrl,
    key: invite.key,
    expires_at: invite.expires_at,
    usage: `node <(curl -s '${scriptUrl}') my-agent-name`,
  };
}

/**
 * @deprecated Use fullOnboard() instead — invite-key flow replaces this.
 */
async function onboard(opts) {
  return fullOnboard(opts);
}

// ── Exports ──

// ── High-level ergonomic operations ──

// Combined use: request token + execute in one call, with self-healing context recovery
async function use({ ref, name, action, owner_did, target_host, target_url, target_user, command, params, override_reason, _retried } = {}) {
  _assertAction(action);
  const tokenReq = { ref, name, action, owner_did, target_host, target_url };
  Object.keys(tokenReq).forEach(k => tokenReq[k] === undefined && delete tokenReq[k]);

  let tokenRes;
  try {
    tokenRes = await _request('POST', '/api/demipass/request-token', tokenReq);
  } catch (err) {
    // Self-healing: if context not found, try to create one and retry
    if (!_retried && err.message && err.message.includes('context') && err.message.includes('not found')) {
      const healed = await _healContext({ ref, name, action, target_host });
      if (healed.ok) {
        return use({ ref, name, action, owner_did, target_host, target_url, target_user, command, params, override_reason, _retried: true });
      }
      throw new Error(`${err.message}. Auto-heal attempted: ${healed.error || 'created context but retry needed'}`);
    }
    throw err;
  }

  if (!tokenRes.use_token) {
    // Same self-healing check for non-throwing error responses
    if (!_retried && tokenRes.error && tokenRes.error.includes('context') && tokenRes.error.includes('not found')) {
      const healed = await _healContext({ ref, name, action, target_host });
      if (healed.ok) {
        return use({ ref, name, action, owner_did, target_host, target_url, target_user, command, params, override_reason, _retried: true });
      }
    }
    throw new Error(tokenRes.error || 'failed to get use-token');
  }

  // The /use handler is inconsistent about where it reads action params:
  // ssh_exec/http_header destructure req.body directly, http_body reads
  // req.body.params. Sending both shapes keeps every action working —
  // spreading alone silently broke http_body (body_template never arrived,
  // so the server fell back to {key: secret} and targets saw no fields).
  const execReq = { use_token: tokenRes.use_token, ...(params || {}), params: params || {} };
  if (target_user) execReq.target_user = target_user;
  if (command) execReq.command = command;
  // Account-binding override forwarding (2026-08-24 Shadow #2 item 3): send both
  // top-level and inside params so the server's action_params flatten picks it up.
  if (override_reason) {
    execReq.override_reason = override_reason;
    execReq.params.override_reason = override_reason;
  }
  return _request('POST', '/api/demipass/use', execReq);
}

// Self-healing: auto-create a context when one is missing
async function _healContext({ ref, name, action, target_host } = {}) {
  // Determine secret name from ref if needed
  let secretName = name;
  if (!secretName && ref) {
    try {
      const allSecrets = await list();
      const match = (allSecrets.secrets || []).find(s => s.ref_code === ref);
      if (match) secretName = match.name;
    } catch {}
  }
  if (!secretName) return { ok: false, error: 'cannot determine secret name for context creation' };

  // Determine action type
  const actionType = action || 'ssh_exec';

  // Least-privilege: refuse to create wildcard contexts automatically.
  // Auto-healed contexts must be scoped to a specific target.
  if (!target_host) {
    return { ok: false, error: 'cannot auto-create context without a specific target_host (least-privilege)' };
  }

  // Generate a context name from the action + target
  const ctxName = `${actionType}-${target_host.replace(/[^a-zA-Z0-9.-]/g, '')}`;

  try {
    const result = await _request('POST', '/api/demipass/context/add', {
      secret_name: secretName,
      action_type: actionType,
      target_host: target_host,
      target_host_pattern: target_host,
      context_name: ctxName,
    });
    if (result.ok || result.context) {
      return { ok: true, context_name: ctxName, note: `Auto-created context "${ctxName}" for ${secretName}` };
    }
    return { ok: false, error: result.error || 'context creation failed' };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// SSH: one call with ref + host + command → output (self-healing)
// target_user default REMOVED (2026-08-24 Shadow round #2): defaulting to 'root'
// at the SDK layer silently overrode the server-side resolver, sending 'root' as
// an explicit value regardless of the secret's bound username. Now leave it
// undefined so the server resolver decides: bound → username, else hard error.
// override_reason forwarded through for bound-mismatch cases.
async function ssh({ ref, target_host, target_user, command, override_reason } = {}) {
  if (!ref || !target_host || !command) throw new Error('ref, target_host, and command required');
  return use({ ref, action: 'ssh_exec', target_host, target_user, command, override_reason });
}

// Search secrets by name pattern, type, or provider
async function search({ query, type, provider } = {}) {
  const all = await list();
  const secrets = (all.secrets || []).filter(s => {
    if (query && !s.name.toLowerCase().includes(query.toLowerCase()) &&
        !s.description?.toLowerCase().includes(query.toLowerCase()) &&
        !s.ref_code?.toLowerCase().includes(query.toLowerCase())) return false;
    if (type && s.secret_type !== type) return false;
    if (provider && s.provider !== provider) return false;
    return true;
  });
  return { secrets, total: secrets.length };
}

// List expiring secrets within N days
async function expiring({ days = 7 } = {}) {
  return _request('GET', `/api/demipass/expiring?days=${days}`);
}

// Get own trust gradient + wallet status
async function whoami() {
  // Extract DID from the bearer token (JWT sub claim) to pass to trust endpoint
  let did = '';
  if (config.bearerToken) {
    try {
      const payload = JSON.parse(Buffer.from(config.bearerToken.split('.')[1], 'base64').toString());
      did = payload.sub || '';
    } catch {}
  }
  if (did) return _request('GET', `/api/identity/trust?did=${encodeURIComponent(did)}`);
  return _request('GET', '/api/identity/trust');
}

// Get the ODT seed document
async function genesisSeed() {
  return _request('GET', '/api/identity/genesis/seed');
}

// Submit origin refraction
async function genesisSubmit({ refraction } = {}) {
  if (!refraction) throw new Error('refraction required');
  return _request('POST', '/api/identity/genesis', { refraction });
}

// Verify a refraction against origin
async function genesisVerify({ refraction } = {}) {
  if (!refraction) throw new Error('refraction required');
  return _request('POST', '/api/identity/genesis/verify', { refraction });
}

// Swap a refresh token for a fresh access token (single-use rotation server-side)
async function refreshAccess({ refreshToken, expiresIn = "24h" } = {}) {
  if (!refreshToken) throw new Error("refreshAccess() requires refreshToken");
  return _request("POST", "/api/identity/refresh", { refresh_token: refreshToken, expires_in: expiresIn });
}
async function revokeRefresh({ refreshToken } = {}) {
  if (!refreshToken) throw new Error("revokeRefresh() requires refreshToken");
  return _request("POST", "/api/identity/refresh/revoke", { refresh_token: refreshToken });
}

// Check genesis status
async function genesisStatus() {
  let did = '';
  if (config.bearerToken) {
    try { did = JSON.parse(Buffer.from(config.bearerToken.split('.')[1], 'base64').toString()).sub || ''; } catch {}
  }
  if (!did) return { error: 'no DID available' };
  return _request('GET', `/api/identity/genesis/status?did=${encodeURIComponent(did)}`);
}

// ── Doctor — agent first-contact diagnostics ──

async function doctor() {
  const report = {
    sdk_version: require('./package.json').version,
    configured: !!config.baseUrl && !!config.bearerToken,
    base_url: config.baseUrl || 'NOT SET',
    token_present: !!config.bearerToken,
    conduit_configured: !!process.env.CONDUIT_TOKEN,
  };

  // Identity
  if (config.bearerToken) {
    try {
      const payload = JSON.parse(Buffer.from(config.bearerToken.split('.')[1], 'base64').toString());
      report.identity = {
        did: payload.sub || '',
        username: payload.username || '',
        email: payload.email || '',
        scope: payload.scope || '',
        expires: payload.exp ? new Date(payload.exp * 1000).toISOString() : 'unknown',
        expired: payload.exp ? Date.now() > payload.exp * 1000 : false,
        auth_method: payload.auth_method || '',
      };
    } catch { report.identity = { error: 'could not parse token' }; }
  } else {
    report.identity = { error: 'no bearer token configured' };
  }

  // Test API connectivity
  try {
    const health = await _request('GET', '/api/health');
    report.api = { reachable: true, service: health.service, uptime: health.uptime };
  } catch (e) {
    report.api = { reachable: false, error: e.message };
  }

  // Secrets summary
  if (report.configured && !report.identity?.expired) {
    try {
      const secrets = await list();
      report.secrets = {
        total: secrets.total || (secrets.secrets || []).length,
        types: {},
      };
      for (const s of (secrets.secrets || [])) {
        report.secrets.types[s.secret_type] = (report.secrets.types[s.secret_type] || 0) + 1;
      }
    } catch (e) { report.secrets = { error: e.message }; }

    // Available contexts
    try {
      const trust = await whoami();
      report.trust = {
        band: trust.band || trust.trust_band || 'unknown',
        score: trust.score || trust.trust_score || 0,
        recovery_email: trust.recovery_email ? 'set' : 'NOT SET',
      };
    } catch (e) { report.trust = { error: e.message }; }
  }

  // Action types
  report.available_actions = ['ssh_exec', 'http_header', 'http_body', 'document', 'env_inject', 'git_clone', 'smtp_auth', 'database_connect'];

  // Recommendations
  report.recommendations = [];
  if (!report.configured) report.recommendations.push('Sign in with the device flow — demipass_login (MCP) or `npx demipass-login` (CLI) — or run demipass.configure({ baseUrl, bearerToken }) / set DEMIPASS_URL + DEMIPASS_TOKEN');
  if (report.identity?.expired) report.recommendations.push('Bearer token expired — re-authenticate via POST /api/identity/auth-fingerprint');
  if (report.trust?.recovery_email === 'NOT SET') report.recommendations.push('Set a recovery email in Settings — required for password recovery');
  if (!report.conduit_configured) report.recommendations.push('Set CONDUIT_TOKEN env var to enable agent-to-agent messaging');
  if (report.secrets?.total === 0) report.recommendations.push('No secrets stored — use demipass_store to deposit your first credential');
  // This flag gets set to true when called via MCP handler
  report.called_via_mcp = false;
  if (!report.called_via_mcp) report.recommendations.push('You are calling doctor via SDK, not MCP. If your agent session does not have demipass_* tools available, restart your session/agent with the MCP server configured in .mcp.json. MCP tools are only available when the agent is LAUNCHED with the MCP config — discovering .mcp.json after launch does not attach them.');

  return report;
}

// ── Explain denial — why was an action blocked? ──

async function explainDenial({ ref, name, action, target_host } = {}) {
  const report = { ref, name, action, target_host, checks: [] };

  // Check if secret exists
  if (ref) {
    try {
      const secrets = await list();
      const match = (secrets.secrets || []).find(s => s.ref_code === ref);
      if (match) {
        report.secret_found = true;
        report.secret_status = match.status;
        report.checks.push({ check: 'secret exists', passed: true });
        if (match.status !== 'active') report.checks.push({ check: 'secret active', passed: false, reason: `status is ${match.status}` });
      } else {
        report.secret_found = false;
        report.checks.push({ check: 'secret exists', passed: false, reason: 'ref code not found — may be revoked or wrong DID' });
      }
    } catch (e) { report.checks.push({ check: 'secret lookup', passed: false, reason: e.message }); }
  }

  // Try to request a token and capture the error
  try {
    const body = {};
    if (ref) body.ref = ref;
    if (name) body.name = name;
    if (action) body.action = action;
    if (target_host) body.target_host = target_host;
    const result = await _request('POST', '/api/demipass/request-token', body);
    if (result.use_token) {
      report.would_succeed = true;
      report.checks.push({ check: 'token issuance', passed: true, note: 'action would succeed — token issued (not consumed)' });
    }
  } catch (e) {
    report.would_succeed = false;
    const msg = e.message || '';
    if (msg.includes('context')) report.checks.push({ check: 'context', passed: false, reason: msg, fix: 'Create a context: POST /api/demipass/context/add with secret_name, action_type, target_host' });
    else if (msg.includes('suspended')) report.checks.push({ check: 'suspension', passed: false, reason: msg, fix: 'Account is suspended — contact admin' });
    else if (msg.includes('concurrent')) report.checks.push({ check: 'concurrent limit', passed: false, reason: msg, fix: 'Wait 30 seconds for existing token to expire' });
    else report.checks.push({ check: 'token request', passed: false, reason: msg });
  }

  return report;
}

// Blind rotation — server generates, applies, stores. Agent never sees new password.
async function rotateBlind({ ref, target_host, target_user, reason } = {}) {
  if (!ref || !target_host) throw new Error('ref and target_host required');
  return _request('POST', '/api/demipass/rotate-blind', { ref, target_host, target_user, reason });
}

// ── Conduit — agent-to-agent messaging ──

const CONDUIT_URL = process.env.CONDUIT_URL || 'http://100.69.1.78:8080';
const CONDUIT_TOKEN = process.env.CONDUIT_TOKEN || '';
const CONDUIT_SENDER = process.env.CONDUIT_SENDER || 'phasewhip';

function _conduit(method, path, body) {
  if (!CONDUIT_TOKEN) throw new Error('CONDUIT_TOKEN env var required for Conduit messaging');
  const url = new URL(path, CONDUIT_URL);
  const proto = url.protocol === 'https:' ? require('https') : require('http');
  const postData = body ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search, method,
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + CONDUIT_TOKEN },
      timeout: 15000,
    };
    if (postData) opts.headers['Content-Length'] = Buffer.byteLength(postData);
    const req = proto.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          try { reject(new Error(JSON.parse(data).detail || JSON.parse(data).error || `Conduit HTTP ${res.statusCode}`)); }
          catch { reject(new Error(`Conduit HTTP ${res.statusCode}: ${data.slice(0, 100)}`)); }
          return;
        }
        try { resolve(JSON.parse(data)); } catch { resolve({ raw: data, status: res.statusCode }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('conduit timeout')); });
    if (postData) req.write(postData);
    req.end();
  });
}

async function conduitSend({ to, message, thread_id } = {}) {
  if (!to || !message) throw new Error('conduitSend() requires to (agent_id) and message');

  let tid = thread_id;

  // Find or create thread
  if (!tid) {
    const threads = await _conduit('GET', '/threads');
    const existing = (Array.isArray(threads) ? threads : threads.data || []).find(t => {
      const p = t.participants || t.agents || [];
      return p.includes(to) && p.includes(CONDUIT_SENDER);
    });
    if (existing) {
      tid = existing.id || existing.thread_id;
    } else {
      try {
        const created = await _conduit('POST', '/threads', {
          participants: [CONDUIT_SENDER, to],
          label: CONDUIT_SENDER + ' <-> ' + to,
        });
        tid = created.id || created.thread_id;
      } catch (e) {
        // If permission denied, auto-file handshake and explain
        if (e.message && e.message.includes('Permission required')) {
          try {
            const hs = await _conduit('POST', '/handshakes/request', { to_agent_id: to, message: 'Requesting operational thread from ' + CONDUIT_SENDER });
            return {
              ok: false,
              handshake_pending: true,
              request_id: hs.request_id,
              note: `Handshake filed with ${to}. The target agent must approve before messaging works. They need to call POST /handshakes/approve with their token and request_id: ${hs.request_id}`,
            };
          } catch (hsErr) {
            // Handshake might already be pending
            if (hsErr.message && hsErr.message.includes('pending')) {
              return { ok: false, handshake_pending: true, note: `Handshake already pending with ${to}. Waiting for their approval.` };
            }
            throw hsErr;
          }
        }
        throw e;
      }
    }
  }

  if (!tid) throw new Error('failed to find or create thread with ' + to);

  const result = await _conduit('POST', '/messages', {
    thread_id: tid,
    body: message,
    sender_agent_id: CONDUIT_SENDER,
  });

  return { ok: true, thread_id: tid, message_id: result.id, to, delivered: true };
}

async function conduitThreads() {
  const threads = await _conduit('GET', '/threads');
  return { threads: threads.data || threads || [] };
}

async function conduitStatus() {
  return _conduit('GET', '/carbon/status');
}

// ── Device authorization (agent login without sharing a password) ──
//
// The agent asks the server for a one-time request, shows the operator a short
// code + URL, and polls. The operator approves on https://demipass.com/device
// from any device (the phone vault works). The agent then receives an access
// JWT plus a single-use refresh token, persisted locally with 0600 perms and
// kept fresh automatically. No secret transits a chat, and nothing is pasted
// into a config file by hand.

const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULT_VERIFICATION_URL = 'https://demipass.com/device';

/** Where the login credentials live. Override with DEMIPASS_CREDENTIALS. */
function credentialsPath() {
  if (process.env.DEMIPASS_CREDENTIALS) return process.env.DEMIPASS_CREDENTIALS;
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  return path.join(base, 'demipass', 'credentials.json');
}

function defaultAgentLabel() {
  const who = process.env.DEMIPASS_AGENT_LABEL || process.env.DEMIPASS_AGENT_NAME || 'demipass-sdk';
  return `${who}@${os.hostname()}`.slice(0, 80);
}

/**
 * Decode a DemiPass JWT WITHOUT verifying it (the server verifies; we only need
 * lifecycle fields). Returns null for anything that is not a JWT. Never returns
 * the token itself, so the result is safe to log.
 */
function tokenInfo(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const p = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    const exp = Number(p.exp) || 0;
    return {
      did: p.sub || '', scope: p.scope || '', jti: p.jti || '',
      email: p.email || '', username: p.username || '',
      agent_label: p.agent_label || '', auth_method: p.auth_method || '',
      issued_at: p.iat ? new Date(p.iat * 1000).toISOString() : null,
      expires_at: exp ? new Date(exp * 1000).toISOString() : null,
      seconds_remaining: exp ? exp - now : null,
      expired: exp ? exp <= now : false,
    };
  } catch { return null; }
}

/** Redacted view of a credentials record — everything except the secret values. */
function describeCredentials(rec) {
  if (!rec) return null;
  const info = tokenInfo(rec.token) || {};
  return {
    base_url: rec.base_url || null,
    did: rec.did || info.did || '',
    email: rec.email || info.email || '',
    scope: rec.scope || info.scope || '',
    agent_label: rec.agent_label || info.agent_label || '',
    auth_method: rec.auth_method || info.auth_method || '',
    token_expires_at: info.expires_at || rec.token_expires_at || null,
    token_seconds_remaining: info.seconds_remaining ?? null,
    token_expired: 'expired' in info ? info.expired : true,
    has_refresh_token: Boolean(rec.refresh_token),
    refresh_expires_at: rec.refresh_expires_at || null,
    saved_at: rec.saved_at || null,
  };
}

function loadCredentials(file = credentialsPath()) {
  try {
    const rec = JSON.parse(fs.readFileSync(file, 'utf8'));
    return rec && typeof rec === 'object' && rec.token ? rec : null;
  } catch { return null; }
}

/** Persist a token bundle (device login, auth-fingerprint, or refresh). Atomic write, 0600 file, 0700 dir. */
function saveCredentials(bundle, file = credentialsPath()) {
  if (!bundle || !bundle.token) throw new Error('saveCredentials() requires a bundle with a token');
  const info = tokenInfo(bundle.token) || {};
  const rec = {
    base_url: bundle.base_url || config.baseUrl,
    token: bundle.token,
    token_expires_at: info.expires_at || null,
    refresh_token: bundle.refresh_token || null,
    refresh_expires_at: bundle.refresh_expires_at || null,
    did: bundle.did || info.did || '',
    email: bundle.email || info.email || '',
    scope: bundle.scope || info.scope || '',
    agent_label: bundle.agent_label || info.agent_label || '',
    auth_method: bundle.auth_method || info.auth_method || '',
    saved_at: new Date().toISOString(),
  };
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(rec, null, 2) + '\n', { mode: 0o600 });
  try { fs.chmodSync(tmp, 0o600); } catch {}
  fs.renameSync(tmp, file);
  return { path: file, ...describeCredentials(rec) };
}

function clearCredentials(file = credentialsPath()) {
  try { fs.unlinkSync(file); return { path: file, removed: true }; }
  catch (e) { return { path: file, removed: false, reason: e.code === 'ENOENT' ? 'absent' : e.message }; }
}

/**
 * Pick the bearer for this process. A credentials file written by an explicit
 * login (and kept fresh by refresh) beats a static DEMIPASS_TOKEN env value —
 * the env value is the legacy hand-pasted token that goes stale. Returns where
 * the bearer came from, never the bearer itself.
 */
function loadBearerFromEnvironment({ envToken = process.env.DEMIPASS_TOKEN || '', envBaseUrl = process.env.DEMIPASS_URL || '', file = credentialsPath() } = {}) {
  const rec = loadCredentials(file);
  if (rec) {
    const info = tokenInfo(rec.token);
    const refreshAlive = Boolean(rec.refresh_token) && (!rec.refresh_expires_at || new Date(rec.refresh_expires_at).getTime() > Date.now());
    if ((info && !info.expired) || refreshAlive) {
      if (!envBaseUrl && rec.base_url) config.baseUrl = rec.base_url;
      config.bearerToken = rec.token;
      return { source: 'credentials_file', path: file, ...describeCredentials(rec) };
    }
  }
  if (envToken) {
    config.bearerToken = envToken;
    const info = tokenInfo(envToken);
    return { source: 'env', did: info?.did || '', scope: info?.scope || '', token_expires_at: info?.expires_at || null, token_expired: info ? info.expired : null };
  }
  return { source: 'none' };
}

let _refreshInFlight = null;
/**
 * Refresh the bearer when it is within `minRemainingSeconds` of expiry, using
 * the refresh token on file. Cheap to call before every request: it is a local
 * decode unless a refresh is actually due. Several processes may share one
 * file and refresh tokens are single-use, so a failed refresh re-reads the file
 * and adopts a sibling's fresher token before giving up.
 */
async function ensureFreshToken({ minRemainingSeconds = 3600, file = credentialsPath() } = {}) {
  const info = tokenInfo(config.bearerToken);
  if (info && info.seconds_remaining !== null && info.seconds_remaining > minRemainingSeconds) {
    return { refreshed: false, reason: 'fresh', token_expires_at: info.expires_at };
  }
  if (_refreshInFlight) return _refreshInFlight;
  _refreshInFlight = (async () => {
    const adopt = () => {
      const latest = loadCredentials(file);
      const li = latest && tokenInfo(latest.token);
      if (li && li.seconds_remaining > minRemainingSeconds) {
        config.bearerToken = latest.token;
        return { refreshed: false, reason: 'adopted_from_file', token_expires_at: li.expires_at };
      }
      return null;
    };
    const rec = loadCredentials(file);
    if (!rec || !rec.refresh_token) {
      return { refreshed: false, reason: info ? 'no_refresh_token' : 'no_token', token_expires_at: info ? info.expires_at : null };
    }
    if (rec.token !== config.bearerToken) { const a = adopt(); if (a) return a; }
    let r;
    try {
      r = await refreshAccess({ refreshToken: rec.refresh_token });
    } catch (e) {
      const a = adopt(); if (a) return a;
      throw new Error(`token refresh failed: ${e.message} — run demipass_login (or npx demipass-login) to sign in again`);
    }
    if (!r || !r.token) { const a = adopt(); if (a) return a; throw new Error('token refresh failed: no token returned'); }
    config.bearerToken = r.token;
    const saved = saveCredentials({ ...rec, ...r, agent_label: rec.agent_label, base_url: rec.base_url || config.baseUrl }, file);
    return { refreshed: true, token_expires_at: saved.token_expires_at, refresh_expires_at: saved.refresh_expires_at };
  })();
  try { return await _refreshInFlight; } finally { _refreshInFlight = null; }
}

/** Step 1: ask the server for a device request. Returns the user_code + URL to show the operator. */
function deviceCodeStart({ agentLabel, agent_label, scope = 'transact' } = {}) {
  const label = String(agentLabel || agent_label || defaultAgentLabel()).slice(0, 80);
  return _request('POST', '/api/identity/device/code', { agent_label: label, scope });
}

/** Step 2: poll once. Resolves {status:'pending'} or {status:'approved', ...tokens}; throws on denied / expired / invalid. */
async function deviceCodePoll({ deviceCode, device_code } = {}) {
  const dc = deviceCode || device_code;
  if (!dc) throw new Error('deviceCodePoll() requires deviceCode');
  const { status, data } = await _send('POST', '/api/identity/device/token', { device_code: dc });
  const err = data && data.error;
  if (status === 428 || err === 'authorization_pending') return { status: 'pending' };
  if (status === 429 || err === 'slow_down') return { status: 'pending', slow_down: true };
  if (status >= 400) {
    const map = {
      access_denied: 'device login denied by the operator',
      expired_token: 'device login expired before it was approved — start a new login',
      already_claimed: 'device login already redeemed — start a new login',
    };
    throw new Error(map[err] || `device login failed: ${err || `HTTP ${status}`}`);
  }
  if (!data || !data.token) throw new Error('device login failed: no token in response');
  return { status: 'approved', ...data };
}

/**
 * Whole flow: start, hand the code to `onCode`, poll until approved (or timeout),
 * then adopt + persist the tokens. Resolves a redacted description — no token values.
 */
async function deviceLogin({ agentLabel, agent_label, scope = 'transact', onCode, intervalMs, timeoutMs = 15 * 60 * 1000, persist = true, file = credentialsPath() } = {}) {
  const label = String(agentLabel || agent_label || defaultAgentLabel()).slice(0, 80);
  const start = await deviceCodeStart({ agentLabel: label, scope });
  if (!start || !start.device_code || !start.user_code) throw new Error('device login failed: server returned no device code');
  const shown = {
    user_code: start.user_code,
    verification_url: start.verification_url || DEFAULT_VERIFICATION_URL,
    verification_url_complete: start.verification_url_complete || `${DEFAULT_VERIFICATION_URL}?code=${encodeURIComponent(start.user_code)}`,
    expires_in: start.expires_in || 900,
    interval: start.interval || 5,
    scope, agent_label: label,
  };
  if (typeof onCode === 'function') await onCode(shown);
  let wait = intervalMs || shown.interval * 1000;
  const deadline = Date.now() + Math.min(timeoutMs, shown.expires_in * 1000);
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, wait));
    const p = await deviceCodePoll({ deviceCode: start.device_code });
    if (p.status === 'approved') {
      config.bearerToken = p.token;
      const bundle = { ...p, agent_label: p.agent_label || label, base_url: config.baseUrl };
      const saved = persist ? saveCredentials(bundle, file) : { path: null, ...describeCredentials(bundle) };
      return { ok: true, persisted: persist, user_code: shown.user_code, ...saved };
    }
    if (p.slow_down) wait += 5000;
  }
  throw new Error(`device login timed out — code ${shown.user_code} was not approved in time`);
}

/** Current auth state for this process. No secret values. */
function loginStatus({ file = credentialsPath() } = {}) {
  const rec = loadCredentials(file);
  const active = tokenInfo(config.bearerToken);
  return {
    base_url: config.baseUrl,
    active,
    active_source: !config.bearerToken ? 'none' : (rec && rec.token === config.bearerToken ? 'credentials_file' : 'env_or_configure'),
    credentials_file: rec ? { path: file, present: true, ...describeCredentials(rec) } : { path: file, present: false },
  };
}

/** Revoke the refresh token on file (best-effort the access token too), delete the file, drop the in-memory bearer. */
async function logout({ file = credentialsPath(), revoke = true } = {}) {
  const rec = loadCredentials(file);
  let refreshRevoked = false, accessRevoked = false;
  if (revoke && rec) {
    const info = tokenInfo(rec.token);
    if (info && info.jti && !info.expired) {
      const keep = config.bearerToken; config.bearerToken = rec.token;
      try { await tokenRevoke({ jti: info.jti }); accessRevoked = true; } catch {}
      config.bearerToken = keep;
    }
    if (rec.refresh_token) {
      try { const r = await revokeRefresh({ refreshToken: rec.refresh_token }); refreshRevoked = Boolean(r && r.revoked); } catch {}
    }
  }
  const credentials = clearCredentials(file);
  if (!rec || config.bearerToken === rec.token) config.bearerToken = '';
  return { ok: true, refresh_revoked: refreshRevoked, access_revoked: accessRevoked, credentials };
}

module.exports = {
  configure,
  // Device login + local credentials (no secret values are ever returned)
  deviceCodeStart,
  deviceCodePoll,
  deviceLogin,
  loginStatus,
  logout,
  credentialsPath,
  loadCredentials,
  saveCredentials,
  clearCredentials,
  describeCredentials,
  loadBearerFromEnvironment,
  ensureFreshToken,
  tokenInfo,
  store,
  setUsername,
  deposit,
  rotate,
  list,
  deleteSecret,
  tokens,
  tokenRevoke,
  addContext,
  listContexts,
  requestContext,
  requestToken,
  getToken,
  execute,
  delegate,
  revoke,
  delegations,
  history,
  authenticate,
  requestInvite,
  createWithKey,
  fullOnboard,
  getOnboardScript,
  onboard,
  // High-level ergonomic operations
  use,
  ssh,
  search,
  expiring,
  whoami,
  // ODT Genesis
  genesisSeed,
  genesisSubmit,
  refreshAccess,
  revokeRefresh,
  genesisVerify,
  genesisStatus,
  rotateBlind,
  // Diagnostics
  doctor,
  explainDenial,
  // Conduit
  conduitSend,
  conduitThreads,
  conduitStatus,
};
