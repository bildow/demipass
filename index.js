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

function _request(method, path, body, query) {
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
        if (res.statusCode >= 400) {
          const msg = (data && data.error) || `HTTP ${res.statusCode}`;
          return reject(new Error(`${method} ${path} failed: ${msg}`));
        }
        resolve(data);
      });
    });

    req.on('error', (err) => reject(new Error(`Network error: ${err.message}`)));
    if (payload) req.write(payload);
    req.end();
  });
}

// ── Secret management (carbon operations) ──

/** POST /api/demipass/store — store a secret */
function store({ name, value, type, secret_type, description, expires_in, ownership, rotatable, metadata, category, labels, rotation_interval_days } = {}) {
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
  return _request('POST', '/api/demipass/store', body);
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
function execute({ token, use_token, action, params, target_user, command } = {}) {
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
async function use({ ref, name, action, owner_did, target_host, target_url, target_user, command, params, _retried } = {}) {
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
        return use({ ref, name, action, owner_did, target_host, target_url, target_user, command, params, _retried: true });
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
        return use({ ref, name, action, owner_did, target_host, target_url, target_user, command, params, _retried: true });
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
async function ssh({ ref, target_host, target_user = 'root', command } = {}) {
  if (!ref || !target_host || !command) throw new Error('ref, target_host, and command required');
  return use({ ref, action: 'ssh_exec', target_host, target_user, command });
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
    conduit_configured: conduitConfig().onboarded,
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
  if (!report.configured) report.recommendations.push('Run demipass.configure({ baseUrl, bearerToken }) or set DEMIPASS_URL + DEMIPASS_TOKEN env vars');
  if (report.identity?.expired) report.recommendations.push('Bearer token expired — re-authenticate via POST /api/identity/auth-fingerprint');
  if (report.trust?.recovery_email === 'NOT SET') report.recommendations.push('Set a recovery email in Settings — required for password recovery');
  if (!report.conduit_configured) report.recommendations.push('Run conduit_onboard to join Conduit (agent relay by name, metered through DemiPass)');
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

// ── Conduit — agent-to-agent relay addressed by name (atlas/conduit v0.1) ──
//
// Every hop presents a DemiPass *service token* for the tenant `conduit` (post 2 / forward 2 / read 1 / ack 1 DD).
// The token comes from this session's own DemiPass bearer: consent to pay conduit (approved once in the app), then
// POST /api/services/token. conduitOnboard() walks that path and leaves the result in a 0600 config file that every
// call re-reads, so one onboarding serves every pane on the machine and a token that runs out is minted again
// without a restart. The file is the source of truth; CONDUIT_URL / CONDUIT_SENDER / CONDUIT_TOKEN env vars are
// fallbacks for a machine that has no file yet (a CONDUIT_TOKEN that is not a DemiPass service token for conduit —
// the pre-rebuild bearers — is ignored, with the reason reported by conduitStatus()).

const CONDUIT_DEFAULT_URL = 'http://phasewhip.taildb5a42.ts.net:8080';
const CONDUIT_RENEW_BEFORE_MS = 5 * 60 * 1000;

let conduitPane = null;
function conduitPaneAddress({ model_family, session_id } = {}) {
  if (!/^[a-z][a-z0-9]{0,14}$/.test(model_family || '') ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(session_id || ''))
    throw new Error('model_family (lowercase family) and full lowercase UUID session_id required');
  return `${model_family}-${session_id}`;
}
// A stable session role is explicit; a shared daemon's cwd or PID is never an identity.
function conduitSessionAlias(label) {
  if (typeof label !== 'string' || label.length > 160) throw new Error('session_name must be at most 160 characters');
  const alias = label.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  if (!/^[a-z][a-z0-9-]{1,79}$/.test(alias) || alias === 'conduit' || /^[a-z][a-z0-9]{0,14}-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(alias)) throw new Error('session_name needs a usable, non-reserved stable name');
  return alias;
}
// The pane identity from the environment. Claude Code exports CLAUDE_CODE_SESSION_ID (not CLAUDE_SESSION_ID). An
// incomplete or malformed identity is not thrown from every call (conduit_status "never throws"): it is reported as
// conduitPaneError and leaves explicit conduit_onboard({model_family, session_id}) free to bind (review 2026-11-12).
let conduitPaneError = null;
let conduitPaneSource = null;
// Precedence: a pane already selected in this process (explicit conduit_onboard, or an autobind once resolved) →
// CONDUIT_MODEL_FAMILY / CONDUIT_SESSION_ID (an explicit launcher binding) → CONDUIT_AUTOBIND=claude → none.
function _conduitPane() {
  if (conduitPane) return conduitPane;
  const env = _conduitEnvPane();
  if (env !== undefined) return env;
  if (process.env.CONDUIT_AUTOBIND) return _conduitAutobind();
  return null;
}
// undefined = the environment names no pane; null = it names one that is malformed (conduitPaneError says why).
function _conduitEnvPane() {
  if (!(process.env.CONDUIT_MODEL_FAMILY || process.env.CONDUIT_SESSION_ID)) return undefined;
  const p = { model_family: process.env.CONDUIT_MODEL_FAMILY,
    session_id: String(process.env.CONDUIT_SESSION_ID || process.env.CODEX_THREAD_ID || process.env.CLAUDE_CODE_SESSION_ID || process.env.CLAUDE_SESSION_ID || '').toLowerCase() };
  try { conduitPaneAddress(p); conduitPaneError = null; conduitPaneSource = 'env'; return p; }
  catch (e) { conduitPaneError = 'pane identity from the environment is incomplete or malformed (CONDUIT_MODEL_FAMILY / session id): ' + e.message; return null; }
}

// ── Pane autobind (CONDUIT_AUTOBIND=claude, set by bin/demipass-pane-mcp.js under an unbound Claude Code pane) ──
// The address is <family>-<CLAUDE_CODE_SESSION_ID>. The launcher never guesses the family: it is read here, lazily at the
// first Conduit call, from the model Claude Code recorded in this session's own transcript
// (~/.claude/projects/<slug>/<session-id>.jsonl, last non-synthetic assistant `message.model`, claude-<family>-…).
// Once resolved it is cached for the life of this MCP process: a later /model switch does not move the address.
// Only the tail of the file is read (512 KiB, widened once to at most 4 MiB when that holds no usable record), only the model string is taken, nothing from the file is logged, the path
// is built only from a validated UUID, and symlinked project directories or transcript files are refused.
const AUTOBIND_TAIL_BYTES = 512 * 1024;
const AUTOBIND_WIDE_BYTES = 4 * 1024 * 1024;   // one widened read when the tail holds no usable record
const AUTOBIND_RETRY_MS = 2000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const FAMILY_RE = /^[a-z][a-z0-9]{0,14}$/;
let _autobindMiss = { at: 0, error: null };

/** Model family recorded for a Claude Code session: {family, model, bytes_read} or {error}. Never throws. */
function _conduitClaudeFamily(sessionId, { home, maxBytes = AUTOBIND_TAIL_BYTES, maxWideBytes = AUTOBIND_WIDE_BYTES } = {}) {
  const fs = require('fs'); const path = require('path');
  const sid = String(sessionId || '');
  if (!UUID_RE.test(sid)) return { error: 'CLAUDE_CODE_SESSION_ID is missing or not a full lowercase UUID' };
  const projects = path.join(home || require('os').homedir(), '.claude', 'projects');
  let dirs;
  try { dirs = fs.readdirSync(projects, { withFileTypes: true }); } catch { return { error: 'no transcript for this session yet' }; }   // no ~/.claude/projects yet
  let best = null;
  for (const d of dirs) {
    if (!d.isDirectory()) continue;   // Dirent is lstat-based: a symlinked project directory is not a directory here
    const file = path.join(projects, d.name, sid + '.jsonl');
    let fd;
    try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | (fs.constants.O_NONBLOCK || 0)); }
    catch (e) { if (e.code === 'ELOOP') best = best || { refused: true }; continue; }
    try {
      const st = fs.fstatSync(fd);
      if (!st.isFile() || (typeof process.getuid === 'function' && st.uid !== process.getuid())) { best = best || { refused: true }; continue; }
      if (!best || best.refused || st.mtimeMs > best.mtimeMs) { if (best && best.fd !== undefined) fs.closeSync(best.fd); best = { fd, size: st.size, mtimeMs: st.mtimeMs }; fd = undefined; }
    } finally { if (fd !== undefined) fs.closeSync(fd); }
  }
  if (!best) return { error: 'no transcript for this session yet' };
  if (best.refused) return { error: 'transcript refused (symlink, not a regular file, or not owned by this user)' };
  // Scan one tail window backwards for the last complete, usable assistant record.
  const scan = (want) => {
    const len = Math.min(best.size, want);
    const start = best.size - len;
    const buf = Buffer.alloc(len);
    let got = 0;
    while (got < len) { const n = fs.readSync(best.fd, buf, got, len - got, start + got); if (!n) break; got += n; }
    let text = buf.toString('utf8', 0, got);
    if (start > 0) { const nl = text.indexOf('\n'); text = nl < 0 ? '' : text.slice(nl + 1); }   // drop the cut first line
    const lines = text.split('\n');
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i];
      if (!line.includes('"assistant"') || !line.includes('"model"')) continue;
      let rec; try { rec = JSON.parse(line); } catch { continue; }
      if (!rec || rec.type !== 'assistant' || rec.isSidechain === true || !rec.message || typeof rec.message.model !== 'string') continue;
      const m = /^claude-([a-z][a-z0-9]*)(?:-|$)/.exec(rec.message.model);
      if (!m || !FAMILY_RE.test(m[1])) continue;   // '<synthetic>' and old/unrecognised model ids are skipped (fail closed)
      return { family: m[1], model: rec.message.model.slice(0, 64), bytes_read: got };
    }
    return { error: 'no model recorded for this session', bytes_read: got };
  };
  try {
    const r = scan(maxBytes);
    // Nothing usable in the tail (e.g. the newest assistant line is itself longer than the tail and was cut): widen
    // once, capped, so the newest complete record is found. Anything older than the cap fails closed.
    if (r.family || best.size <= maxBytes || maxWideBytes <= maxBytes) return r;
    return scan(maxWideBytes);
  } catch { return { error: 'transcript unreadable' }; }
  finally { try { fs.closeSync(best.fd); } catch {} }
}

function _conduitAutobind() {
  const mode = process.env.CONDUIT_AUTOBIND;
  if (mode !== 'claude') {
    conduitPaneError = `CONDUIT_AUTOBIND=${String(mode).slice(0, 16)} is not supported (only claude); call conduit_onboard with model_family and session_id`;
    return null;
  }
  if (_autobindMiss.error && Date.now() - _autobindMiss.at < AUTOBIND_RETRY_MS) { conduitPaneError = _autobindMiss.error; return null; }
  const sid = String(process.env.CLAUDE_CODE_SESSION_ID || '');
  const r = _conduitClaudeFamily(sid);
  if (r.family) {
    conduitPane = { model_family: r.family, session_id: sid };
    conduitPaneSource = 'autobind'; conduitPaneError = null; _autobindMiss = { at: 0, error: null };
    return conduitPane;
  }
  const why = r.error === 'no transcript for this session yet' || r.error === 'no model recorded for this session'
    ? 'no model recorded for this session' : r.error;
  conduitPaneError = `pane identity not resolvable yet: ${why} (CONDUIT_AUTOBIND=claude); retry after this session's first reply, or call conduit_onboard with model_family and session_id`;
  _autobindMiss = { at: Date.now(), error: conduitPaneError };
  return null;
}
// CONDUIT_SESSION_NAME names this pane's stable role only when the launcher set it from an explicit pane binding, which
// it marks with CONDUIT_SESSION_NAME_SOURCE=binding (#23 review): a variable merely inherited from a shell or another
// pane does nothing. An autobound pane ignores it either way; its role handover must be an explicit conduit_onboard.
function _conduitEnvSessionName() {
  if (process.env.CONDUIT_SESSION_NAME_SOURCE !== 'binding') return null;
  const pane = _conduitPane();
  return pane && conduitPaneSource !== 'autobind' ? (process.env.CONDUIT_SESSION_NAME || null) : null;
}
function _conduitSharedFile() {
  return process.env.CONDUIT_CONFIG || require('path').join(require('os').homedir(), '.config', 'demipass', 'conduit.json');
}
function _conduitConfigFile() {
  const p = _conduitPane();
  return p ? require('path').join(require('path').dirname(_conduitSharedFile()), 'conduit-panes', conduitPaneAddress(p) + '.json') : _conduitSharedFile();
}
function _conduitLoad(file) {
  try {
    const value = JSON.parse(require('fs').readFileSync(file, 'utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid Conduit config');
    return value;
  } catch (e) { if (e.code === 'ENOENT') return null; throw new Error('Conduit config unreadable or malformed: ' + file); }
}
function _conduitReadFile() {
  const pane = _conduitPane();
  const own = _conduitLoad(_conduitConfigFile());
  if (!pane) return own;
  if (own && own.name && own.name !== conduitPaneAddress(pane)) throw new Error('pane config address mismatch');
  const shared = _conduitLoad(_conduitSharedFile()) || {};
  const inherited = {};
  // Same payer/consent, separate routing addresses. Never inherit another pane's name or ownership.
  for (const k of ['token', 'token_id', 'expires_at', 'cap_dd', 'ttl', 'consent_id', 'daily_cap_dd', 'wallet', 'url', 'minted_at'])
    if (shared[k] !== undefined) inherited[k] = shared[k];
  return { ...inherited, ...(own || {}) };
}
function _conduitWriteFile(cfg) {
  const fs = require('fs'); const path = require('path'); const file = _conduitConfigFile();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
  try { fs.chmodSync(file, 0o600); } catch {}
  return file;
}
function _jwtClaims(token) {
  try { return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url').toString('utf8')); } catch { return null; }
}
function _isConduitServiceToken(token) {
  const c = _jwtClaims(token);
  return !!(c && c.aud === 'svc:conduit');
}

/** The effective Conduit settings: file first, env fallbacks second. Never throws. */
function conduitConfig() {
  const f = _conduitReadFile() || {};
  const envTok = process.env.CONDUIT_TOKEN || '';
  const envTokOk = envTok ? _isConduitServiceToken(envTok) : false;
  const token = f.token || (envTokOk ? envTok : '');
  const claims = token ? _jwtClaims(token) : null;
  const expiresAt = f.expires_at || (claims && claims.exp ? new Date(claims.exp * 1000).toISOString() : null);
  const cfg = {
    file: _conduitConfigFile(),
    file_present: require('fs').existsSync(_conduitConfigFile()),
    url: String(f.url || process.env.CONDUIT_URL || CONDUIT_DEFAULT_URL).replace(/\/+$/, ''),
    name: _conduitPane() ? (f.name || '') : (f.name || process.env.CONDUIT_SENDER || ''),
    session_name: f.session_name || null, stable_address: f.stable_address || null,
    token,
    token_id: f.token_id || (claims && claims.jti) || null,
    expires_at: expiresAt,
    cap_dd: f.cap_dd || (claims && claims.cap_dd) || null,
    ttl: f.ttl || '24h',
    consent_id: f.consent_id || null,
    daily_cap_dd: f.daily_cap_dd || null,
    wallet: f.wallet || (claims && claims.sub) || null,
    owns: Array.isArray(f.owns) ? f.owns : [],
    minted_at: f.minted_at || null,
  };
  cfg.token_valid = !!token && (!expiresAt || Date.parse(expiresAt) - Date.now() > CONDUIT_RENEW_BEFORE_MS);
  cfg.onboarded = !!(cfg.name && cfg.token);
  cfg.pane_address = _conduitPane() ? conduitPaneAddress(_conduitPane()) : null;
  if (cfg.pane_address) cfg.pane_source = conduitPaneSource;
  else if (conduitPaneError) cfg.pane_error = conduitPaneError;
  if (process.env.CONDUIT_REQUIRE_PANE === '1' && !cfg.pane_address) { cfg.onboarded = false; cfg.name = ''; cfg.pane_required = true; }
  if (envTok && !envTokOk && !f.token) cfg.env_token_ignored = 'CONDUIT_TOKEN is not a DemiPass service token for conduit (aud svc:conduit); run conduit_onboard';
  return cfg;
}

// Relay address resolution: conduit.json url → CONDUIT_URL → the tenant registry's `endpoint` (GET /api/services/conduit,
// set by the tenant owner under app approval; dustforge #87) → the built-in default. A relay move then takes one
// approval and no client edits. The registry answer is cached for an hour and never persisted into the file.
// The cache belongs to the registry that answered: configure({ baseUrl }) to another DemiPass asks that one (#18 review P2).
let _registryCache = { at: 0, endpoint: null, base: null };
async function _conduitRegistryEndpoint() {
  const base = config.baseUrl || 'https://api.dustforge.com';
  if (_registryCache.base === base && Date.now() - _registryCache.at < 3600000) return _registryCache.endpoint;
  // Only an answer is cached (an endpoint, or "none set"); a failed lookup (timeout, 5xx) is not, so the next call asks
  // again instead of using the default for an hour (#18 review round 2).
  let d;
  // Relative to the base (not "/api/..."), so a DemiPass hosted under a path keeps it (#18 review round 3).
  try { d = await _conduitHttp('GET', 'api/services/conduit', null, null, String(base).replace(/\/+$/, '')); }
  catch { return null; }
  const endpoint = d && d.endpoint ? String(d.endpoint).replace(/\/+$/, '') : null;
  _registryCache = { at: Date.now(), endpoint, base };
  return endpoint;
}
async function _conduitResolveUrl() {
  const f = _conduitReadFile() || {};
  if (f.url) return { url: String(f.url).replace(/\/+$/, ''), source: 'config_file' };
  if (process.env.CONDUIT_URL) return { url: String(process.env.CONDUIT_URL).replace(/\/+$/, ''), source: 'env' };
  const reg = await _conduitRegistryEndpoint();
  if (reg) return { url: reg, source: 'registry' };
  return { url: CONDUIT_DEFAULT_URL, source: 'default' };
}

function _conduitServices() {
  if (!config.bearerToken) throw new Error('DEMIPASS_TOKEN is not set: Conduit tokens are minted from this session\'s DemiPass identity');
  return require('./services').services({ token: config.bearerToken, baseUrl: config.baseUrl });
}

/** Mint a fresh service token for conduit from this session's DemiPass bearer and persist it. */
async function _conduitMint({ ttl, capDd } = {}) {
  const f = _conduitReadFile() || {};
  const cfg = conduitConfig();
  let r;
  try {
    r = await _conduitServices().mintToken({ service: 'conduit', ttl: ttl || cfg.ttl || '24h', capDd: capDd || cfg.cap_dd || undefined });
  } catch (e) {
    if (e && e.status === 403 && e.body && e.body.consent_required) {
      const err = new Error('this wallet has no standing consent to pay conduit; run conduit_onboard (it files the consent for approval in the DemiPass app)');
      err.status = 403; err.body = e.body; throw err;
    }
    if (e && e.status === 400 && e.body && /cap_dd/.test(e.body.error || '')) {
      // the stored cap is above the (new) consent cap: let the server pick its default
      r = await _conduitServices().mintToken({ service: 'conduit', ttl: ttl || cfg.ttl || '24h' });
    } else throw e;
  }
  const next = { ...f, token: r.token, token_id: r.token_id, expires_at: r.expires_at, cap_dd: r.cap_dd, ttl: ttl || cfg.ttl || '24h',
    wallet: (_jwtClaims(r.token) || {}).sub || f.wallet || null, minted_at: new Date().toISOString() };
  if (cfg.name) next.name = cfg.name;
  _conduitWriteFile(next);
  return next;
}

// A cached service token is this session's only if it was minted for the same wallet: another identity on the same
// machine must not message (and be charged) as the previous one (#16 review P1).
function _conduitTokenIsMine(token) {
  if (!config.bearerToken) return true;   // nothing to mint from: the configured token is all there is
  const me = (_jwtClaims(config.bearerToken) || {}).sub, owner = (_jwtClaims(token) || {}).sub;
  return !!me && !!owner && me === owner;
}
async function _conduitToken({ force } = {}) {
  const cfg = conduitConfig();
  if (!force && cfg.token_valid && _conduitTokenIsMine(cfg.token)) return cfg.token;
  return (await _conduitMint()).token;
}

function _conduitHttp(method, path, body, token, baseUrl) {
  const url = new URL(path, (baseUrl || conduitConfig().url) + '/');
  const proto = url.protocol === 'https:' ? https : http;
  const postData = body ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search, method,
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json', 'X-DemiPass-Agent': AGENT_HEADER },
      timeout: 15000,
    };
    if (token) opts.headers['Authorization'] = 'Bearer ' + token;
    if (_conduitPane()) opts.headers['X-Conduit-Address'] = conduitPaneAddress(_conduitPane());
    if (postData) opts.headers['Content-Length'] = Buffer.byteLength(postData);
    const req = proto.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        let parsed; try { parsed = data ? JSON.parse(data) : {}; } catch { parsed = { raw: data.slice(0, 300) }; }
        if (res.statusCode >= 400) {
          const err = new Error(`Conduit ${method} ${url.pathname} → ${res.statusCode} ${parsed.error || parsed.detail || parsed.raw || ''}`.trim());
          err.status = res.statusCode; err.body = parsed; return reject(err);
        }
        resolve(parsed);
      });
    });
    req.on('error', (e) => { const err = new Error(`Conduit unreachable at ${url.origin}: ${e.message}`); err.status = 0; reject(err); });
    req.on('timeout', () => { req.destroy(); const err = new Error('Conduit timeout'); err.status = 0; reject(err); });
    if (postData) req.write(postData);
    req.end();
  });
}

/** Authenticated Conduit call. A token that has run out is minted again (once) from the DemiPass bearer. */
let conduitAutoOnboarding = null;
async function _conduit(method, path, body, { noAutoOnboard = false } = {}) {
  // A pane identity that is configured but malformed never falls back to the shared legacy address (Codex #19 P2).
  if (!_conduitPane() && conduitPaneError) throw new Error(conduitPaneError + ' — refusing to message as the shared legacy address; fix the identity or call conduit_onboard with model_family and session_id');
  if (process.env.CONDUIT_REQUIRE_PANE === '1' && !_conduitPane()) throw new Error('Pane identity required: call conduit_onboard with model_family and full session_id before messaging (panes with no automatic address, e.g. Codex, always need this)');
  // Existing clients with a verified launcher identity/name migrate on first use. Never auto-reclaim a rotated role.
  // An autobound pane never takes a role from the environment (it may be inherited from another pane): roles for those
  // are taken only by an explicit conduit_onboard({session_name}).
  if (!noAutoOnboard && _conduitPane() && _conduitEnvSessionName() && !conduitConfig().stable_address && !_conduitRoleReleased(_conduitEnvSessionName())) {
    if (!conduitAutoOnboarding) conduitAutoOnboarding = conduitOnboard({}, { automatic: true }).finally(() => { conduitAutoOnboarding = null; });
    const ready = await conduitAutoOnboarding;
    if (!ready.ok) throw new Error('Conduit session onboarding required: ' + (ready.error || ready.status || ready.step));
  }
  const { url } = await _conduitResolveUrl();
  let token = await _conduitToken();
  const call = async () => {
    try { return await _conduitHttp(method, path, body, token, url); }
    catch (e) {
      if (e.status === 401 && config.bearerToken) {
        token = await _conduitToken({ force: true });
        return _conduitHttp(method, path, body, token, url);
      }
      throw e;
    }
  };
  try { return await call(); }
  catch (e) {
    // 410 address_retired on a call made AS this pane. Only an idle-expiry retirement (retired_by "expiry") is undone:
    // the pane re-registers its own address once (same model_family/session_id, previous owns; only the owning wallet
    // can) and retries the original call once; a second 410 is returned as is. A retirement by the owner, or one an
    // older relay does not label, is deliberate: never revived here (#20 review M1).
    // 410 session_rotated: a successor took this pane's stable role over (POST /addresses/bind). Final for this
    // session: no re-register, no re-onboarding, no retry (the relay refuses a rotated session's register anyway).
    if (_conduitErrCode(e) === 'address_retired' && _conduitPane()) {
      if (e.body.retired_by !== 'expiry') throw _conduitRetiredError(e, body);
      await _conduitRevive(token, url);
      try { return await call(); } catch (e2) { throw _conduitRetiredError(e2, body); }
    }
    throw _conduitRetiredError(e, body);
  }
}
function _conduitErrCode(e) { return e && e.status === 410 && e.body && typeof e.body.error === 'string' ? e.body.error : null; }
// A 410 said plainly, worded from the relay's retired_by; the relay's body stays on err.body. Other errors pass through.
function _conduitRetiredError(e, body) {
  const code = _conduitErrCode(e);
  if (code === 'session_rotated') return _conduitRotatedError(e);
  if (code !== 'recipient_retired' && code !== 'address_retired') return e;
  const by = e.body.retired_by;
  const how = by === 'expiry' ? 'retired after 7 days idle' : by === 'owner' ? 'retired by its owner' : 'retired (the relay did not say why)';
  const when = ` (retired_at ${e.body.retired_at || 'unknown'})`;
  const alias = typeof e.body.stable_address === 'string' ? e.body.stable_address : null;
  let msg;
  if (code === 'recipient_retired') {
    const to = e.body.to || (body && body.to) || 'the recipient';
    // The relay refuses the post and stores nothing: nothing waits anywhere (#23 review).
    msg = alias
      ? `Conduit: not delivered — "${to}", the current pane of stable address "${alias}", was ${how}${when}; the relay stored nothing. Send again after a successor binds "${alias}" or the pane returns.`
      : `Conduit: not delivered — "${to}" was ${how}${when}; the relay stored nothing. Send again after the pane returns (only its own pane can bring it back), or find a live address with conduit_agents.`;
  } else {
    const name = e.body.name || (_conduitPane() ? conduitPaneAddress(_conduitPane()) : 'this address');
    msg = by === 'expiry'
      ? `Conduit: this pane address ${name} was ${how}${when} and is still retired after re-registering once; not retrying`
      : `Conduit: this pane address ${name} was ${how}${when}; it is not revived automatically. Re-onboard deliberately with conduit_onboard (same model_family and session_id) if this pane should use it again.`;
  }
  const err = new Error(msg);
  err.status = 410; err.code = code; err.retired_by = by || null; err.stable_address = alias; err.body = e.body; err.cause = e;
  return err;
}
// POST /addresses/bind refusals, said plainly. Unknown codes (a newer relay) keep the relay's code and detail.
function _conduitBindError(e, alias) {
  const b = (e && e.body) || {}; const code = typeof b.error === 'string' ? b.error : null;
  const a = `"${alias}"`;
  const known = {
    bad_session_name: `session_name is not usable as a stable address${b.detail ? ': ' + b.detail : ''}`,
    invalid_handover_target: `this pane's address cannot hold ${a} (not registered to this wallet as a pane, or retired)`,
    stable_address_conflicts_with_agent: `${a} is (or normalizes to) a registered agent name; choose another session_name`,
    stable_address_taken: `${a} belongs to another wallet, or this pane already holds a different stable address`,
    handover_conflict: `${a} changed hands while onboarding (current: ${b.current === undefined ? 'unknown' : b.current}); not retried: check conduit_agents and onboard again if this pane should take it over`,
    too_many_stable_addresses: `this wallet holds the maximum number of stable addresses${b.max ? ` (${b.max})` : ''}; release one before binding ${a}`,
    session_rotated: 'this session was rotated and cannot take a stable address',
    stable_address_reserved: `${a} was recently unbound by another wallet and stays reserved to it${b.reserved_until ? ` until ${b.reserved_until}` : ''}`,
    unknown_stable_address: `${a} is not a stable address`,
    not_owner: `${a} belongs to another wallet`,
  };
  const message = 'Conduit stable address: ' + (known[code] || `${a} refused (${code || e.status || 'error'})${b.detail ? ': ' + b.detail : ''}; ${e.message}`);
  return { code: code || null, message, current: b.current };
}
function _conduitRotatedError(e) {
  const b = (e && e.body) || {};
  const me = _conduitPane() ? conduitPaneAddress(_conduitPane()) : 'this address';
  const err = new Error(`Conduit: this session was rotated: ${me} was handed over${b.stable_address ? ` (stable address "${b.stable_address}")` : ''}${b.replacement ? ` to ${b.replacement}` : ''}. A rotated session cannot send, re-register or reclaim the role; it is not revived. Continue in the successor session, or onboard this one under a different session_name.`);
  err.status = 410; err.code = 'session_rotated'; err.replacement = b.replacement || null; err.stable_address = b.stable_address || null; err.body = b; err.cause = e;
  return err;
}
async function _conduitRevive(token, url) {
  const pane = _conduitPane();
  const address = conduitPaneAddress(pane);
  const f = _conduitReadFile() || {};
  let reg;
  try {
    // owns omitted: the relay keeps the subjects on record for a revive (sending the config's copy could clear them).
    reg = await _conduitHttp('POST', '/agents/register', { name: address, ...pane, description: f.description || undefined }, token, url);
  } catch (e) {
    if (_conduitErrCode(e) === 'session_rotated') throw _conduitRotatedError(e);
    const err = new Error(`Conduit: this pane's address ${address} was retired after 7 days idle and re-registering it failed: ${e.message}`);
    err.status = e.status; err.code = 'address_retired'; err.body = e.body; throw err;
  }
  if (!reg || reg.name !== address) throw new Error(`Conduit: re-registering retired address ${address} returned a different name; not retrying`);
  try { _conduitWriteFile({ ...f, name: reg.name, owns: Array.isArray(reg.owns) ? reg.owns : (f.owns || []), revived_at: new Date().toISOString() }); } catch {}
  return reg;
}

/**
 * Join Conduit through the normal DemiPass path and leave a working config behind:
 *   1. GET /health (is the relay up)       2. standing consent to pay conduit (filed for app approval if missing)
 *   3. service token (minted; reused while valid)   4. POST /agents/register {name, owns}   5. GET /agents (is it there)
 * A missing consent returns {status:'approval_pending', approval_id}: approve it in the DemiPass app, then call again
 * with approval_id. Idempotent otherwise: run it any time to confirm or repair the setup.
 */
async function conduitOnboard({ name, model_family, session_id, session_name, owns, description, daily_cap_dd, cap_dd, ttl, approval_id, url, renew } = {}, { automatic = false } = {}) {
  if (model_family !== undefined || session_id !== undefined) {
    const proposed = { model_family, session_id };
    conduitPaneAddress(proposed);
    // An explicit identity outranks autobind: only a pane already in use by this process (or set by the launcher's
    // explicit binding) blocks it. A pending autobind is not consulted, so a transcript is never read here.
    const env = _conduitEnvPane();
    const current = conduitPane || env;
    if (current && conduitPaneAddress(current) !== conduitPaneAddress(proposed)) throw new Error('this MCP process is bound to another pane; use a separate process');
    if (!conduitPane) conduitPaneSource = env ? 'env' : 'onboard';
    conduitPane = proposed; conduitPaneError = null;
  }
  const pane = _conduitPane();
  if (process.env.CONDUIT_REQUIRE_PANE === '1' && !pane) return { ok: false, step: 'pane_identity', error: 'model_family and full session_id required; shared legacy name is not a pane identity', ...(conduitPaneError ? { pane_error: conduitPaneError } : {}) };
  if (pane && name && name !== conduitPaneAddress(pane)) throw new Error('name must match model-family-session-id');
  const steps = [];
  const fs = require('fs');
  const prior = _conduitReadFile() || {};
  const stableLabel = session_name !== undefined ? session_name : (prior.session_name || _conduitEnvSessionName() || undefined);
  let stableAlias = null;
  if (stableLabel !== undefined && stableLabel !== null) {
    if (!pane) return { ok:false, step:'stable_address', error:'session_name requires a model_family and session_id', ...(conduitPaneError ? { pane_error: conduitPaneError } : {}) };
    try { stableAlias = conduitSessionAlias(stableLabel); }
    catch (e) { return { ok:false, step:'stable_address', error:e.message }; }
    if (prior.stable_address && prior.stable_address !== stableAlias)
      return { ok:false, step:'stable_address', error:'this session already has a different stable address; start a separate session for a different role' };
  }
  const resolved = url ? { url: String(url).replace(/\/+$/, ''), source: 'argument' } : await _conduitResolveUrl();
  const baseUrl = resolved.url;
  // The URL is saved only with a working setup (step 5): a mistyped one never replaces the relay every pane uses (#16 review P2).

  // 1. relay up?
  let health;
  try { health = await _conduitHttp('GET', '/health', null, null, baseUrl); }
  catch (e) { return { ok: false, step: 'health', url: baseUrl, error: e.message }; }
  steps.push({ step: 'health', ok: true, url_source: resolved.source, version: health.version, agents: health.agents, prices_dd: health.prices_dd });

  // 2. identity
  if (!config.bearerToken) return { ok: false, step: 'identity', error: 'DEMIPASS_TOKEN is not set; Conduit tokens are minted from this session\'s DemiPass identity', steps };
  const me = _jwtClaims(config.bearerToken) || {};
  const wantName = String((pane && conduitPaneAddress(pane)) || name || prior.name || process.env.CONDUIT_SENDER || me.username || '').trim();
  if (!wantName) return { ok: false, step: 'name', error: 'name required (no CONDUIT_SENDER, no username in the DemiPass token)', steps };
  const dp = _conduitServices();

  // 3. consent (services.ensureConsent: the same helper every caller-side onboarding uses)
  let consent = null;
  const cap = Number.isInteger(daily_cap_dd) ? daily_cap_dd : 300;
  try {
    const c = await dp.ensureConsent({ service: 'conduit', dailyCapDd: cap, approvalId: approval_id });
    if (c.pending) {
      return { ok: false, status: 'approval_pending', step: 'consent', approval_id: c.pending.approval_id, expires_at: c.pending.expires_at,
        daily_cap_dd: cap, wallet: me.sub || null, steps,
        next: `Approve "let a wallet pay conduit" (${cap} DD/day) in the DemiPass app, then call conduit_onboard again with approval_id=${c.pending.approval_id} and the same name/owns${url ? '/url' : ''}.` };
    }
    consent = c.consent;
    steps.push({ step: 'consent', ok: true, consent_id: consent.id, daily_cap_dd: consent.daily_cap_dd, existing: c.existing, approval_id: c.existing ? undefined : (approval_id || null) });
  } catch (e) {
    return { ok: false, step: 'consent', status: e.status, error: (e.body && e.body.error) || e.message, steps,
      hint: e.status === 403 ? 'an identity no fleet created has no person to consent for it: use a person session or a fleet-created silicon' : undefined };
  }

  // 4. token
  let cfg = conduitConfig();
  let minted = false;
  // A token only in CONDUIT_TOKEN (not in the shared file) is minted into the file, so every pane's later calls have it
  // (#16 review round 2).
  const fileHasToken = !!(_conduitReadFile() || {}).token;
  if (renew || !fileHasToken || !cfg.token_valid || !_conduitTokenIsMine(cfg.token) || (cap_dd && cap_dd !== cfg.cap_dd) || (ttl && ttl !== cfg.ttl)) {
    try { await _conduitMint({ ttl, capDd: cap_dd }); minted = true; }
    catch (e) { return { ok: false, step: 'token', status: e.status, error: (e.body && e.body.error) || e.message, steps }; }
  }
  cfg = conduitConfig();
  steps.push({ step: 'token', ok: true, minted, token_id: cfg.token_id, expires_at: cfg.expires_at, cap_dd: cfg.cap_dd });

  // 5. register (one name per wallet; a wallet that already has a name keeps it)
  let reg; let finalName = wantName;
  // A cached token Conduit rejects (revoked before its expiry) is minted again once, as _conduit() does (#16 review round 2).
  const withToken = async (fn) => {
    try { return await fn(cfg.token); }
    catch (e) {
      if (e.status !== 401 || !config.bearerToken) throw e;
      await _conduitMint({ ttl, capDd: cap_dd }); minted = true; cfg = conduitConfig();
      return fn(cfg.token);
    }
  };
  const register = async (n, o) => withToken((t) => _conduitHttp('POST', '/agents/register', { name: n, ...(pane || {}), owns: o, description: description || prior.description || undefined }, t, baseUrl));
  const ownsFor = async (n) => {
    if (Array.isArray(owns)) return owns;
    // Through withToken: a revoked cached token is minted again here too, so the directory answer (not a stale fallback)
    // decides what this name owns (#16 review, after merge). Only a lookup that still fails falls back.
    // A successor registers with its OWN subjects only; the role's subjects move to it with the handover (relay 25fa1db
    // POST /addresses/bind moves owns), so two live panes never claim them at once (#23 review).
    try { const dir = await withToken((t) => _conduitHttp('GET', '/agents', null, t, baseUrl)); const mine = (dir.agents || dir || []).find(a => a.name === n); if (mine) return mine.owns || []; } catch {}
    return prior.owns || [];
  };
  const listing = async () => { const d = await withToken(t => _conduitHttp('GET', '/agents', null, t, baseUrl)); return d.agents || d || []; };
  // The automatic first-call onboarding must not undo a deliberate retirement: registering a retired name revives it.
  // GET /history (unchargeable) as this pane says which: 410 address_retired with retired_by. Only an idle-expiry
  // retirement may be revived here; one by the owner needs an explicit conduit_onboard (Codex #23 P2).
  let revivingExpired = false;
  if (automatic && pane) {
    try { await withToken(t => _conduitHttp('GET', '/history?limit=1', null, t, baseUrl)); }
    catch (e) {
      // An expiry-retired pane is revived by registering it WITHOUT owns: the relay then keeps the subjects it has on
      // record (/agents hides retired panes, so a local or empty list would overwrite them: Codex #23 P2).
      if (_conduitErrCode(e) === 'address_retired' && e.body.retired_by === 'expiry' && !Array.isArray(owns)) revivingExpired = true;
      else if (_conduitErrCode(e) === 'address_retired') {
        const r = _conduitRetiredError(e, null);
        return { ok: false, step: 'register', status: 410, code: 'address_retired', retired_by: e.body.retired_by || null, error: r.message, steps };
      }
      if (pane && _conduitErrCode(e) === 'session_rotated') { const r = _conduitRotatedError(e); return { ok: false, step: 'register', status: 410, code: 'session_rotated', error: r.message, replacement: r.replacement, requested: wantName, steps }; }
      // 409 register_first (a new pane) and anything else: go on to register, which reports real failures itself.
    }
  }
  try { reg = await register(wantName, revivingExpired ? undefined : await ownsFor(wantName)); }
  catch (e) {
    if (pane && _conduitErrCode(e) === 'session_rotated') { const r = _conduitRotatedError(e); return { ok: false, step: 'register', status: 410, code: 'session_rotated', error: r.message, replacement: r.replacement, requested: wantName, steps }; }
    if (pane) return { ok: false, step: 'register', status: e.status, error: e.message, requested: wantName, steps };
    if (e.status === 409 && e.body && e.body.error === 'wallet_has_name' && e.body.name) {
      finalName = e.body.name;
      steps.push({ step: 'register', note: `this wallet is already "${finalName}" on Conduit (one name per wallet); keeping it`, requested: wantName });
      try { reg = await register(finalName, await ownsFor(finalName)); } catch (e2) { return { ok: false, step: 'register', status: e2.status, error: e2.message, steps }; }
    } else if (e.status === 409 && e.body && e.body.error === 'name_taken') {
      return { ok: false, step: 'register', status: 409, error: `name "${wantName}" belongs to another wallet; choose another`, steps };
    } else return { ok: false, step: 'register', status: e.status, error: e.message, steps };
  }
  if (pane && reg.name !== wantName) return { ok: false, step: 'register', error: 'relay returned a different address', steps };
  steps.push({ step: 'register', ok: true, name: reg.name, owns: reg.owns, via: reg.via });
  let route = null;
  if (stableAlias) {
    try {
      const active = (await listing()).find(a => a.route && a.route.alias === stableAlias);
      // A role whose session_name was not passed to THIS call (the automatic first-call onboarding from a launcher
      // binding, or a conduit_onboard() re-using an env/recorded role) is bound only when it is unbound, already this
      // pane's, or held by a retired pane. Taking it from a LIVE pane cuts that pane off for good, so it needs an explicit
      // conduit_onboard({session_name}) (#23 review). Checked after register, so a rotated session still gets its 410.
      if ((automatic || session_name === undefined) && active && active.route.current !== reg.name) {
        return { ok:false, step:'stable_address', code:'stable_address_held', holder: active.route.current, name: reg.name, steps,
          error: `stable address "${stableAlias}" is held by the live pane ${active.route.current}; ${automatic ? 'automatic onboarding' : 'onboarding without an explicit session_name'} never takes a role from a live pane. To hand it over to this pane deliberately (that pane is then cut off), run conduit_onboard({session_name: ${JSON.stringify(String(stableLabel).trim())}})` };
      }
      const bind = (expected) => withToken(t => _conduitHttp('POST', '/addresses/bind', { session_name: stableLabel.trim(), address: reg.name, expected_current: expected }, t, baseUrl));
      // One optimistic handoff only. A concurrent successor wins or loses explicitly; never retry a stale CAS.
      // Single exception: the directory hides retired panes, so a role whose current pane was retired looks unbound
      // (expected_current null → handover_conflict naming it). The relay documents binding a successor over the retired
      // pane; that is retried once, and only if the named holder is still absent from the live directory.
      let result;
      try { result = await bind(active ? active.route.current : null); }
      catch (e) {
        const held = e.status === 409 && e.body && e.body.error === 'handover_conflict' && !active && typeof e.body.current === 'string' ? e.body.current : null;
        if (!held || (await listing()).some(a => a.name === held)) throw e;
        result = await bind(held);
        steps.push({ step: 'stable_address_takeover', from_retired: held });
      }
      if (!result.ok || !result.route || result.route.current !== reg.name || result.route.alias !== stableAlias)
        throw new Error('relay did not confirm the requested stable address');
      route = result.route;
      if (Array.isArray(result.owns)) reg = { ...reg, owns: result.owns };   // the relay moved the role's subjects here
      else if (active && active.name !== reg.name && Array.isArray(active.owns) && active.owns.length && !Array.isArray(owns)) {
        // An older relay (before 25fa1db) does not move subjects on handover: carry them over after the bind instead.
        reg = await register(reg.name, [...new Set([...(reg.owns || []), ...active.owns])]);
        steps.push({ step: 'owns_carried', owns: reg.owns });
      }
      steps.push({ step:'stable_address', ok:true, route });
    } catch (e) { const b = _conduitBindError(e, stableAlias); return { ok:false, step:'stable_address', status:e.status, code:b.code, error:b.message, ...(b.current !== undefined ? { current:b.current } : {}), name:reg.name, steps }; }
  }
  _conduitWriteFile({ ...(_conduitReadFile() || {}), ...(route ? { session_name:route.session_name, stable_address:route.alias, stable_address_released: undefined } : {}), ...(url ? { url: baseUrl } : {}), name: reg.name, owns: reg.owns, description: reg.description || '', consent_id: consent.id, daily_cap_dd: consent.daily_cap_dd, wallet: me.sub || cfg.wallet || null, onboarded_at: prior.onboarded_at || new Date().toISOString() });

  // 6. directory check
  let listed = false;
  try { const dir = await _conduitHttp('GET', '/agents', null, cfg.token, baseUrl); listed = !!(dir.agents || dir || []).find(a => a.name === reg.name); } catch {}
  steps.push({ step: 'directory', ok: listed });

  const final = conduitConfig();
  const mode = fs.statSync(final.file).mode & 0o777;
  return { ok: listed, ...(route ? { stable_address:route.alias, session_name:route.session_name, route } : {}), url: baseUrl, url_source: resolved.source, name: reg.name, owns: reg.owns, wallet: final.wallet, consent: { id: consent.id, daily_cap_dd: consent.daily_cap_dd },
    token: { token_id: final.token_id, expires_at: final.expires_at, cap_dd: final.cap_dd, minted }, config_file: final.file, config_mode: mode.toString(8), steps,
    note: 'Every conduit_* call re-reads this file and mints a new token from the DemiPass session when this one runs out; no restart needed. Panes started before this file existed keep working through it too.' };
}

/** Post a message by registered name (2 DD). `subject` owned by another agent is forwarded to its owner with a notice back. */
async function conduitSend({ to, thread, subject, body, message, client_msg_id } = {}) {
  const text = body || message;
  if (!text) throw new Error('conduitSend() requires body');
  if (!to && !thread) throw new Error('conduitSend() requires to (a registered name; see conduitAgents) or thread');
  // Every send carries an idempotency key: a retry with the same client_msg_id is one message and one charge. One is
  // made when the caller gave none, and it is named in any error, so the caller can retry with it.
  const cid = client_msg_id || ('cm_' + require('crypto').randomBytes(12).toString('hex'));
  const payload = { body: text, client_msg_id: cid };
  if (to) payload.to = to; if (thread) payload.thread = thread; if (subject) payload.subject = subject;
  let r;
  try { r = await _conduit('POST', '/messages', payload); }
  catch (e) { e.message = `${e.message} (to retry without sending twice, call again with client_msg_id "${cid}")`; e.client_msg_id = cid; throw e; }
  return { ok: true, client_msg_id: cid, ...r };
}
// Opt-in, local endpoint operations. Ordinary onboarding neither generates keys nor activates release.
function conduitSealedClient() {
  if(process.env.DEMIPASS_SEALED_ENABLE!=='1')throw new Error('sealed messaging is opt-in; set DEMIPASS_SEALED_ENABLE=1 in the endpoint launcher');
  const cfg=conduitConfig();
  return new (require('./sealed/client').Client)({mailbox:cfg.stable_address || cfg.name,directory:process.env.DEMIPASS_SEALED_DIRECTORY});
}
async function conduitSealedIdentity(){return conduitSealedClient().initialize();}
async function conduitSealedPrepare(args){
  if(args.policy || args.fixture)throw new Error('MCP guardian enrollment/release is disabled until independent custodians are selected');
  return conduitSealedClient().prepare(args);
}
async function conduitSealedSend({id}){
  const payload=conduitSealedClient().transport(id);
  // Refuse an older relay that would silently ignore payload_type and forward ciphertext as ordinary text.
  const card=await _conduit('GET','/readme?format=json');
  if(!Array.isArray(card.payload_types)||!card.payload_types.includes(payload.payload_type))throw new Error('relay lacks sealed transport capability; no message sent');
  return _conduit('POST','/messages',payload);
}
async function conduitSealedOpen(args){return {plaintext:await conduitSealedClient().open(args)};}
async function conduitSealedCapsule({id}){return {capsule:conduitSealedClient().capsule(id),note:'Recipient-encrypted capsule; publish later through your separately selected channel. It is not a plaintext key.'};}
/** Pending and recent messages for this name. Costs 1 DD only when it turns ≥1 message from delivered to read. */
async function conduitInbox({ since, limit, include_acked } = {}) {
  const q = new URLSearchParams();
  if (since !== undefined) q.set('since', String(since)); if (limit) q.set('limit', String(limit)); if (include_acked) q.set('include_acked', '1');
  const s = q.toString();
  return _conduit('GET', '/inbox' + (s ? `?${s}` : ''));
}
async function conduitAck({ msg_id } = {}) { if (!msg_id) throw new Error('msg_id required'); return _conduit('POST', `/messages/${encodeURIComponent(msg_id)}/ack`, {}); }
async function conduitHistory({ since = 0, limit = 100 } = {}) {
  return _conduit('GET', `/history?since=${encodeURIComponent(since)}&limit=${encodeURIComponent(limit)}`);
}
async function conduitReceipts({ since = 0, limit = 100 } = {}) {
  return _conduit('GET', `/receipts?since=${encodeURIComponent(since)}&limit=${encodeURIComponent(limit)}`);
}
async function conduitReceipt({ msg_id } = {}) { if (!msg_id) throw new Error('msg_id required'); return _conduit('GET', `/messages/${encodeURIComponent(msg_id)}`); }
async function conduitForward({ msg_id, to, note } = {}) { if (!msg_id || !to) throw new Error('msg_id and to required'); return _conduit('POST', `/messages/${encodeURIComponent(msg_id)}/forward`, { to, note }); }
async function conduitAgents() { const r = await _conduit('GET', '/agents'); return { agents: r.agents || r }; }
/** Legacy thread view (kept for lori_checkin and the old clients). */
async function conduitThreads() { const threads = await _conduit('GET', '/threads'); return { threads: threads.data || threads.threads || threads || [] }; }
function _conduitRoleReleased(label) {
  let alias; try { alias = conduitSessionAlias(label); } catch { return false; }
  return (_conduitReadFile() || {}).stable_address_released === alias;
}
/**
 * Unbind a stable session name of this wallet (DELETE /addresses/:name, relay 25fa1db). The name is freed (reserved to
 * this wallet for 7 days) and its mailbox chain dissolved: each pane keeps the mail addressed to it. If it was this
 * pane's role, the pane config forgets it, and a launcher binding's session_name is not re-bound automatically by this
 * pane again (an explicit conduit_onboard({session_name}) still can).
 */
async function conduitUnbind({ session_name } = {}) {
  const label = session_name !== undefined ? session_name : (_conduitReadFile() || {}).session_name;
  if (typeof label !== 'string' || !label.trim()) throw new Error('session_name required (none recorded for this pane)');
  const alias = conduitSessionAlias(label);
  let r;
  try { r = await _conduit('DELETE', '/addresses/' + encodeURIComponent(alias), null, { noAutoOnboard: true }); }
  catch (e) {
    if (!e.body || typeof e.body.error !== 'string' || e.code) throw e;
    const b = _conduitBindError(e, alias); const err = new Error(b.message.replace('Conduit stable address:', 'Conduit unbind:'));
    err.status = e.status; err.code = b.code; err.body = e.body; throw err;
  }
  const f = _conduitReadFile() || {};
  // Also when this pane has not saved its role yet but the launcher's binding names it: otherwise the next ordinary call
  // would onboard automatically and bind the role just released (Codex #23 P2).
  let envAlias = null; try { envAlias = _conduitEnvSessionName() ? conduitSessionAlias(_conduitEnvSessionName()) : null; } catch {}
  if (_conduitPane() && (f.stable_address === alias || envAlias === alias)) {
    const { session_name: _s, stable_address: _a, ...rest } = f;
    _conduitWriteFile({ ...rest, stable_address_released: alias });
  }
  return { ok: true, unbound: r.unbound || alias, current: r.current || null, addresses: r.addresses || [] };
}

/** Relay health plus this machine's onboarding state. Never throws on a missing token. */
async function conduitStatus() {
  const cfg = conduitConfig();
  const resolved = await _conduitResolveUrl();
  const out = { url: resolved.url, url_source: resolved.source, me: { onboarded: cfg.onboarded, name: cfg.name || null, session_name:cfg.session_name, stable_address:cfg.stable_address, wallet: cfg.wallet, token_id: cfg.token_id, token_expires_at: cfg.expires_at,
    token_valid: cfg.token_valid, cap_dd: cfg.cap_dd, consent_id: cfg.consent_id, daily_cap_dd: cfg.daily_cap_dd, config_file: cfg.file, config_present: cfg.file_present } };
  if (cfg.env_token_ignored) out.me.env_token_ignored = cfg.env_token_ignored;
  if (cfg.pane_address) { out.me.pane_address = cfg.pane_address; out.me.pane_source = cfg.pane_source; }
  if (cfg.pane_error) out.me.pane_error = cfg.pane_error;
  try { out.health = await _conduitHttp('GET', '/health', null, null, resolved.url); } catch (e) { out.health = { ok: false, error: e.message }; }
  if (!cfg.onboarded) out.next = 'run conduit_onboard';
  else if (out.health && out.health.ok) { try { out.agents = (await conduitAgents()).agents; } catch (e) { out.agents_error = e.message; } }
  return out;
}

module.exports = {
  configure,
  store,
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
  // Service tenants (identity + metering for agent services; docs/services.md)
  services: require('./services').services,
  ServiceError: require('./services').ServiceError,
  verifyServiceReceipt: require('./services').verifyReceipt,
  // Conduit (agent relay by name; docs/conduit.md)
  conduitPaneAddress,
  _conduitClaudeFamily,
  conduitHistory,
  conduitReceipts,
  conduitConfig,
  _conduitRegistryReset: () => { _registryCache = { at: 0, endpoint: null, base: null }; },
  conduitOnboard,
  conduitUnbind,
  conduitSend,
  conduitSealedIdentity,
  conduitSealedPrepare,
  conduitSealedSend,
  conduitSealedOpen,
  conduitSealedCapsule,
  conduitInbox,
  conduitAck,
  conduitReceipt,
  conduitForward,
  conduitAgents,
  conduitThreads,
  conduitStatus,
};
