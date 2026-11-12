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
function _conduitPane() {
  if (conduitPane) return conduitPane;
  if (process.env.CONDUIT_MODEL_FAMILY || process.env.CONDUIT_SESSION_ID) {
    const p = { model_family: process.env.CONDUIT_MODEL_FAMILY,
      session_id: process.env.CONDUIT_SESSION_ID || process.env.CODEX_THREAD_ID || process.env.CLAUDE_SESSION_ID };
    conduitPaneAddress(p); return p;
  }
  return null;
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
async function _conduit(method, path, body) {
  const { url } = await _conduitResolveUrl();
  let token = await _conduitToken();
  try { return await _conduitHttp(method, path, body, token, url); }
  catch (e) {
    if (e.status === 401 && config.bearerToken) {
      token = await _conduitToken({ force: true });
      return _conduitHttp(method, path, body, token, url);
    }
    throw e;
  }
}

/**
 * Join Conduit through the normal DemiPass path and leave a working config behind:
 *   1. GET /health (is the relay up)       2. standing consent to pay conduit (filed for app approval if missing)
 *   3. service token (minted; reused while valid)   4. POST /agents/register {name, owns}   5. GET /agents (is it there)
 * A missing consent returns {status:'approval_pending', approval_id}: approve it in the DemiPass app, then call again
 * with approval_id. Idempotent otherwise: run it any time to confirm or repair the setup.
 */
async function conduitOnboard({ name, model_family, session_id, owns, description, daily_cap_dd, cap_dd, ttl, approval_id, url, renew } = {}) {
  if (model_family !== undefined || session_id !== undefined) {
    const proposed = { model_family, session_id };
    conduitPaneAddress(proposed);
    const current = _conduitPane();
    if (current && conduitPaneAddress(current) !== conduitPaneAddress(proposed)) throw new Error('this MCP process is bound to another pane; use a separate process');
    conduitPane = proposed;
  }
  const pane = _conduitPane();
  if (pane && name && name !== conduitPaneAddress(pane)) throw new Error('name must match model-family-session-id');
  const steps = [];
  const fs = require('fs');
  const prior = _conduitReadFile() || {};
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
    try { const dir = await withToken((t) => _conduitHttp('GET', '/agents', null, t, baseUrl)); const mine = (dir.agents || dir || []).find(a => a.name === n); if (mine) return mine.owns || []; } catch {}
    return prior.owns || [];
  };
  try { reg = await register(wantName, await ownsFor(wantName)); }
  catch (e) {
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
  _conduitWriteFile({ ...(_conduitReadFile() || {}), ...(url ? { url: baseUrl } : {}), name: reg.name, owns: reg.owns, description: reg.description || '', consent_id: consent.id, daily_cap_dd: consent.daily_cap_dd, wallet: me.sub || cfg.wallet || null, onboarded_at: prior.onboarded_at || new Date().toISOString() });

  // 6. directory check
  let listed = false;
  try { const dir = await _conduitHttp('GET', '/agents', null, cfg.token, baseUrl); listed = !!(dir.agents || dir || []).find(a => a.name === reg.name); } catch {}
  steps.push({ step: 'directory', ok: listed });

  const final = conduitConfig();
  const mode = fs.statSync(final.file).mode & 0o777;
  return { ok: listed, url: baseUrl, url_source: resolved.source, name: reg.name, owns: reg.owns, wallet: final.wallet, consent: { id: consent.id, daily_cap_dd: consent.daily_cap_dd },
    token: { token_id: final.token_id, expires_at: final.expires_at, cap_dd: final.cap_dd, minted }, config_file: final.file, config_mode: mode.toString(8), steps,
    note: 'Every conduit_* call re-reads this file and mints a new token from the DemiPass session when this one runs out; no restart needed. Panes started before this file existed keep working through it too.' };
}

/** Post a message by registered name (2 DD). `subject` owned by another agent is forwarded to its owner with a notice back. */
async function conduitSend({ to, thread, subject, body, message, client_msg_id } = {}) {
  const text = body || message;
  if (!text) throw new Error('conduitSend() requires body');
  if (!to && !thread) throw new Error('conduitSend() requires to (a registered name; see conduitAgents) or thread');
  const payload = { body: text };
  if (to) payload.to = to; if (thread) payload.thread = thread; if (subject) payload.subject = subject; if (client_msg_id) payload.client_msg_id = client_msg_id;
  const r = await _conduit('POST', '/messages', payload);
  return { ok: true, ...r };
}
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
/** Relay health plus this machine's onboarding state. Never throws on a missing token. */
async function conduitStatus() {
  const cfg = conduitConfig();
  const resolved = await _conduitResolveUrl();
  const out = { url: resolved.url, url_source: resolved.source, me: { onboarded: cfg.onboarded, name: cfg.name || null, wallet: cfg.wallet, token_id: cfg.token_id, token_expires_at: cfg.expires_at,
    token_valid: cfg.token_valid, cap_dd: cfg.cap_dd, consent_id: cfg.consent_id, daily_cap_dd: cfg.daily_cap_dd, config_file: cfg.file, config_present: cfg.file_present } };
  if (cfg.env_token_ignored) out.me.env_token_ignored = cfg.env_token_ignored;
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
  conduitHistory,
  conduitReceipts,
  conduitConfig,
  _conduitRegistryReset: () => { _registryCache = { at: 0, endpoint: null, base: null }; },
  conduitOnboard,
  conduitSend,
  conduitInbox,
  conduitAck,
  conduitReceipt,
  conduitForward,
  conduitAgents,
  conduitThreads,
  conduitStatus,
};
