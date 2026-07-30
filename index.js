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
const VALID_ACTIONS = ['http_header', 'ssh_exec', 'http_body', 'env_inject', 'git_clone', 'smtp_auth', 'database_connect'];

function _assertAction(action) {
  if (action && !VALID_ACTIONS.includes(action)) {
    throw new Error(
      `unknown action '${action}'. Valid actions: ${VALID_ACTIONS.join(', ')}. ` +
      `('document' is not implemented — to read a secret value use a context-bound ` +
      `action such as http_body with a {{SECRET}} placeholder.)`
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
  const body = { use_token: t };
  if (action) body.action = action;
  if (params) Object.assign(body, params);
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
  if (!report.configured) report.recommendations.push('Run demipass.configure({ baseUrl, bearerToken }) or set DEMIPASS_URL + DEMIPASS_TOKEN env vars');
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
  // Conduit
  conduitSend,
  conduitThreads,
  conduitStatus,
};
