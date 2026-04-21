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
function store({ name, value, metadata } = {}) {
  if (!name || !value) throw new Error('store() requires name and value');
  return _request('POST', '/api/demipass/store', { name, value, metadata });
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

// ── Context management ──

/** POST /api/demipass/context/add — add context to a secret */
function addContext({ secretName, key, value } = {}) {
  if (!secretName || !key) throw new Error('addContext() requires secretName and key');
  return _request('POST', '/api/demipass/context/add', {
    secret_name: secretName, key, value,
  });
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

/** POST /api/demipass/request-token — get a 30s nonce for secret use */
function requestToken({ secretName, action, scope } = {}) {
  if (!secretName) throw new Error('requestToken() requires secretName');
  return _request('POST', '/api/demipass/request-token', {
    secret_name: secretName, action, scope,
  });
}

/** POST /api/demipass/use — redeem token, execute action */
function execute({ token, action, params } = {}) {
  if (!token) throw new Error('execute() requires token');
  return _request('POST', '/api/demipass/use', { token, action, params });
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
async function use({ ref, name, action, owner_did, target_host, target_user, command, params, _retried } = {}) {
  const tokenReq = { ref, name, action, owner_did, target_host };
  Object.keys(tokenReq).forEach(k => tokenReq[k] === undefined && delete tokenReq[k]);

  let tokenRes;
  try {
    tokenRes = await _request('POST', '/api/demipass/request-token', tokenReq);
  } catch (err) {
    // Self-healing: if context not found, try to create one and retry
    if (!_retried && err.message && err.message.includes('context') && err.message.includes('not found')) {
      const healed = await _healContext({ ref, name, action, target_host });
      if (healed.ok) {
        return use({ ref, name, action, owner_did, target_host, target_user, command, params, _retried: true });
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
        return use({ ref, name, action, owner_did, target_host, target_user, command, params, _retried: true });
      }
    }
    throw new Error(tokenRes.error || 'failed to get use-token');
  }

  const execReq = { use_token: tokenRes.use_token, ...params };
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

  // Generate a context name from the action + target
  const ctxName = target_host
    ? `${actionType}-${target_host.replace(/[^a-zA-Z0-9.-]/g, '')}`
    : `${actionType}-default`;

  try {
    const result = await _request('POST', '/api/demipass/context/add', {
      secret_name: secretName,
      action_type: actionType,
      target_host: target_host || '*',
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
  const identity = await _request('GET', '/api/identity/trust');
  return identity;
}

module.exports = {
  configure,
  store,
  deposit,
  rotate,
  list,
  addContext,
  listContexts,
  requestContext,
  requestToken,
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
};
