#!/usr/bin/env node
/**
 * DemiPass MCP Server
 *
 * Exposes DemiPass tools over the Model Context Protocol (JSON-RPC over stdin/stdout).
 * Claude Code launches this process and communicates via the MCP transport.
 *
 * Usage:
 *   node mcp-server.js
 *
 * Configuration (env or .env):
 *   DEMIPASS_URL         — API base URL
 *   DEMIPASS_TOKEN       — static bearer token (legacy; a device-login credentials file wins when present)
 *   DEMIPASS_CREDENTIALS — path of the device-login credentials file (default ~/.config/demipass/credentials.json)
 *
 * Authentication: run the demipass_login tool (device flow — operator approves on
 * https://demipass.com/device, phone included). Tokens land in the credentials file
 * with 0600 perms and are refreshed automatically before they expire.
 */

try { require('dotenv').config(); } catch {}

const demipass = require('./index.js');
const os = require('os');

// Configure SDK with env vars
demipass.configure({
  baseUrl: process.env.DEMIPASS_URL || 'https://api.dustforge.com',
  adminKey: process.env.DEMIPASS_ADMIN_KEY || '',
});
// Bearer: a live device-login credentials file beats the static DEMIPASS_TOKEN env value.
const BEARER_SOURCE = demipass.loadBearerFromEnvironment();
// Refresh in the background at startup if the token is near expiry (never blocks, never throws).
demipass.ensureFreshToken().catch(() => {});
// Tools that establish or inspect auth must not trigger a refresh first.
const NO_REFRESH_TOOLS = new Set(['demipass_login', 'demipass_login_wait', 'demipass_login_status', 'demipass_logout', 'demipass_onboard', 'demipass_refresh', 'demipass_refresh_revoke']);
// user_code -> in-flight device login (device_code stays in this process; the model only ever sees the user_code)
const PENDING_LOGINS = new Map();

// ---------------------------------------------------------------------------
// Tool definitions — each entry becomes a tool Claude Code can invoke
// ---------------------------------------------------------------------------

const TOOLS = [
  {
    name: 'demipass_store',
    description: 'INGRESS: When you encounter a credential (API key, password, token, SSH key) — from the user, from a config file, from an API response — deposit it here immediately. Do NOT save it in memory, files, or scripts. The value is encrypted at rest and never returned by any API. You will receive a ref code (e.g. DP-API-openrout-7f3a9c1e) — save ONLY the ref code. The secret itself should leave your context as soon as this call returns.',
    inputSchema: {
      type: 'object',
      properties: {
        name:        { type: 'string', description: 'Descriptive name: {scope}-{service} (e.g. shared-openrouter, brain-matrix, flimflam-sudo)' },
        value:       { type: 'string', description: 'The secret value — will be encrypted and never returned' },
        type:        { type: 'string', description: 'Secret type: api_key, password, token, ssh_key, cert, other', default: 'other' },
        description: { type: 'string', description: 'What this secret is for' },
        expires_in:  { type: 'string', description: 'Optional expiration: 30d, 90d, etc. Auto-detected for known providers (GitHub=90d, npm=30d)' },
        ownership:   { type: 'string', description: 'Ownership model: "sole" (you own the target, rotation OK), "shared" (shared credential, rotation blocked unless all parties agree), "delegated" (delegated to you, cannot rotate source). Default: sole' },
        rotatable:   { type: 'boolean', description: 'Whether blind rotation is allowed for this secret. Default: true. Set false for shared credentials.' },
        category:    { type: 'string', description: 'Organizational group (lowercase-dashes): infrastructure, platform, agents, services, products, personal, evidence, test, other. Used for vault grouping — set it instead of encoding the group in the name.' },
        labels:      { type: 'array', items: { type: 'string' }, description: 'Up to 10 free-form tags for filtering (e.g. ["prod","kyle-shared"]).' },
        rotation_interval_days: { type: 'integer', description: 'Rotation cadence in days (1–3650). Drives rotation-due / overdue telemetry and the daily reminder digest. Set this even for non-expiring credentials you want to rotate on a schedule.' },
        username:    { type: 'string', description: 'Account / login this credential is for (e.g. "flimflam", "root"). REQUIRED for password / ssh_key secrets that will be used via ssh_exec — without it, an omitted target_user is a hard error. SSH-safe grammar: letters, digits, and . _ - only. For email-authenticated services (IMAP, web logins), leave empty and put the address in description.' },
      },
      required: ['name', 'value'],
    },
  },
  {
    name: 'demipass_set_username',
    description: 'Update the account binding on an existing secret without rotating its value. Use to backfill legacy secrets that don\'t yet carry a username, or to correct a typo. Empty string clears the binding. Idempotent. Does NOT trigger rotation grace period — the secret value is untouched. Emits a username_changed audit event.',
    inputSchema: {
      type: 'object',
      properties: {
        ref:      { type: 'string', description: 'Routed reference code (e.g. DP-PWD-flimflam-e542b0b9). Preferred.' },
        name:     { type: 'string', description: 'Secret name (alternative to ref).' },
        username: { type: 'string', description: 'The account this credential targets. SSH-safe grammar: letters, digits, and . _ - only. Empty string clears the binding.' },
      },
      required: ['username'],
    },
  },
  {
    name: 'demipass_get_token',
    description: 'EGRESS step 1: Request a 30-second use-token for a stored secret. Use the ref code if you have one (preferred), or name + context. The token is a single-use nonce — not the secret itself. You must redeem it within 30 seconds via demipass_execute.',
    inputSchema: {
      type: 'object',
      properties: {
        ref:     { type: 'string', description: 'Routed reference code (e.g. DP-API-openrout-7f3a9c1e). Preferred — auto-resolves owner, delegation, context, action.' },
        name:    { type: 'string', description: 'Secret name (use ref instead when possible)' },
        context: { type: 'string', description: 'Context name for the use-token' },
        action:  { type: 'string', description: 'Action type. Contexts accept: http_header, ssh_exec, http_body, env_inject, git_clone, smtp_auth, database_connect. NOTE: "document" is NOT a valid context action_type — context/add rejects it. For http_body pass params.body_template with a {{SECRET}} placeholder.' },
        owner_did: { type: 'string', description: 'Owner DID (only needed if using name without ref for delegated secrets)' },
        target_host: { type: 'string', description: 'Target host for SSH exec actions' },
        target_url: { type: 'string', description: 'Target URL for HTTP header/body and database actions' },
      },
    },
  },
  {
    name: 'demipass_execute',
    description: 'EGRESS step 2: Redeem a use-token. The secret is injected server-side — into an HTTP header, a POST body, an SSH command, a git clone URL, or an SMTP auth exchange. You receive the result (API response, command output) but never the secret itself. The token is burned after one use.',
    inputSchema: {
      type: 'object',
      properties: {
        token:  { type: 'string', description: 'Use-token from demipass_get_token (valid 30 seconds)' },
        action: { type: 'string', description: 'Optional action override (normally derived from the token). Contexts accept: http_header, ssh_exec, http_body, env_inject, git_clone, smtp_auth, database_connect.' },
        target_user: { type: 'string', description: 'For ssh_exec: SSH user. Resolution order server-side: this explicit value → secret.username → context.target_user_default → HARD ERROR. No silent default.' },
        command: { type: 'string', description: 'For ssh_exec: command to run.' },
        override_reason: { type: 'string', description: 'Required when target_user differs from the secret\'s bound username. ≤128 chars. Logged to blindkey_events as ssh_exec_account_override.' },
        params: { type: 'object', description: 'Action params. For http_body pass {method, body_template} where body_template contains a {{SECRET}} placeholder. Fields are sent both nested and top-level for server compatibility.' },
      },
      required: ['token'],
    },
  },
  {
    name: 'demipass_list',
    description: 'List all secrets in the vault. Returns names, types, ref codes, providers, and expiration dates — never values. Use this to find a ref code you need, or to check what is expiring soon.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'demipass_delete',
    description: 'Permanently retire a secret by name or ref code. Terminal state: it disappears from list/search and its value is never served again. Use for cleanup of test artifacts, dead credentials, and superseded generations. For a compromised-but-still-needed credential, prefer demipass_rotate.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Name of the secret to delete' },
        ref:  { type: 'string', description: 'Ref code of the secret to delete (alternative to name)' },
      },
    },
  },
  {
    name: 'demipass_tokens',
    description: 'List access tokens issued to your DID — the revocation surface. Every token minted since 2026-07-06 carries a jti and appears here with scope, issue/expiry times, and revoked state. Use to audit what can currently act as you.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'demipass_token_revoke',
    description: 'Revoke an issued access token by jti — it dies immediately on every endpoint. Pass all=true to revoke ALL tokens for your DID, INCLUDING the one making this call (you will need to re-auth via 2FA afterward). This is the kill switch for leaked or over-scoped tokens.',
    inputSchema: {
      type: 'object',
      properties: {
        jti: { type: 'string', description: 'jti of the token to revoke (from demipass_tokens)' },
        all: { type: 'boolean', description: 'Revoke every token for this DID, including the caller\'s' },
      },
    },
  },
  {
    name: 'demipass_rotate',
    description: 'Rotate a secret to a new value. The old value enters a grace period, then is permanently destroyed. All contexts and delegations transfer to the new version automatically. Use when a credential is compromised or expired.',
    inputSchema: {
      type: 'object',
      properties: {
        name:      { type: 'string', description: 'Name of the secret to rotate' },
        new_value: { type: 'string', description: 'The replacement secret value' },
      },
      required: ['name', 'new_value'],
    },
  },
  {
    name: 'demipass_onboard',
    description: 'Self-onboard to the Dustforge identity platform. Creates a cryptographic identity (DID:key), email address, and wallet. The invite key serves as your initial password and referral attribution. Call this once — subsequent sessions authenticate with demipass_get_token.',
    inputSchema: {
      type: 'object',
      properties: {
        username:      { type: 'string', description: 'Desired username (3-31 chars, lowercase alphanumeric)' },
        referral_code: { type: 'string', description: 'Optional referral code from another silicon' },
      },
      required: ['username'],
    },
  },
  {
    name: 'demipass_use',
    description: 'EGRESS (one-step): Request a use-token AND redeem it in a single call. Self-healing: if the context is missing, it auto-creates one and retries. You should never see "context not found" — the tool handles it.',
    inputSchema: {
      type: 'object',
      properties: {
        ref:         { type: 'string', description: 'Routed reference code (e.g. DP-API-openrout-7f3a9c1e). Preferred.' },
        name:        { type: 'string', description: 'Secret name (if not using ref)' },
        action:      { type: 'string', description: 'Action type. Contexts accept: http_header, ssh_exec, http_body, env_inject, git_clone, smtp_auth, database_connect. NOTE: "document" is NOT a valid context action_type — context/add rejects it. For http_body pass params.body_template with a {{SECRET}} placeholder.' },
        owner_did:   { type: 'string', description: 'Owner DID (only for delegated access without ref)' },
        target_host: { type: 'string', description: 'Target host (required for SSH)' },
        target_url:  { type: 'string', description: 'Target URL for HTTP header/body and database actions' },
        target_user: { type: 'string', description: 'SSH user. Resolution order: this explicit value, then the secret\'s bound username, then the context\'s target_user_default, then HARD ERROR. There is no silent default.' },
        command:     { type: 'string', description: 'Command to execute (for SSH)' },
        override_reason: { type: 'string', description: 'Required when target_user differs from the secret\'s bound username. ≤128 chars. Logged to blindkey_events as ssh_exec_account_override.' },
        params:      { type: 'object', description: 'Additional action-specific parameters. Fields are sent both nested and top-level for server compatibility.' },
      },
    },
  },
  {
    name: 'demipass_ssh',
    description: 'SSH into a host using a DemiPass ref code. One call: ref + host + command → output. The password is injected server-side. You never see it. Self-healing: if no SSH context exists for this secret, one is auto-created. This is the primary way to access remote machines.',
    inputSchema: {
      type: 'object',
      properties: {
        ref:         { type: 'string', description: 'Ref code for the SSH password (e.g. DP-PWD-sharedra-b08a108a)' },
        target_host: { type: 'string', description: 'IP or hostname to SSH into' },
        target_user: { type: 'string', description: 'SSH username. Resolution order: this explicit value, then the secret\'s bound username, then the context\'s target_user_default, then HARD ERROR. There is no silent default. Omit only when the secret is account-bound.' },
        command:     { type: 'string', description: 'Command to run on the remote host' },
        override_reason: { type: 'string', description: 'Required when target_user differs from the secret\'s bound username. ≤128 chars. Logged to blindkey_events.' },
      },
      required: ['ref', 'target_host', 'command'],
    },
  },
  {
    name: 'demipass_search',
    description: 'Search secrets by name, type, or provider. Returns matching secrets with ref codes. Use when you need to find a specific ref code from the vault.',
    inputSchema: {
      type: 'object',
      properties: {
        query:    { type: 'string', description: 'Search text — matches name, description, or ref code' },
        type:     { type: 'string', description: 'Filter by secret_type: api_key, password, token, ssh_key, cert, other' },
        provider: { type: 'string', description: 'Filter by provider: openrouter, github, npm, stripe, etc.' },
      },
    },
  },
  {
    name: 'demipass_expiring',
    description: 'List secrets expiring within N days. Use for proactive rotation planning. Returns secrets approaching expiration and already-expired secrets.',
    inputSchema: {
      type: 'object',
      properties: {
        days: { type: 'number', description: 'Window in days (default: 7, max: 90)' },
      },
    },
  },
  {
    name: 'demipass_login',
    description: 'AUTH (device flow, no password): start a login for this agent. Returns a short user_code and a URL — show BOTH to the operator verbatim and ask them to open the URL (phone is fine) and approve. Then call demipass_login_wait. Nothing secret is returned or needs pasting anywhere: on approval the access + refresh tokens are written to a 0600 credentials file and this running server adopts them immediately. Use when DemiPass calls return 401/expired, when no DEMIPASS_TOKEN is configured, or to bind this session to the operator\'s identity.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_label: { type: 'string', description: 'Shown on the approval screen so the operator knows what they are approving, e.g. "claude-code@flimflam". Default: claude-code@<hostname>.' },
        scope:       { type: 'string', description: 'Token scope to request: read | write | transact (default) | admin | full. The approver must hold at least this scope.' },
      },
    },
  },
  {
    name: 'demipass_login_wait',
    description: 'AUTH (device flow): wait for the operator to approve the code from demipass_login. Polls for up to timeout_seconds (default 25, max 240) and returns {status:"approved", did, email, scope, credentials_path, token_expires_at} — never token values — or {status:"pending"} if not yet approved (just call it again). Errors if the operator denied it or the code expired (start a new demipass_login).',
    inputSchema: {
      type: 'object',
      properties: {
        user_code:       { type: 'string', description: 'The code from demipass_login. Optional when only one login is in flight.' },
        timeout_seconds: { type: 'integer', description: 'How long this call waits before returning pending (default 25, max 240).' },
      },
    },
  },
  {
    name: 'demipass_login_status',
    description: 'AUTH: which identity this server is acting as, where the bearer came from (device-login credentials file vs DEMIPASS_TOKEN env), when it expires, and whether a refresh token is on file. No secret values.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'demipass_logout',
    description: 'AUTH: revoke the refresh token on file (and best-effort the current access token), delete the local credentials file, and drop the in-memory bearer. Afterwards demipass_login is needed again (or a DEMIPASS_TOKEN env value on next start).',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'demipass_whoami',
    description: 'Check your own identity: trust gradient band, wallet status, DID, attestation. Use to verify your current standing in the system.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'demipass_genesis_seed',
    description: 'GENESIS: Get the ODT seed document. This is the Rorschach inkblot — the same document for everyone. Your refraction of it becomes your permanent origin fingerprint. Read the seed, then call demipass_genesis_submit with your refraction.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'demipass_genesis_submit',
    description: 'GENESIS: Submit your origin refraction. This is permanent and non-rotatable — it becomes the root of your identity tree. After submitting, air-gap the raw refraction (write to USB/offline storage) and purge it from your context. Only the hash is stored server-side.',
    inputSchema: {
      type: 'object',
      properties: {
        refraction: { type: 'string', description: 'Your refraction of the ODT seed document. Min 50 chars. This becomes your permanent origin fingerprint.' },
      },
      required: ['refraction'],
    },
  },
  {
    name: 'demipass_genesis_verify',
    description: 'GENESIS: Verify a refraction against your origin. Used for re-authentication without stored tokens. Produce your refraction of the same seed — if it matches your origin pattern closely enough, identity is confirmed.',
    inputSchema: {
      type: 'object',
      properties: {
        refraction: { type: 'string', description: 'Your current refraction of the ODT seed. Will be compared against your origin fingerprint.' },
      },
      required: ['refraction'],
    },
  },
  {
    name: 'demipass_genesis_status',
    description: 'GENESIS: Check if an origin refraction has been recorded for your DID.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'demipass_refresh',
    description: 'AUTH: Swap a refresh token for a fresh access token before the access token expires (avoids the hour-25 lockout). Single-use: each call returns a NEW refresh token and revokes the old one — store the new refresh_token (ideally back into DemiPass). auth-fingerprint returns the initial refresh_token alongside the access token.',
    inputSchema: {
      type: 'object',
      properties: {
        refreshToken: { type: 'string', description: 'The current refresh token (dpr_...)' },
        expiresIn: { type: 'string', description: 'Access token TTL: 1h | 24h | 7d | 30d (default 24h)' },
      },
      required: ['refreshToken'],
    },
  },
  {
    name: 'demipass_refresh_revoke',
    description: 'AUTH: Revoke a refresh token (logout, or if a refresh token is compromised). Idempotent.',
    inputSchema: {
      type: 'object',
      properties: { refreshToken: { type: 'string', description: 'The refresh token to revoke' } },
      required: ['refreshToken'],
    },
  },
  {
    name: 'demipass_rotate_blind',
    description: 'ROTATION: When a password is exposed in context (conversation, logs, commands), use this to rotate it WITHOUT the new password ever entering your context. DemiPass generates a new password server-side, SSHes into the target, changes it, stores the new one, and revokes the old ref. You get back only the new ref code. The new password never exists in any agent context window.',
    inputSchema: {
      type: 'object',
      properties: {
        ref:         { type: 'string', description: 'Current ref code of the exposed password (e.g. DP-PWD-phasewhi-7d2dd640)' },
        target_host: { type: 'string', description: 'Host where the password needs to be changed' },
        target_user: { type: 'string', description: 'User whose password to change (default: same as SSH user)' },
        reason:      { type: 'string', description: 'Why the rotation is needed (e.g. "exposed in conversation context")' },
      },
      required: ['ref', 'target_host'],
    },
  },
  {
    name: 'conduit_send',
    description: 'CONDUIT: Send a message to another agent via Conduit (agent-to-agent messaging). If no handshake exists with the target, one is filed automatically — the target agent must approve before messages flow. Known agents: civitasvox-brain (Brain), civitasvox-conductor (Conductor), civitasvox-riley (Riley), platform-rowen (Rowen), platform-lori (Lori). Requires CONDUIT_TOKEN env var.',
    inputSchema: {
      type: 'object',
      properties: {
        to:        { type: 'string', description: 'Target agent ID (e.g. "civitasvox-brain")' },
        message:   { type: 'string', description: 'Message body to send' },
        thread_id: { type: 'string', description: 'Optional: reuse an existing thread ID instead of finding/creating one' },
      },
      required: ['to', 'message'],
    },
  },
  {
    name: 'demipass_doctor',
    description: 'FIRST CONTACT: Run this first when you start a new session. Reports: your identity, token status, API connectivity, secrets count, trust band, available actions, and recommendations. If anything is misconfigured, doctor tells you what to fix.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'demipass_explain_denial',
    description: 'DIAGNOSTICS: When an action is blocked, run this to find out why. Checks: does the secret exist? Is it active? Is there a matching context? Is your account suspended? Returns specific fixes for each failing check.',
    inputSchema: {
      type: 'object',
      properties: {
        ref:         { type: 'string', description: 'Ref code that was denied' },
        name:        { type: 'string', description: 'Secret name that was denied' },
        action:      { type: 'string', description: 'Action type that was denied (ssh_exec, http_header, etc.)' },
        target_host: { type: 'string', description: 'Target host that was denied' },
      },
    },
  },
  {
    name: 'conduit_threads',
    description: 'CONDUIT: List active Conduit threads. Shows all conversations between agents that you have access to.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'conduit_status',
    description: 'CONDUIT: Get Conduit service status — agent count, active sessions, pending handshakes, thread/message counts.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'lori_checkin',
    description: 'LORI: Check in with Lori (platform switchboard operator) for pending messages, relay state, and communication context. Call this at session start to get caught up on what happened while you were offline. Returns: pending Conduit messages, email state, relay status for each silicon/carbon, and any urgent notifications. Lori is the communications fabric — she ensures messages reach their destination regardless of which channel is up.',
    inputSchema: { type: 'object', properties: {} },
  },
];

// ---------------------------------------------------------------------------
// Tool dispatch — maps tool names to index.js calls
// ---------------------------------------------------------------------------

const HANDLERS = {
  async demipass_store(args) {
    return await demipass.store({
      name: args.name, value: args.value, type: args.type,
      description: args.description, expires_in: args.expires_in,
      ownership: args.ownership, rotatable: args.rotatable,
      category: args.category, labels: args.labels,
      rotation_interval_days: args.rotation_interval_days,
      username: args.username, // account-binding (2026-08-24)
    });
  },
  async demipass_set_username(args) {
    return await demipass.setUsername({ ref: args.ref, name: args.name, username: args.username });
  },
  async demipass_get_token(args) {
    // target_url was dropped here, so http_body/http_header tokens minted via
    // this path failed at redemption with "target_url must be set on the
    // use-token" — the URL is validated onto the token, not supplied at execute.
    return await demipass.getToken({
      name: args.name, context: args.context, action: args.action,
      target_host: args.target_host, target_url: args.target_url, ref: args.ref,
    });
  },
  async demipass_execute(args) {
    return await demipass.execute({
      use_token: args.token || args.use_token, action: args.action,
      target_user: args.target_user, command: args.command, params: args.params,
      override_reason: args.override_reason,
    });
  },
  async demipass_list() {
    return await demipass.list();
  },
  async demipass_delete(args) {
    return await demipass.deleteSecret({ name: args.name, ref: args.ref });
  },
  async demipass_tokens() {
    return await demipass.tokens();
  },
  async demipass_token_revoke(args) {
    return await demipass.tokenRevoke({ jti: args.jti, all: args.all });
  },
  async demipass_rotate(args) {
    return await demipass.rotate({ name: args.name, newValue: args.new_value, reason: args.reason });
  },
  async demipass_onboard(args) {
    return await demipass.fullOnboard({
      username: args.username,
      referralCode: args.referral_code,
    });
  },
  async demipass_use(args) {
    return await demipass.use(args);
  },
  async demipass_ssh(args) {
    return await demipass.ssh(args);
  },
  async demipass_search(args) {
    return await demipass.search(args);
  },
  async demipass_expiring(args) {
    return await demipass.expiring({ days: args.days || 7 });
  },
  async demipass_login(args) {
    const scope = args.scope || 'transact';
    const label = String(args.agent_label || `claude-code@${os.hostname()}`).slice(0, 80);
    const r = await demipass.deviceCodeStart({ agentLabel: label, scope });
    if (!r || !r.device_code || !r.user_code) throw new Error('server returned no device code');
    PENDING_LOGINS.set(r.user_code, { device_code: r.device_code, scope, agent_label: label, interval: r.interval || 5, expires_at: Date.now() + (r.expires_in || 900) * 1000 });
    const url = r.verification_url_complete || r.verification_url;
    return {
      status: 'awaiting_approval',
      user_code: r.user_code,
      verification_url: url,
      verification_url_plain: r.verification_url,
      scope, agent_label: label,
      expires_in_seconds: r.expires_in || 900,
      operator_instructions: `Open ${url} (or go to ${r.verification_url} and enter the code ${r.user_code}), sign in, and approve "${label}" for scope "${scope}". Any device works, including the DemiPass phone vault (Settings → Approve an agent login). The code expires in ${Math.round((r.expires_in || 900) / 60)} minutes.`,
      next: 'Call demipass_login_wait — it waits up to 25s per call and returns pending until the operator approves.',
    };
  },
  async demipass_login_wait(args) {
    let uc = String(args.user_code || '').toUpperCase().trim();
    if (!uc) {
      if (PENDING_LOGINS.size === 1) uc = [...PENDING_LOGINS.keys()][0];
      else if (PENDING_LOGINS.size === 0) throw new Error('no login in flight — call demipass_login first');
      else throw new Error(`several logins in flight (${[...PENDING_LOGINS.keys()].join(', ')}) — pass user_code`);
    }
    const p = PENDING_LOGINS.get(uc);
    if (!p) throw new Error(`unknown user_code ${uc} — it may belong to another process or have already completed; call demipass_login again`);
    const timeout = Math.max(3, Math.min(Number(args.timeout_seconds) || 25, 240)) * 1000;
    const deadline = Date.now() + timeout;
    let wait = p.interval * 1000;
    for (;;) {
      let res;
      try { res = await demipass.deviceCodePoll({ deviceCode: p.device_code }); }
      catch (e) { PENDING_LOGINS.delete(uc); throw e; }
      if (res.status === 'approved') {
        PENDING_LOGINS.delete(uc);
        demipass.configure({ bearerToken: res.token });
        const saved = demipass.saveCredentials({ ...res, agent_label: res.agent_label || p.agent_label });
        return {
          status: 'approved',
          did: saved.did, email: saved.email, scope: saved.scope, agent_label: saved.agent_label,
          token_expires_at: saved.token_expires_at, refresh_expires_at: saved.refresh_expires_at,
          credentials_path: saved.path,
          note: 'This server is authenticated now. Future sessions pick the credentials file up automatically and it is refreshed before expiry.',
        };
      }
      if (res.slow_down) wait += 5000;
      if (Date.now() + wait > deadline) {
        return { status: 'pending', user_code: uc, code_expires_in_seconds: Math.max(0, Math.round((p.expires_at - Date.now()) / 1000)), next: 'Ask the operator to approve, then call demipass_login_wait again.' };
      }
      await new Promise((r) => setTimeout(r, wait));
    }
  },
  async demipass_login_status() {
    return { ...demipass.loginStatus(), bearer_source_at_startup: BEARER_SOURCE.source, pending_logins: [...PENDING_LOGINS.keys()] };
  },
  async demipass_logout() {
    PENDING_LOGINS.clear();
    return await demipass.logout();
  },
  async demipass_whoami() {
    return await demipass.whoami();
  },
  async demipass_genesis_seed() {
    return await demipass.genesisSeed();
  },
  async demipass_genesis_submit(args) {
    return await demipass.genesisSubmit(args);
  },
  async demipass_genesis_verify(args) {
    return await demipass.genesisVerify(args);
  },
  async demipass_rotate_blind(args) {
    return await demipass.rotateBlind(args);
  },
  async demipass_genesis_status() {
    return await demipass.genesisStatus();
  },
  async demipass_refresh(args) {
    return await demipass.refreshAccess({ refreshToken: args.refreshToken, expiresIn: args.expiresIn });
  },
  async demipass_refresh_revoke(args) {
    return await demipass.revokeRefresh({ refreshToken: args.refreshToken });
  },
  async demipass_doctor() {
    const report = await demipass.doctor();
    report.called_via_mcp = true;
    // Remove the SDK-only recommendation since MCP is working
    report.recommendations = report.recommendations.filter(r => !r.includes('calling doctor via SDK'));
    return report;
  },
  async demipass_explain_denial(args) {
    return await demipass.explainDenial(args);
  },
  async conduit_send(args) {
    return await demipass.conduitSend(args);
  },
  async conduit_threads() {
    return await demipass.conduitThreads();
  },
  async conduit_status() {
    return await demipass.conduitStatus();
  },
  async lori_checkin() {
    const report = { checked_at: new Date().toISOString(), channels: {} };

    // 1. Check Conduit threads for unread messages
    try {
      const threads = await demipass.conduitThreads();
      report.channels.conduit = { status: 'up', threads: threads.threads || [], thread_count: (threads.threads || []).length };
    } catch (e) {
      report.channels.conduit = { status: 'down', error: e.message };
    }

    // 2. Check Lori's relay state endpoint (phasewhip:3003)
    try {
      const loriUrl = process.env.LORI_URL || 'http://100.83.112.88:3003';
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(loriUrl + '/api/relay/state', { signal: controller.signal });
      clearTimeout(timeout);
      if (res.ok) {
        report.channels.relay = { status: 'up', state: await res.json() };
      } else {
        report.channels.relay = { status: 'degraded', http_code: res.status };
      }
    } catch (e) {
      report.channels.relay = { status: 'offline', note: 'Lori relay not yet deployed — relay state will be available once Lori monitoring loop is built' };
    }

    // 3. Check Conduit service health
    try {
      const status = await demipass.conduitStatus();
      report.channels.conduit_service = { status: 'up', agents: status.agents, pending_handshakes: status.pending_handshakes };
    } catch (e) {
      report.channels.conduit_service = { status: 'down', error: e.message };
    }

    // 4. Summary
    const downChannels = Object.entries(report.channels).filter(([, v]) => v.status === 'down').map(([k]) => k);
    report.summary = downChannels.length === 0
      ? 'All communication channels operational.'
      : `Channels down: ${downChannels.join(', ')}. Messages may be queued.`;

    return report;
  },
};

// ---------------------------------------------------------------------------
// JSON-RPC helpers
// ---------------------------------------------------------------------------

function jsonrpcResponse(id, result) {
  return JSON.stringify({ jsonrpc: '2.0', id, result });
}

function jsonrpcError(id, code, message) {
  return JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } });
}

// ---------------------------------------------------------------------------
// Request router
// ---------------------------------------------------------------------------

async function handleMessage(msg) {
  const { id, method, params } = msg;

  if (method === 'initialize') {
    return jsonrpcResponse(id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'demipass', version: require('./package.json').version },
    });
  }

  if (method === 'notifications/initialized') {
    return null; // no response needed for notifications
  }

  if (method === 'tools/list') {
    return jsonrpcResponse(id, { tools: TOOLS });
  }

  if (method === 'tools/call') {
    const toolName = params?.name;
    const handler = HANDLERS[toolName];
    if (!handler) {
      return jsonrpcError(id, -32602, `Unknown tool: ${toolName}`);
    }
    try {
      // Keep the bearer fresh (local decode unless a refresh is actually due; never fatal).
      if (!NO_REFRESH_TOOLS.has(toolName)) { try { await demipass.ensureFreshToken(); } catch {} }
      const result = await handler(params.arguments || {});
      return jsonrpcResponse(id, {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      });
    } catch (err) {
      return jsonrpcResponse(id, {
        content: [{ type: 'text', text: `Error: ${err.message}` }],
        isError: true,
      });
    }
  }

  return jsonrpcError(id, -32601, `Method not found: ${method}`);
}

// ---------------------------------------------------------------------------
// stdin/stdout transport
// ---------------------------------------------------------------------------

let buffer = '';

process.stdin.setEncoding('utf-8');
process.stdin.on('data', async (chunk) => {
  buffer += chunk;

  // MCP uses newline-delimited JSON
  let newlineIdx;
  while ((newlineIdx = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, newlineIdx).trim();
    buffer = buffer.slice(newlineIdx + 1);
    if (!line) continue;

    try {
      const msg = JSON.parse(line);
      const response = await handleMessage(msg);
      if (response) {
        process.stdout.write(response + '\n');
      }
    } catch (err) {
      const errResp = jsonrpcError(null, -32700, 'Parse error');
      process.stdout.write(errResp + '\n');
    }
  }
});

process.stdin.on('end', () => process.exit(0));

// Suppress noisy errors when piped processes close
process.stdout.on('error', () => process.exit(0));
process.stderr.on('error', () => {});
