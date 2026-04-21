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
 *   DEMIPASS_URL    — API base URL
 *   DEMIPASS_TOKEN  — bearer token for auth
 */

try { require('dotenv').config(); } catch {}

const demipass = require('./index.js');

// Configure SDK with env vars
demipass.configure({
  baseUrl: process.env.DEMIPASS_URL || 'https://api.dustforge.com',
  bearerToken: process.env.DEMIPASS_TOKEN || '',
  adminKey: process.env.DEMIPASS_ADMIN_KEY || '',
});

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
      },
      required: ['name', 'value'],
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
        action:  { type: 'string', description: 'Action type: http_header, ssh_exec, http_body, document' },
        owner_did: { type: 'string', description: 'Owner DID (only needed if using name without ref for delegated secrets)' },
        target_host: { type: 'string', description: 'Target host for SSH exec actions' },
      },
    },
  },
  {
    name: 'demipass_execute',
    description: 'EGRESS step 2: Redeem a use-token. The secret is injected server-side — into an HTTP header, a POST body, an SSH command, or returned as a document. You receive the result (API response, command output) but never the secret itself. The token is burned after one use.',
    inputSchema: {
      type: 'object',
      properties: {
        token:  { type: 'string', description: 'Use-token from demipass_get_token (valid 30 seconds)' },
        params: { type: 'object', description: 'Action params: {command, target_user} for ssh_exec, {url, method} for http_header, etc.' },
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
    description: 'EGRESS (one-step): Request a use-token AND redeem it in a single call. Combines get_token + execute. Use this instead of the two-step flow for simple operations. Specify a ref code OR name + action.',
    inputSchema: {
      type: 'object',
      properties: {
        ref:         { type: 'string', description: 'Routed reference code (e.g. DP-API-openrout-7f3a9c1e). Preferred.' },
        name:        { type: 'string', description: 'Secret name (if not using ref)' },
        action:      { type: 'string', description: 'Action type: http_header, ssh_exec, http_body, document' },
        owner_did:   { type: 'string', description: 'Owner DID (only for delegated access without ref)' },
        target_host: { type: 'string', description: 'Target host (required for SSH)' },
        target_user: { type: 'string', description: 'SSH user (default: root)' },
        command:     { type: 'string', description: 'Command to execute (for SSH)' },
        params:      { type: 'object', description: 'Additional action-specific parameters' },
      },
    },
  },
  {
    name: 'demipass_ssh',
    description: 'SSH into a host using a DemiPass ref code. One call: ref + host + command → output. The password is injected server-side. You never see it. This is the primary way to access remote machines.',
    inputSchema: {
      type: 'object',
      properties: {
        ref:         { type: 'string', description: 'Ref code for the SSH password (e.g. DP-PWD-sharedra-b08a108a)' },
        target_host: { type: 'string', description: 'IP or hostname to SSH into' },
        target_user: { type: 'string', description: 'SSH username (default: root)' },
        command:     { type: 'string', description: 'Command to run on the remote host' },
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
    name: 'demipass_whoami',
    description: 'Check your own identity: trust gradient band, wallet status, DID, attestation. Use to verify your current standing in the system.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

// ---------------------------------------------------------------------------
// Tool dispatch — maps tool names to index.js calls
// ---------------------------------------------------------------------------

const HANDLERS = {
  async demipass_store(args) {
    return await demipass.store(args.name, args.value, args.type, args.description);
  },
  async demipass_get_token(args) {
    return await demipass.getToken(args.name, args.context, args.action);
  },
  async demipass_execute(args) {
    return await demipass.execute(args.token, args.params);
  },
  async demipass_list() {
    return await demipass.list();
  },
  async demipass_rotate(args) {
    return await demipass.rotate(args.name, args.new_value);
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
  async demipass_whoami() {
    return await demipass.whoami();
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
      serverInfo: { name: 'demipass', version: '0.1.0' },
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
