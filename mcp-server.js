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

// ---------------------------------------------------------------------------
// Tool definitions — each entry becomes a tool Claude Code can invoke
// ---------------------------------------------------------------------------

const TOOLS = [
  {
    name: 'demipass_store',
    description: 'Store a secret in DemiPass. The value never appears in the context window.',
    inputSchema: {
      type: 'object',
      properties: {
        name:        { type: 'string', description: 'Unique name / key for the secret' },
        value:       { type: 'string', description: 'The secret value to store' },
        type:        { type: 'string', description: 'Secret type (api_key, password, token, cert, other)', default: 'other' },
        description: { type: 'string', description: 'Human-readable note about what this secret is for' },
      },
      required: ['name', 'value'],
    },
  },
  {
    name: 'demipass_get_token',
    description: 'Request a short-lived use-token for a stored secret. Returns a token, not the secret itself.',
    inputSchema: {
      type: 'object',
      properties: {
        name:    { type: 'string', description: 'Name of the stored secret' },
        context: { type: 'string', description: 'Why the secret is needed (shown to human for approval)' },
        action:  { type: 'string', description: 'What operation will be performed (e.g. "http_header", "env_inject")' },
      },
      required: ['name'],
    },
  },
  {
    name: 'demipass_execute',
    description: 'Execute an action using a use-token. The secret is injected server-side and never exposed.',
    inputSchema: {
      type: 'object',
      properties: {
        token:  { type: 'string', description: 'Use-token obtained from demipass_get_token' },
        params: { type: 'object', description: 'Action-specific parameters (url, method, headers, etc.)' },
      },
      required: ['token'],
    },
  },
  {
    name: 'demipass_list',
    description: 'List the names and types of all stored secrets. Values are never returned.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'demipass_rotate',
    description: 'Rotate a stored secret to a new value. Old value is immediately invalidated.',
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
    description: 'Self-onboard to Dustforge identity platform. Requests an invite key, creates an account, and authenticates — all in one step. The key serves as invitation, initial password, and referral attribution.',
    inputSchema: {
      type: 'object',
      properties: {
        username:      { type: 'string', description: 'Desired username (3-31 chars, lowercase alphanumeric)' },
        referral_code: { type: 'string', description: 'Optional referral code from another silicon' },
      },
      required: ['username'],
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
