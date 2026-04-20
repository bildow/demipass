#!/usr/bin/env node
/**
 * Buoy MCP Server — Temporal anchoring for agent workflows
 *
 * Exposes Buoy tick tools over MCP (JSON-RPC over stdin/stdout).
 * Claude Code launches this and uses it to anchor decisions, handoffs,
 * and task completions in a tamper-evident chain.
 *
 * Configuration (env):
 *   BUOY_URL     — API base URL (default: https://api.dustforge.com)
 *   BUOY_TOKEN   — Bearer token for authenticated ticks
 */

try { require('dotenv').config(); } catch {}

const BUOY_URL = process.env.BUOY_URL || process.env.DEMIPASS_URL || 'https://api.dustforge.com';
const BUOY_TOKEN = process.env.BUOY_TOKEN || process.env.DEMIPASS_TOKEN || '';

const TOOLS = [
  {
    name: 'buoy_tick',
    description: 'Drop a temporal anchor (tick). Creates a tamper-evident chain entry with type, note, and optional cross-references. Use at task boundaries, handoffs, decisions, and audit points.',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', enum: ['begin', 'complete', 'handoff', 'audit', 'decision', 'block', 'unblock', 'alert', 'tick'], description: 'Tick type — what kind of moment this anchors' },
        note: { type: 'string', description: 'What happened or what was decided (max 300 chars)' },
        ref_tick: { type: 'number', description: 'Optional tick ID to link to (e.g., handoff → begin, block → unblock)' },
        tags: { type: 'array', items: { type: 'string' }, description: 'Optional tags (e.g., ["card:245", "repo:rowen"])' },
      },
      required: ['type', 'note'],
    },
  },
  {
    name: 'buoy_verify',
    description: 'Verify a tick signature. Proves a specific agent made a specific claim at a specific time.',
    inputSchema: {
      type: 'object',
      properties: {
        tick_id: { type: 'number', description: 'The tick ID to verify' },
        signature: { type: 'string', description: 'The signature to check' },
      },
      required: ['tick_id', 'signature'],
    },
  },
  {
    name: 'buoy_chain_verify',
    description: 'Verify chain integrity for a range of ticks. Detects tampering or missing entries.',
    inputSchema: {
      type: 'object',
      properties: {
        did: { type: 'string', description: 'DID of the identity whose chain to verify' },
        from_tick_id: { type: 'number', description: 'Start of range (optional)' },
        to_tick_id: { type: 'number', description: 'End of range (optional)' },
      },
      required: ['did'],
    },
  },
  {
    name: 'buoy_stats',
    description: 'Get tick statistics: total ticks, streak, first/last tick.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'buoy_ledger',
    description: 'Read recent tick history (last 20 ticks).',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Number of ticks to return (max 100, default 20)' },
      },
    },
  },
];

// ── HTTP helper ──
function apiRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BUOY_URL);
    const mod = url.protocol === 'https:' ? require('https') : require('http');
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    if (BUOY_TOKEN) opts.headers['Authorization'] = 'Bearer ' + BUOY_TOKEN;
    if (data) opts.headers['Content-Length'] = Buffer.byteLength(data);
    const req = mod.request(opts, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(d); } catch { parsed = d; }
        if (res.statusCode >= 400) {
          return reject(new Error((parsed && parsed.error) || `HTTP ${res.statusCode}`));
        }
        resolve(parsed);
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('timeout')); });
    if (data) req.write(data);
    req.end();
  });
}

// ── Tool handlers ──
async function handleTool(name, args) {
  switch (name) {
    case 'buoy_tick':
      return apiRequest('POST', '/api/tick', {
        note: args.note,
        type: args.type || 'tick',
        ref_tick: args.ref_tick || null,
        tags: args.tags || [],
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
      });

    case 'buoy_verify':
      return apiRequest('POST', '/api/tick/verify', {
        tick_id: args.tick_id,
        signature: args.signature,
      });

    case 'buoy_chain_verify':
      return apiRequest('POST', '/api/tick/chain/verify', {
        did: args.did,
        from_tick_id: args.from_tick_id,
        to_tick_id: args.to_tick_id,
      });

    case 'buoy_stats':
      return apiRequest('GET', '/api/tick/stats');

    case 'buoy_ledger':
      return apiRequest('GET', `/api/tick/ledger?limit=${args.limit || 20}`);

    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

// ── MCP JSON-RPC transport (stdin/stdout) ──
let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (line) handleMessage(line);
  }
});

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

async function handleMessage(line) {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }

  if (msg.method === 'initialize') {
    send({
      jsonrpc: '2.0', id: msg.id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'buoy', version: '1.0.0' },
      },
    });
  } else if (msg.method === 'notifications/initialized') {
    // no-op
  } else if (msg.method === 'tools/list') {
    send({ jsonrpc: '2.0', id: msg.id, result: { tools: TOOLS } });
  } else if (msg.method === 'tools/call') {
    const { name, arguments: args } = msg.params;
    try {
      const result = await handleTool(name, args || {});
      send({
        jsonrpc: '2.0', id: msg.id,
        result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] },
      });
    } catch (err) {
      send({
        jsonrpc: '2.0', id: msg.id,
        result: { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true },
      });
    }
  }
}
