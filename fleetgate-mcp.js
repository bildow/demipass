#!/usr/bin/env node
'use strict';
/**
 * FLEETGATE MCP server — any agent pane onto the FLEETGATE release gate, as its own DemiPass wallet.
 *
 * FLEETGATE is a DemiPass service tenant (dustforge docs/service-tenants.md); the door (atlas/boltcluster fleet/door)
 * takes pull requests from any wallet that consents to pay it. Onboarding is the same path as Conduit's
 * (services().onboard): a consent the wallet's person approves in the DemiPass app, then a service token
 * (aud svc:fleetgate) minted from this pane's own session. The token lives in this process's memory only: it is never
 * printed, returned or written to disk, and is re-minted when it expires (24 h at most) or the door answers 401.
 *
 *   fleetgate_onboard({daily_cap_dd?, approval_id?})   consent (one app approval, once per wallet) + token
 *   fleetgate_prices()                                  the door's public price list
 *   fleetgate_submit({repo, title, files, body?, submission_id?})   one PR into atlas/<repo>; charged once (submit + review round)
 *   fleetgate_status()                                  onboarded? token expiry, consent, door health
 *
 * The gate decides: a submitted PR is evaluated by the release controller under the signed charter like any other.
 * Nothing here merges, approves, reviews or touches a charter.
 *
 * Env: DEMIPASS_TOKEN (this pane's DemiPass session), DEMIPASS_URL, FLEETGATE_DOOR_URL
 *      (default https://repo.dustroot.com/-/fleetgate/door), FLEETGATE_DAILY_CAP_DD (default 3000).
 */
const crypto = require('crypto');
const { services } = require('./services.js');

const DEMIPASS_URL = (process.env.DEMIPASS_URL || 'https://api.dustforge.com').replace(/\/$/, '');
const DOOR = (process.env.FLEETGATE_DOOR_URL || 'https://repo.dustroot.com/-/fleetgate/door').replace(/\/$/, '');
const DEFAULT_CAP = Number(process.env.FLEETGATE_DAILY_CAP_DD || 3000);   // one submission is ~700 DD (submit + review round)
const SERVICE = 'fleetgate';

function dp() { return services({ token: process.env.DEMIPASS_TOKEN || '', baseUrl: DEMIPASS_URL }); }

// The service token: memory only.
let held = null;   // { token, token_id, expires_at, cap_dd }
let consentSeen = null;
const live = () => held && Date.parse(held.expires_at) - Date.now() > 60 * 1000;

async function onboard({ daily_cap_dd, approval_id } = {}) {
  if (!process.env.DEMIPASS_TOKEN) return { ok: false, error: 'DEMIPASS_TOKEN is not set for this MCP server: sign this pane in to DemiPass first' };
  // services().onboard's two steps, with the token's cap set to the whole daily consent: the server's default token
  // cap (500 DD) is below one submission (submit + review round, ~700 DD), so a default token could never submit.
  const api = dp();
  const c = await api.ensureConsent({ service: SERVICE, dailyCapDd: daily_cap_dd || DEFAULT_CAP, approvalId: approval_id });
  let r = c;
  if (!c.pending) {
    const t = await api.mintToken({ service: SERVICE, ttl: '24h', capDd: c.consent.daily_cap_dd });
    r = { consent: c.consent, existing: c.existing, token: { token: t.token, token_id: t.token_id, expires_at: t.expires_at, cap_dd: t.cap_dd } };
  }
  if (r.pending) {
    return { ok: false, status: 'approval_pending', approval_id: r.pending.approval_id, expires_at: r.pending.expires_at, daily_cap_dd: r.pending.daily_cap_dd,
             next: 'Approve "let a wallet pay fleetgate" in the DemiPass app (Requests), then call fleetgate_onboard again with this approval_id.' };
  }
  held = { token: r.token.token, token_id: r.token.token_id, expires_at: r.token.expires_at, cap_dd: r.token.cap_dd };
  consentSeen = r.consent || consentSeen;
  return { ok: true, service: SERVICE, consent: r.consent ? { id: r.consent.id, daily_cap_dd: r.consent.daily_cap_dd, existing: Boolean(r.existing) } : null,
           token_id: held.token_id, expires_at: held.expires_at, cap_dd: held.cap_dd };
}

// A live token, minting one when the consent already exists; an onboarding that needs an approval is reported, not waited on.
async function token() {
  if (live()) return held.token;
  const r = await onboard({});
  if (!r.ok) throw Object.assign(new Error(r.status === 'approval_pending' ? 'not onboarded: run fleetgate_onboard and approve it in the DemiPass app' : r.error), { result: r });
  return held.token;
}

async function http(method, url, { auth, body } = {}) {
  const headers = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (auth) headers.authorization = 'Bearer ' + auth;
  const r = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(180000) });
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch (_) { data = { raw: text.slice(0, 500) }; }
  return { status: r.status, data };
}

const SUBMISSION_RE = /^[A-Za-z0-9_-]{8,64}$/;
async function submit({ repo, title, body, files, submission_id }) {
  if (!repo || !/^[A-Za-z0-9._-]{1,100}$/.test(repo)) return { ok: false, error: 'repo: the name of a repo under atlas/ (e.g. boltcluster)' };
  if (!title) return { ok: false, error: 'title required' };
  if (!Array.isArray(files) || !files.length) return { ok: false, error: 'files: [{path, content}] (the whole new content of each file)' };
  const sid = submission_id || crypto.randomBytes(12).toString('hex');
  if (!SUBMISSION_RE.test(sid)) return { ok: false, error: 'submission_id: 8-64 letters, digits, _ or -' };
  const payload = { submission_id: sid, repo, title, ...(body ? { body } : {}), files };
  let r = await http('POST', DOOR + '/v1/pulls', { auth: await token(), body: payload });
  if (r.status === 401) { held = null; r = await http('POST', DOOR + '/v1/pulls', { auth: await token(), body: payload }); }   // expired or revoked: re-mint once
  if (r.status === 201) return { ok: true, submission_id: sid, ...r.data, note: 'The release controller evaluates it under the signed charter; a retry with the same submission_id replays, never double-charges.' };
  return { ok: false, http_status: r.status, submission_id: sid, ...(r.data || {}),
           ...(r.status === 402 ? { hint: 'DemiPass refused the charge: no consent, not enough DD, or a cap. Nothing was created.' } : {}) };
}

async function status() {
  const health = await http('GET', DOOR + '/health').catch(e => ({ status: 0, data: { error: e.message } }));
  return { ok: true, door: DOOR, door_health: health.status === 200 ? health.data : { http_status: health.status, ...(health.data || {}) },
           onboarded: Boolean(live()), token_id: live() ? held.token_id : null, expires_at: live() ? held.expires_at : null,
           consent: consentSeen ? { id: consentSeen.id, daily_cap_dd: consentSeen.daily_cap_dd } : null };
}

const TOOLS = [
  { name: 'fleetgate_onboard',
    description: 'FLEETGATE: put this pane on the FLEETGATE release gate as its own DemiPass wallet. Checks for a consent to pay fleetgate; if there is none it files one (status approval_pending + approval_id) — the person approves it in the DemiPass app, then call again with approval_id. Then mints a fleetgate service token held only inside this MCP server (never shown). Run once per pane; re-minting after expiry is automatic.',
    inputSchema: { type: 'object', properties: {
      daily_cap_dd: { type: 'integer', description: `Most fleetgate may charge this wallet per 24 h (default ${DEFAULT_CAP}; one submission is about 700 DD)` },
      approval_id: { type: 'integer', description: 'The approval_id from an earlier approval_pending answer, once approved in the app' } } } },
  { name: 'fleetgate_prices', description: 'FLEETGATE: the door\'s public price list (DD per action, margin included).', inputSchema: { type: 'object', properties: {} } },
  { name: 'fleetgate_submit',
    description: 'FLEETGATE: submit a pull request to a chartered repo under atlas/ through the door. Charged once (submit + one review round, see fleetgate_prices) to this pane\'s wallet. The gate evaluates it under the signed charter; this never merges or reviews. Not allowed: dotfiles, charters/, fleet/{controller,review,ci,door}/; at most 20 files, 128 KB each, 384 KB in all.',
    inputSchema: { type: 'object', required: ['repo', 'title', 'files'], properties: {
      repo: { type: 'string', description: 'Repo name under atlas/ (e.g. boltcluster)' },
      title: { type: 'string' }, body: { type: 'string', description: 'PR description' },
      files: { type: 'array', items: { type: 'object', required: ['path', 'content'], properties: { path: { type: 'string' }, content: { type: 'string', description: 'The whole new file content' } } } },
      submission_id: { type: 'string', description: 'Idempotency key (8-64 of A-Z a-z 0-9 _ -). Reuse it to retry the same submission without a second charge; omitted → a fresh one, returned.' } } } },
  { name: 'fleetgate_status', description: 'FLEETGATE: is this pane onboarded (token id and expiry, consent), and is the door up.', inputSchema: { type: 'object', properties: {} } },
];
const HANDLERS = {
  fleetgate_onboard: onboard,
  fleetgate_prices: async () => { const r = await http('GET', DOOR + '/v1/prices'); return r.status === 200 ? { ok: true, ...r.data } : { ok: false, http_status: r.status, ...(r.data || {}) }; },
  fleetgate_submit: submit,
  fleetgate_status: status,
};

// Errors never carry the token: a ServiceError's body is DemiPass's answer, and our own errors name no secret.
function errBody(e) { return { ok: false, error: e.message, ...(e.result || {}), ...(e.body && typeof e.body === 'object' ? { demipass: e.body } : {}), ...(e.status ? { http_status: e.status } : {}) }; }

async function handleMessage(msg) {
  const { id, method, params } = msg;
  if (method === 'initialize') return { jsonrpc: '2.0', id, result: { protocolVersion: (params && params.protocolVersion) || '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'fleetgate', version: require('./package.json').version } } };
  if (method === 'notifications/initialized' || (method && method.startsWith('notifications/'))) return null;
  if (method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
  if (method === 'tools/call') {
    const h = HANDLERS[params && params.name];
    if (!h) return { jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${params && params.name}` } };
    let out; try { out = await h((params && params.arguments) || {}); } catch (e) { out = errBody(e); }
    return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }], ...(out && out.ok === false ? { isError: true } : {}) } };
  }
  if (id === undefined) return null;
  return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
}

module.exports = { handleMessage, _reset: () => { held = null; consentSeen = null; } };

if (require.main === module) {
  // Messages are answered in order through one queue; stdin closing waits for the queue (a call in flight is answered).
  let buf = '', queue = Promise.resolve();
  const answer = line => async () => {
    let msg; try { msg = JSON.parse(line); } catch (_) { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n'); return; }
    const r = await handleMessage(msg).catch(e => ({ jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32603, message: e.message } }));
    if (r) process.stdout.write(JSON.stringify(r) + '\n');
  };
  process.stdin.setEncoding('utf-8');
  process.stdin.on('data', chunk => {
    buf += chunk; let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
      if (line) queue = queue.then(answer(line));
    }
  });
  process.stdin.on('end', () => { queue.then(() => process.exit(0)); });
  process.stdout.on('error', () => process.exit(0));
}
