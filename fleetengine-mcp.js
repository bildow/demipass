#!/usr/bin/env node
'use strict';
/**
 * FleetEngine MCP server — any agent pane onto FleetEngine (CSP's engines as one metered service), as its own DemiPass
 * wallet. Modeled on fleetgate-mcp.js (#17, fe62cdf).
 *
 * FleetEngine is a DemiPass service tenant (dustforge docs/service-tenants.md; tome
 * decisions/2026-11-12-DECISION-fleetengine-and-shadow-engine-redefinition.md). Onboarding is the same path as
 * FLEETGATE's: a consent the wallet's person approves in the DemiPass app, then a service token (aud svc:fleetengine)
 * minted from this pane's own session. The token lives in this process's memory only: it is never printed, returned or
 * written to disk, and is re-minted when it expires (24 h at most) or the service answers 401. It carries a follow-up
 * budget (follow_up_dd) because an engine's model calls are metered after the intake charge, as follow-ups of it.
 *
 *   fleetengine_onboard({daily_cap_dd?, approval_id?})       consent (one app approval, once per wallet) + token
 *   fleetengine_status()                                      onboarded? token expiry, consent, service health
 *   fleetengine_engines()                                     the engines the service runs (public)
 *   fleetengine_prices()                                      the tenant's public price list
 *   fleetengine_run({engine, requisition, job_id?})           one job; intake charged once, model calls metered
 *   fleetengine_job({job_id})                                 a job's state and outcome (only the paying wallet)
 *   fleetengine_pattern_run({pattern, inputs, job_id?})       a shadow (pattern) engine run: engines chained
 *
 * job_id is the caller's idempotency key: a retry with the same job_id replays the intake charge and finds the job,
 * never a second charge. Refusals from DemiPass (401/402/403, approval pending) come back as DemiPass gave them.
 *
 * Env: DEMIPASS_TOKEN (this pane's DemiPass session), DEMIPASS_URL, FLEETENGINE_URL
 *      (default https://repo.dustroot.com/-/fleetengine), FLEETENGINE_DAILY_CAP_DD (default 3000).
 */
const crypto = require('crypto');
const { services } = require('./services.js');
// This machine's live DemiPass session, read each time it is needed: the MCP config entry holds no copy of it.
const { sessionToken, consentAtLeast } = require('./onboard.js');

const DEMIPASS_URL = (process.env.DEMIPASS_URL || 'https://api.dustforge.com').replace(/\/$/, '');
const SERVICE_DEFAULT = 'https://repo.dustroot.com/-/fleetengine';
const SERVICE = 'fleetengine';
// The service: FLEETENGINE_URL, else the endpoint FleetEngine registered with DemiPass (GET /api/services/fleetengine),
// else the default. https only, except a loopback host (tests) — the service token goes there.
function endpointRefusal(u) {
  let x; try { x = new URL(u); } catch (_) { return 'not a URL'; }
  if (x.username || x.password || x.search || x.hash) return 'no credentials, query or fragment in the endpoint';
  if (x.protocol === 'https:') return null;
  if (x.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(x.hostname)) return null;
  return 'the FleetEngine endpoint must be https';
}
let endpointCached = null;
async function endpoint() {
  if (endpointCached) return endpointCached;
  let u = process.env.FLEETENGINE_URL || '';
  if (!u) { try { const r = await http('GET', DEMIPASS_URL + '/api/services/' + SERVICE); if (r.status === 200 && r.data && r.data.endpoint) u = r.data.endpoint; } catch (_) {} }
  u = (u || SERVICE_DEFAULT).replace(/\/+$/, '');
  const bad = endpointRefusal(u); if (bad) throw new Error(`FleetEngine ${u}: ${bad}`);
  return (endpointCached = u);
}
const DEFAULT_CAP = Number(process.env.FLEETENGINE_DAILY_CAP_DD || 3000);   // a deep job's ceiling is 5000 DD: pass a higher daily_cap_dd for those

function dp(token = sessionToken()) { return services({ token, baseUrl: DEMIPASS_URL }); }

// The service token: memory only.
let held = null;   // { token, token_id, expires_at, cap_dd, wallet }
let consentSeen = null;
const pendingCaps = new Map();   // approval_id → the daily cap asked for: redeeming must repeat it
const TOKEN_RE = /^[A-Za-z0-9_.-]{20,4096}$/;
// A held token is used only by the wallet that minted it (the JWT's sub of the session it was minted with).
const subOf = (t) => { try { return t ? JSON.parse(Buffer.from(String(t).split('.')[1], 'base64url').toString()).sub || null : null; } catch (_) { return null; } };
const sessionSub = () => subOf(sessionToken());
const live = () => { if (!held) return false; const me = sessionSub(); if (!me || me !== held.wallet) return false; return Date.parse(held.expires_at) - Date.now() > 60 * 1000; };

async function onboard({ daily_cap_dd, approval_id } = {}, { fileConsent = true } = {}) {
  // One session for the whole onboarding: the token is minted with it and held for its wallet.
  const session = sessionToken();
  const api = dp(session), wallet = subOf(session);
  if (!session) return { ok: false, error: process.env.DEMIPASS_EXPECT_DID ? `no DemiPass session for ${process.env.DEMIPASS_EXPECT_DID} (the wallet this server was onboarded as) on this machine` : 'no DemiPass session on this machine: sign in first (demipass_login, or set DEMIPASS_TOKEN)' };
  if (approval_id && !daily_cap_dd && pendingCaps.has(Number(approval_id))) daily_cap_dd = pendingCaps.get(Number(approval_id));
  if (!fileConsent) {
    // Running a job never files a consent: after a person said no, a run must not ask their phone again.
    const all = await api.consents();
    if (!(all.mine || []).some(c => c.service === SERVICE && c.status === 'active')) return { ok: false, status: 'not_onboarded', error: 'not onboarded: run fleetengine_onboard and approve it in the DemiPass app' };
  }
  const c = await consentAtLeast(api, { service: SERVICE, cap: daily_cap_dd || DEFAULT_CAP, explicit: Boolean(daily_cap_dd), approvalId: approval_id });
  let r = c;
  if (!c.pending) {
    // The intake stays under the server's default cap; the engine's metered model calls bill afterwards as follow-ups,
    // against the follow-up budget, up to the whole daily consent.
    const t = await api.mintToken({ service: SERVICE, ttl: '24h', followUpDd: c.consent.daily_cap_dd });
    r = { consent: c.consent, existing: c.existing, token: { token: t.token, token_id: t.token_id, expires_at: t.expires_at, cap_dd: t.cap_dd } };
  }
  if (r.pending) {
    pendingCaps.set(Number(r.pending.approval_id), r.pending.daily_cap_dd);
    return { ok: false, status: 'approval_pending', approval_id: r.pending.approval_id, expires_at: r.pending.expires_at, daily_cap_dd: r.pending.daily_cap_dd,
             next: `Approve "let a wallet pay fleetengine" (${r.pending.daily_cap_dd} DD/day) in the DemiPass app (Requests), then call fleetengine_onboard again with approval_id ${r.pending.approval_id} and daily_cap_dd ${r.pending.daily_cap_dd}.` };
  }
  if (!TOKEN_RE.test(String(r.token.token || ''))) return { ok: false, error: 'DemiPass returned a malformed service token; not held' };
  held = { token: r.token.token, token_id: r.token.token_id, expires_at: r.token.expires_at, cap_dd: r.token.cap_dd, wallet };
  consentSeen = r.consent || consentSeen;
  const reach = await readiness();
  const price = await intakePrice();
  const low = price && r.consent && r.consent.daily_cap_dd < price;
  return { ok: true, service: SERVICE, consent: r.consent ? { id: r.consent.id, daily_cap_dd: r.consent.daily_cap_dd, existing: Boolean(r.existing) } : null,
           token_id: held.token_id, expires_at: held.expires_at, cap_dd: held.cap_dd, follow_up_dd: r.consent ? r.consent.daily_cap_dd : null, service_ready: reach,
           ...(low ? { warning: `your daily consent (${r.consent.daily_cap_dd} DD) is below one job's intake (${price} DD): every run would be refused. Call fleetengine_onboard with a higher daily_cap_dd to replace it (one approval).` } : {}) };
}

// Free readiness: the service verifies the held token with DemiPass on a job lookup (verify is free; nothing is
// charged). 404 "no such job" means the token was accepted; 401/402/403 come back as DemiPass gave them.
async function readiness() {
  try {
    const r = await http('GET', (await endpoint()) + '/v1/jobs/readiness-probe', { auth: held.token });
    if (r.status === 404 || r.status === 200) return { ok: true };
    return { ok: false, http_status: r.status, ...(r.data || {}) };
  } catch (e) { return { ok: false, error: e.name === 'TimeoutError' ? 'FleetEngine timed out' : 'FleetEngine could not be reached' }; }
}

async function intakePrice() {
  try { const r = await http('GET', (await endpoint()) + '/v1/prices'); const a = ((r.data && r.data.actions) || []); return a.filter(x => x.action === 'job').reduce((n, x) => n + (x.price_dd || 0), 0) || null; }
  catch (_) { return null; }
}
// A live token, minting one when the consent already exists; an onboarding that needs an approval is reported, not waited on.
async function token() {
  if (live()) return held.token;
  const r = await onboard({}, { fileConsent: false });
  if (!r.ok) throw Object.assign(new Error(r.error || 'not onboarded: run fleetengine_onboard and approve it in the DemiPass app'), { result: r });
  return held.token;
}

async function http(method, url, { auth, body } = {}) {
  const headers = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (auth) headers.authorization = 'Bearer ' + auth;
  const r = await require('./http-json').requestJson(method, url, { headers, body, timeoutMs: 180000 });
  return { status: r.status, data: r.data !== null ? r.data : { raw: r.text.slice(0, 500) } };
}

// The service's own patterns: job_id 6-64 of [A-Za-z0-9_-] starting with a letter or digit; engine names lower-case.
const JOB_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{5,63}$/;
const ENGINE_RE = /^[a-z][a-z0-9_-]{1,31}$/;
const newJobId = () => 'fe-' + crypto.randomBytes(12).toString('hex');

// One authenticated call with the held token: a 401 drops it and re-mints once. Minting is DemiPass's answer, not
// FleetEngine's: its refusal comes back as it is, and says the service was not contacted.
async function authed(method, path, body, jobId) {
  const mint = async () => { try { return { auth: await token() }; } catch (e) { return { refused: { ...errBody(e), job_id: jobId, note: 'DemiPass refused the token; nothing was sent to FleetEngine.' } }; } };
  let m = await mint(); if (m.refused) return { refused: m.refused };
  const url = (await endpoint()) + path;
  let r = await http(method, url, { auth: m.auth, body });
  if (r.status === 401) {   // expired or revoked: re-mint once
    held = null; m = await mint(); if (m.refused) return { refused: m.refused };
    r = await http(method, url, { auth: m.auth, body });
  }
  return { r };
}

async function submitJob(requisition, job_id, label) {
  const jid = job_id || newJobId();
  if (!JOB_ID_RE.test(jid)) return { ok: false, error: 'job_id: 6-64 letters, digits, _ or -, starting with a letter or digit' };
  let out;
  try { out = await authed('POST', '/v1/jobs', { job_id: jid, requisition }, jid); }
  catch (e) {
    // The service may have charged before the connection dropped: hand back the id, so the retry replays.
    if (e.result) return { ...e.result, job_id: jid };
    return { ok: false, job_id: jid, error: e.name === 'TimeoutError' ? 'FleetEngine timed out' : 'FleetEngine could not be reached',
             next: `Retry ${label} with job_id "${jid}": if the intake was already charged, it replays that charge and finds the job.` };
  }
  if (out.refused) return out.refused;
  const r = out.r;
  // 202 is both "queued" (FleetEngine's answer, with the job) and DemiPass's own 202 (an approval pending), passed on.
  if (r.status === 202 && r.data && r.data.ok === true && r.data.job_id)
    return { ...r.data, ok: true, job_id: r.data.job_id, note: 'Queued. Poll fleetengine_job (free), or wait for the Conduit delivery if requisition.delivery names one. A retry with the same job_id replays, never double-charges.' };
  return { ok: false, http_status: r.status, job_id: jid, ...(r.data || {}),
           ...(r.status === 402 ? { hint: 'DemiPass refused the charge: no consent, not enough DD, or a cap. Nothing was queued.' } : {}),
           ...(r.status === 202 ? { hint: 'DemiPass is waiting on an approval in the DemiPass app; nothing was queued. Retry with the same job_id once approved.' } : {}) };
}

async function run({ engine, requisition, job_id } = {}) {
  if (typeof engine !== 'string' || !ENGINE_RE.test(engine)) return { ok: false, error: 'engine: an engine name (fleetengine_engines lists them)' };
  if (!requisition || typeof requisition !== 'object' || Array.isArray(requisition)) return { ok: false, error: 'requisition: {pool, effort?, premise, concern?, delivery?: {conduit_name}}' };
  if (requisition.engine !== undefined && requisition.engine !== engine) return { ok: false, error: `requisition.engine (${requisition.engine}) differs from engine (${engine})` };
  return submitJob({ ...requisition, engine }, job_id, 'fleetengine_run');
}

// The shadow (pattern) engine: one job whose requisition is a pattern (steps, edges, framing injections) plus its
// inputs. One intake for the run; every step bills as a follow-up of it. The service validates the pattern.
async function patternRun({ pattern, inputs, job_id, delivery } = {}) {
  if (!(typeof pattern === 'string' && pattern.trim()) && !(pattern && typeof pattern === 'object' && !Array.isArray(pattern))) return { ok: false, error: 'pattern: a pattern name, or a pattern definition {steps, edges}' };
  if (inputs !== undefined && (!inputs || typeof inputs !== 'object' || Array.isArray(inputs))) return { ok: false, error: 'inputs: an object (the first steps\' requisition fields)' };
  return submitJob({ engine: 'shadow', pattern, inputs: inputs || {}, ...(delivery ? { delivery } : {}) }, job_id, 'fleetengine_pattern_run');
}

async function job({ job_id } = {}) {
  if (typeof job_id !== 'string' || !JOB_ID_RE.test(job_id)) return { ok: false, error: 'job_id: the id fleetengine_run returned' };
  const out = await authed('GET', '/v1/jobs/' + job_id, undefined, job_id);
  if (out.refused) return out.refused;
  const r = out.r;
  if (r.status === 200) return { ok: true, ...r.data };
  return { ok: false, http_status: r.status, job_id, ...(r.data || {}) };
}

async function status() {
  const health = await http('GET', (await endpoint()) + '/health').catch(e => ({ status: 0, data: { error: e.message } }));
  let ready;
  try {
    ready = held && held.wallet !== sessionSub() ? { ok: false, status: 'wallet_changed', error: 'The held token belongs to another wallet; onboard explicitly' }
      : live() ? await readiness() : await onboard({}, { fileConsent: false });
  } catch (e) { ready = errBody(e); }
  return { ok: health.status === 200 && health.data && health.data.ok === true && Boolean(ready.ok), service: await endpoint(),
    service_health: health.status === 200 ? health.data : { http_status: health.status, ...(health.data || {}) },
    onboarded: Boolean(live() && ready.ok), ...(ready.ok ? {} : { readiness: ready }),
    token_id: live() ? held.token_id : null, expires_at: live() ? held.expires_at : null,
    consent: consentSeen ? { id: consentSeen.id, daily_cap_dd: consentSeen.daily_cap_dd } : null };
}

const POOL = { type: 'object', description: 'What to read: exactly one of files [{path, content}] (20 files, 128 KB each, 384 KB in all, no dotfiles), git {url, ref?}, url', properties: {
  files: { type: 'array', items: { type: 'object', required: ['path', 'content'], properties: { path: { type: 'string' }, content: { type: 'string' } } } },
  git: { type: 'object', properties: { url: { type: 'string' }, ref: { type: 'string' } } }, url: { type: 'string' } } };
const DELIVERY = { type: 'object', required: ['conduit_name'], description: 'Post the outcome to this Conduit name when the job ends (Conduit\'s per-recipient charge is a line on the job)', properties: { conduit_name: { type: 'string' } } };
const JOB_ID = { type: 'string', description: 'Idempotency key (6-64 of A-Z a-z 0-9 _ -). Reuse it to retry the same job without a second charge; omitted → a fresh one, returned.' };

const TOOLS = [
  { name: 'fleetengine_onboard',
    description: 'FleetEngine: put this pane on FleetEngine (CSP\'s engines as a metered service) as its own DemiPass wallet. Checks for a consent to pay fleetengine; if there is none it files one (status approval_pending + approval_id) — the person approves it in the DemiPass app, then call again with approval_id. Then mints a fleetengine service token held only inside this MCP server (never shown), with a follow-up budget so the engines\' model calls can bill after the intake. Re-minting is automatic.',
    inputSchema: { type: 'object', properties: {
      daily_cap_dd: { type: 'integer', description: `Most fleetengine may charge this wallet per 24 h (default ${DEFAULT_CAP}; intake plus metered model calls share it; a deep job may meter up to 5000 DD)` },
      approval_id: { type: 'integer', description: 'The approval_id from an earlier approval_pending answer, once approved in the app' } } } },
  { name: 'fleetengine_status', description: 'FleetEngine: free readiness check — onboarded? token id and expiry, consent, service health. No consent is filed and nothing is charged.', inputSchema: { type: 'object', properties: {} } },
  { name: 'fleetengine_engines', description: 'FleetEngine: the engines the service runs (name, what it does, pools it reads, whether it calls models). Free.', inputSchema: { type: 'object', properties: {} } },
  { name: 'fleetengine_prices', description: 'FleetEngine: the tenant\'s public price list (DD per action, margin included). Model calls are metered at cost plus margin. Free.', inputSchema: { type: 'object', properties: {} } },
  { name: 'fleetengine_run',
    description: 'FleetEngine: run one engine on a requisition. Real cost: one intake charge, then the engine\'s model calls metered at cost plus margin in ≤250 DD portions, up to the job\'s ceiling (max_dd, or by effort: scan 250 / standard 1000 / deep 5000). Returns a job_id at once (202); poll fleetengine_job or name a Conduit delivery. A job the wallet can no longer pay for ends as a certified refusal, never a silent partial.',
    inputSchema: { type: 'object', required: ['engine', 'requisition'], properties: {
      engine: { type: 'string', description: 'Engine name, e.g. audit (fleetengine_engines)' },
      requisition: { type: 'object', required: ['pool', 'premise'], properties: {
        pool: POOL,
        effort: { type: 'string', enum: ['scan', 'standard', 'deep'], description: 'Granularity (default standard)' },
        premise: { type: 'string', description: 'The framing the engine works under (the countersign audits it)' },
        concern: { type: 'string', description: 'The focus' },
        delivery: DELIVERY,
        max_dd: { type: 'integer', description: 'This job\'s metered-work ceiling in DD (never above the token\'s follow-up budget)' } } },
      job_id: JOB_ID } } },
  { name: 'fleetengine_job', description: 'FleetEngine: a job\'s state and outcome (queued | running | done | refused | failed), its charges and seal. Only the wallet that paid can read it; any other gets "no such job". Free.',
    inputSchema: { type: 'object', required: ['job_id'], properties: { job_id: { type: 'string' } } } },
  { name: 'fleetengine_pattern_run',
    description: 'FleetEngine: run a shadow (pattern) engine pattern — engines chained, one engine\'s outputs into another\'s inputs, with a framing injection that is predetermined or gated on a returned result. Real cost: one intake for the run, every step metered as a follow-up of it, bounded by the pattern\'s step, depth and DD limits; a tripped bound ends the run as a certified refusal.',
    inputSchema: { type: 'object', required: ['pattern'], properties: {
      pattern: { description: 'A pattern name, or a definition {steps, edges} (steps: engine + requisition template; edges: a result field → the next step\'s pool/premise/concern, with injection predetermined | gated)' },
      inputs: { type: 'object', description: 'Requisition fields for the first steps (pool, premise, concern, effort)' },
      delivery: DELIVERY,
      job_id: JOB_ID } } },
];
const pub = (p) => async () => { const r = await http('GET', (await endpoint()) + p); return r.status === 200 ? { ok: true, ...r.data } : { ok: false, http_status: r.status, ...(r.data || {}) }; };
const HANDLERS = {
  fleetengine_onboard: onboard,
  fleetengine_status: status,
  fleetengine_engines: pub('/v1/engines'),
  fleetengine_prices: pub('/v1/prices'),
  fleetengine_run: run,
  fleetengine_job: job,
  fleetengine_pattern_run: patternRun,
};

// Errors never carry the token: a ServiceError's body is DemiPass's answer, and our own errors name no secret.
function scrub(x) { const t = held && held.token; return t ? JSON.parse(JSON.stringify(x).split(t).join('[token]')) : x; }
function errBody(e) { return { ok: false, error: e.message, ...(e.result || {}), ...(e.body && typeof e.body === 'object' ? { demipass: e.body } : {}), ...(e.status ? { http_status: e.status } : {}) }; }

async function handleMessage(msg) {
  const { id, method, params } = msg;
  if (method === 'initialize') return { jsonrpc: '2.0', id, result: { protocolVersion: (params && params.protocolVersion) || '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'fleetengine', version: require('./package.json').version } } };
  if (method === 'notifications/initialized' || (method && method.startsWith('notifications/'))) return null;
  if (method === 'ping') return { jsonrpc: '2.0', id, result: {} };
  if (method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
  if (method === 'tools/call') {
    const h = HANDLERS[params && params.name];
    if (!h) return { jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${params && params.name}` } };
    let out; try { out = await h((params && params.arguments) || {}); } catch (e) { out = errBody(e); }
    out = scrub(out);
    return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }], ...(out && out.ok === false ? { isError: true } : {}) } };
  }
  if (id === undefined) return null;
  return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
}

module.exports = { handleMessage, _reset: () => { held = null; consentSeen = null; endpointCached = null; pendingCaps.clear(); } };

if (require.main === module) {
  // Messages are answered in order through one queue; stdin closing waits for the queue (a call in flight is answered).
  let buf = '', queue = Promise.resolve();
  const answer = line => async () => {
    let msg; try { msg = JSON.parse(line); if (!msg || typeof msg !== 'object' || Array.isArray(msg)) throw new Error('not a request'); } catch (_) { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n'); return; }
    const r = await handleMessage(msg).catch(e => ({ jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32603, message: String(scrub(e.message)) } }));
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
  process.stdin.on('end', () => { const last = buf.trim(); if (last) queue = queue.then(answer(last)); queue.then(() => process.exit(0)); });
  process.stdout.on('error', () => process.exit(0));
}
