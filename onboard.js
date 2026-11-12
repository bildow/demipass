#!/usr/bin/env node
'use strict';
/**
 * demipass-onboard — put an agent pane onto any DemiPass service (a "tenant": FLEETGATE, Conduit, …) in one step.
 *
 *   demipass-onboard <service> [--cap <DD per day>] [--mcp-config <path>] [--no-wait] [--approval <id>]
 *   demipass-onboard --list
 *
 * What it does, in order:
 *   1. Reads the service from DemiPass's registry (GET /api/services/<slug>): its name, prices, endpoint, and the MCP
 *      server agents attach with (`mcp_server`, "<npm package>#<bin>"). Nothing here hard-codes a service URL.
 *   2. Makes sure this wallet consents to pay it (services.ensureConsent). If not, the consent is filed as a request
 *      the person approves in the DemiPass app; the command waits for that tap (up to 15 min; --no-wait returns the
 *      approval id to pass back with --approval).
 *   3. Registers the service's MCP server in the MCP config (default ~/.mcp.json; one entry per service, idempotent,
 *      a 0600 .bak copy before any change). Only first-party servers: a bin of this demipass package, inside it
 *      (#17 review H1 — the server a tenant names is code run on this machine). The entry holds no session: the
 *      server reads this machine's live DemiPass session when it needs one (no copies to go stale or sprawl, M2).
 *      An existing entry of that name pointing elsewhere is never overwritten (M1). Every pane started afterwards has
 *      the tools; a running pane picks them up with /mcp (reconnect).
 *   4. Fleetgate checks free admission with a short-lived memory-only token. For normal calls, the service's MCP server mints its own (aud svc:<slug>), in memory, on first
 *      use, and re-mints on expiry. A token therefore never sits in a config file.
 *
 * Also exported for the demipass MCP tool `demipass_onboard_service`.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { services } = require('./services.js');

const API = (process.env.DEMIPASS_URL || 'https://api.dustforge.com').replace(/\/$/, '');
const DEFAULT_MCP_CONFIG = path.join(os.homedir(), '.mcp.json');
const SLUG_RE = /^[a-z][a-z0-9-]{1,30}$/;

// The MCP servers this package ships: the only bins a service may name (#87/#17 review: a CLI is not a server).
const MCP_BINS = new Set(['demipass-mcp', 'fleetgate-mcp']);
const didOf = (jwt) => { try { return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url').toString('utf8')).sub || null; } catch (_) { return null; } };

// This machine's DemiPass session: DEMIPASS_TOKEN, else the `demipass` entry of the MCP config (the one the entry was
// registered in: DEMIPASS_MCP_CONFIG), else the SDK login. With DEMIPASS_EXPECT_DID set (every entry onboarding
// writes), a session of any other wallet is refused: a service server pays as the wallet that onboarded it, never as
// whoever signs in later (#17 review M1).
function sessionToken(mcpConfig = process.env.DEMIPASS_MCP_CONFIG || DEFAULT_MCP_CONFIG) {
  const t = sessionTokenAny(mcpConfig);
  const want = process.env.DEMIPASS_EXPECT_DID;
  return want && t && didOf(t) !== want ? '' : t;
}
function sessionTokenAny(mcpConfig) {
  if (process.env.DEMIPASS_TOKEN) return process.env.DEMIPASS_TOKEN.trim();
  try { const c = JSON.parse(fs.readFileSync(mcpConfig, 'utf8')); const t = c.mcpServers && c.mcpServers.demipass && c.mcpServers.demipass.env && c.mcpServers.demipass.env.DEMIPASS_TOKEN; if (t) return t; } catch (_) {}
  try { const c = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.config', 'demipass', 'credentials.json'), 'utf8')); if (c && c.token) return c.token; } catch (_) {}
  return '';
}

async function getJson(url) {
  const r = await require('./http-json').requestJson('GET', url, { headers: { accept: 'application/json' }, timeoutMs: 15000 });
  const d = r.data;
  if (!r.ok) throw Object.assign(new Error(`${url}: HTTP ${r.status} ${(d && d.error) || ''}`.trim()), { status: r.status });
  return d;
}

// "<package>#<bin>" → the local file to run. First-party only: the package must be this demipass package and the
// bin one of its own files, inside it. Nothing else is resolved, and nothing is ever installed (#17 review H1).
function resolveMcpServer(spec) {
  const m = /^((?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*)#([a-z0-9][a-z0-9._-]*)$/.exec(String(spec || ''));
  if (!m) return null;
  const [, pkg, bin] = m;
  let own; try { own = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8')); } catch (_) { return { error: 'this package has no package.json' }; }
  if (own.name !== pkg) return { error: `${pkg}#${bin} is not a first-party DemiPass server; only ${own.name}#<bin> servers are attached` };
  if (!MCP_BINS.has(bin)) return { error: `${pkg}#${bin} is not one of its MCP servers (${[...MCP_BINS].join(', ')})` };
  const rel = own.bin && typeof own.bin === 'object' && Object.prototype.hasOwnProperty.call(own.bin, bin) && typeof own.bin[bin] === 'string' ? own.bin[bin] : null;
  if (!rel) return { error: `${pkg} has no bin "${bin}"` };
  const file = path.resolve(__dirname, rel);
  const inside = path.relative(__dirname, file);
  if (!inside || inside.startsWith('..') || path.isAbsolute(inside)) return { error: `${pkg}#${bin} points outside the package` };
  if (!fs.existsSync(file)) return { error: `${file} is missing` };
  return { file };
}

// Adds (or confirms) the MCP server entry for a service. No session goes into it: the server reads the live one.
function registerMcp({ slug, file, mcpConfig = DEFAULT_MCP_CONFIG, did }) {
  let cfg = { mcpServers: {} };
  const exists = fs.existsSync(mcpConfig);
  if (exists) mcpConfig = fs.realpathSync(mcpConfig);   // a symlinked config is updated where it lives, not replaced
  if (exists) cfg = JSON.parse(fs.readFileSync(mcpConfig, 'utf8'));
  cfg.mcpServers = cfg.mcpServers || {};
  // Already attached under any name (the same file): nothing to do. Conduit's tools, for one, live in the demipass server.
  const write = () => {
    if (exists) { fs.copyFileSync(mcpConfig, mcpConfig + '.bak'); fs.chmodSync(mcpConfig + '.bak', 0o600); }
    const tmp = mcpConfig + '.tmp-' + process.pid;
    fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, mcpConfig);
  };
  const isMain = path.basename(file) === 'mcp-server.js';   // the demipass server itself runs on the session it is given
  for (const [name, e] of Object.entries(cfg.mcpServers)) {
    if (e && Array.isArray(e.args) && e.args.some(a => path.resolve(String(a)) === file)) {
      // A service entry from before (#17 round 1) may still hold a copied session: drop it (#17 review M2).
      if (!isMain && e.env && e.env.DEMIPASS_TOKEN) {
        delete e.env.DEMIPASS_TOKEN;
        Object.assign(e.env, { DEMIPASS_MCP_CONFIG: mcpConfig, ...(did ? { DEMIPASS_EXPECT_DID: did } : {}) });
        write(); return { changed: true, name, stripped_session_copy: true };
      }
      // Pinned to another wallet (another pane onboarded here first): never re-pinned silently, and never reported as
      // attached for this one — its sessions would be refused (#17 review round 4).
      const pinned = e.env && e.env.DEMIPASS_EXPECT_DID;
      if (!isMain && did && pinned && pinned !== did) {
        return { changed: false, name, error: `the "${name}" entry in ${mcpConfig} is pinned to wallet ${pinned}, not ${did}: it serves that wallet only. Add a separate entry for this wallet (a copy under another name with DEMIPASS_EXPECT_DID=${did}), or remove the old one if that wallet no longer uses this machine.` };
      }
      return { changed: false, name };
    }
  }
  // A different server already under this name (a tenant slug like "kodiak" or "brain"): never overwritten (#17 M1).
  if (cfg.mcpServers[slug]) return { changed: false, name: slug, error: `an MCP server named "${slug}" already exists in ${mcpConfig} and runs something else; not replaced` };
  cfg.mcpServers[slug] = { command: process.execPath, args: [file],
    env: { DEMIPASS_URL: API, DEMIPASS_MCP_CONFIG: mcpConfig, ...(did ? { DEMIPASS_EXPECT_DID: did } : {}) } };
  write();
  return { changed: true, name: slug };
}

// A standing consent of at least `cap` DD a day. An existing smaller one is replaced only when a higher cap is asked
// for explicitly: that files a new consent for the person to approve (ensureConsent alone would return the old one).
async function consentAtLeast(dp, { service, cap, explicit, approvalId }) {
  const c = await dp.ensureConsent({ service, dailyCapDd: cap, approvalId });
  if (c.pending || !explicit || c.consent.daily_cap_dd >= cap) return c;
  try { const r = await dp.consent({ service, dailyCapDd: cap, approvalId }); return { consent: { id: r.consent_id, service: r.service, daily_cap_dd: r.daily_cap_dd, status: 'active' }, existing: false }; }
  catch (e) {
    if (!e.pending) throw e;
    return { pending: { approval_id: e.body.approval_id, expires_at: e.body.expires_at || null, daily_cap_dd: cap, replaces: c.consent.id } };
  }
}

async function onboardService({ service, capDd, approvalId, wait = true, waitMs = 15 * 60 * 1000, mcpConfig = DEFAULT_MCP_CONFIG, register = true, log = () => {} } = {}) {
  const slug = String(service || '').toLowerCase();
  if (!SLUG_RE.test(slug)) return { ok: false, error: 'service: a registered service slug (demipass-onboard --list)' };
  let t;
  try { t = await getJson(`${API}/api/services/${slug}`); }
  catch (e) { return { ok: false, error: e.status === 404 ? `no service "${slug}" (demipass-onboard --list)` : e.message }; }
  const token = sessionTokenAny(mcpConfig);
  if (!token) return { ok: false, error: 'no DemiPass session on this machine: sign in first (demipass_login, or set DEMIPASS_TOKEN)' };
  const dp = services({ token, baseUrl: API });

  // One call must fit the daily consent: default to 5 of the dearest open action, at least 300 and at most 10,000 DD
  // (a tenant's prices never make the default ask for more; above it, the person passes --cap; #17 review L).
  const dearest = Math.max(0, ...(t.actions || []).filter(a => a.open).map(a => a.max_price_dd || a.price_dd || 0));
  const cap = capDd || Math.min(10000, Math.max(300, dearest * 5));
  const ask = (id) => consentAtLeast(dp, { service: slug, cap, explicit: Boolean(capDd), approvalId: id });
  let c = await ask(approvalId);
  if (c.pending && wait) {
    log(`Approve "let a wallet pay ${slug}" (${cap} DD/day) in the DemiPass app — waiting (approval ${c.pending.approval_id})…`);
    const id = c.pending.approval_id, until = Date.now() + waitMs;
    while (c.pending && Date.now() < until) {
      await new Promise(ok => setTimeout(ok, 5000));
      try { c = await ask(id); }
      catch (e) { if (e.status === 410 || e.status === 403) return { ok: false, error: `approval ${id}: ${e.message}` }; throw e; }
    }
  }
  if (c.pending) return { ok: false, status: 'approval_pending', service: slug, approval_id: c.pending.approval_id, daily_cap_dd: cap,
    next: `Approve it in the DemiPass app, then call again with approval_id ${c.pending.approval_id} and daily_cap_dd ${cap} (CLI: demipass-onboard ${slug} --cap ${cap} --approval ${c.pending.approval_id})` };
  const intake = slug === 'fleetgate' ? ((t.actions || []).find(a => a.action === 'submit') || {}).price_dd : dearest;
  const low = intake && c.consent.daily_cap_dd < intake;

  let mcp = { attached: false, reason: 'the service names no MCP server yet (its owner sets mcp_server)' };
  if (t.mcp_server && register) {
    const r = resolveMcpServer(t.mcp_server);
    if (!r || r.error) mcp = { attached: false, reason: r ? r.error : `bad mcp_server "${t.mcp_server}"` };
    else { const g = registerMcp({ slug, file: r.file, mcpConfig, did: didOf(token) }); mcp = g.error ? { attached: false, reason: g.error } : { attached: true, config: mcpConfig, entry: g.name, changed: g.changed }; }
  }
  let readiness = null;
  if (slug === 'fleetgate') {
    // The old generic setup returned success for payment consent even when the submitting bot had no lane.
    // A short-lived, memory-only service token checks the real door; never send the wallet session there.
    const probe = await dp.mintToken({ service: slug, ttl: '5m', followUpDd: c.consent.daily_cap_dd });
    readiness = await require('./fleetgate-admission').fleetgateAdmission({ endpoint: t.endpoint, token: probe.token, wallet: didOf(token) });
    if (!readiness.ok) return { ...readiness, service: slug, mcp, consent: { id: c.consent.id, daily_cap_dd: c.consent.daily_cap_dd } };
  }
  return { ok: true, service: slug, name: t.name, endpoint: t.endpoint || null, ...(readiness ? { admission: readiness.admission } : {}),
    consent: { id: c.consent.id, daily_cap_dd: c.consent.daily_cap_dd, existing: Boolean(c.existing) }, mcp,
    ...(low ? { warning: `the daily consent (${c.consent.daily_cap_dd} DD) is below one ${slug} call (${intake} DD); call again with a higher daily_cap_dd (--cap) to file a replacement for approval` } : {}),
    next: mcp.attached ? (mcp.changed ? 'New panes have the tools. In a running pane: /mcp → reconnect.' : 'Already attached; nothing to restart.') : 'Consent is in place.' };
}

async function listServices() {
  const d = await getJson(`${API}/api/services`);
  return d.tenants.map(t => ({ service: t.slug, name: t.name, endpoint: t.endpoint || null, mcp_server: t.mcp_server || null,
    prices: Object.fromEntries((t.actions || []).filter(a => a.open).map(a => [a.action, a.price_dd])) }));
}

module.exports = { onboardService, listServices, resolveMcpServer, registerMcp, sessionToken, consentAtLeast };

if (require.main === module) {
  const a = process.argv.slice(2);
  const opt = (n) => { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : undefined; };
  (async () => {
    if (a[0] === '--list' || !a[0]) { console.log(JSON.stringify(await listServices(), null, 2)); return; }
    const r = await onboardService({ service: a[0], capDd: opt('--cap') ? Number(opt('--cap')) : undefined, approvalId: opt('--approval') ? Number(opt('--approval')) : undefined,
      wait: !a.includes('--no-wait'), mcpConfig: opt('--mcp-config') || DEFAULT_MCP_CONFIG, log: m => console.error(m) });
    console.log(JSON.stringify(r, null, 2));
    process.exit(r.ok ? 0 : (r.status === 'approval_pending' ? 3 : 1));
  })().catch(e => { console.error('demipass-onboard:', e.message); process.exit(1); });
}
