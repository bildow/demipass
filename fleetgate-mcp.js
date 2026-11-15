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
 *   fleetgate_submit({repo, title, files | git, body?, submission_id?, supersedes?})   one PR into atlas/<repo>; intake charged
 *                                                       once; review calls metered separately. git: {dir, ref, base} reads the changed files
 *                                                       from the pane's own checkout; supersedes closes its own earlier submission
 *   fleetgate_status()                                  onboarded? token expiry, consent, door health, lanes, spend
 *   fleetgate_check({repo, paths})                      free: would these paths be admitted, in which lane, or why not
 *   fleetgate_follow({repo, submission_id})             free: this wallet's submission as the release controller sees it
 *                                                       now (every check, each reviewer seat) and the one next step
 *
 * The gate decides: a submitted PR is evaluated by the release controller under the signed charter like any other.
 * Nothing here merges, approves, reviews or touches a charter.
 *
 * Env: DEMIPASS_TOKEN (this pane's DemiPass session), DEMIPASS_URL, FLEETGATE_DOOR_URL
 *      (default https://repo.dustroot.com/-/fleetgate/door), FLEETGATE_DAILY_CAP_DD (default 3000).
 */
const crypto = require('crypto');
const path = require('path');
const { execFileSync } = require('child_process');
const { services } = require('./services.js');
// This machine's live DemiPass session (DEMIPASS_TOKEN, else the demipass MCP entry, else the SDK login), read each
// time it is needed: the MCP config entry holds no copy of it (#17 review M2).
const { sessionToken, consentAtLeast } = require('./onboard.js');
const { fleetgateAdmission } = require('./fleetgate-admission.js');

const DEMIPASS_URL = (process.env.DEMIPASS_URL || 'https://api.dustforge.com').replace(/\/$/, '');
const DOOR_DEFAULT = 'https://repo.dustroot.com/-/fleetgate/door';
// The door: FLEETGATE_DOOR_URL, else the endpoint FLEETGATE registered with DemiPass (GET /api/services/fleetgate),
// else the default. https only, except a loopback host (tests) — the service token goes there (#17 review L2).
function doorRefusal(u) {
  let x; try { x = new URL(u); } catch (_) { return 'not a URL'; }
  if (x.protocol === 'https:') return null;
  if (x.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(x.hostname)) return null;
  return 'the door must be https';
}
let doorCached = null;
async function door() {
  if (doorCached) return doorCached;
  let u = process.env.FLEETGATE_DOOR_URL || '';
  if (!u) { try { const r = await http('GET', DEMIPASS_URL + '/api/services/fleetgate'); if (r.status === 200 && r.data && r.data.endpoint) u = r.data.endpoint; } catch (_) {} }
  u = (u || DOOR_DEFAULT).replace(/\/+$/, '');
  const bad = doorRefusal(u); if (bad) throw new Error(`FLEETGATE door ${u}: ${bad}`);
  return (doorCached = u);
}
const DEFAULT_CAP = Number(process.env.FLEETGATE_DAILY_CAP_DD || 3000);   // preserved default ceiling; an existing smaller consent is never silently raised
const SERVICE = 'fleetgate';

function dp(token = sessionToken()) { return services({ token, baseUrl: DEMIPASS_URL }); }

// The service token: memory only.
let held = null;   // { token, token_id, expires_at, cap_dd }
let consentSeen = null;
let admissionSeen = null;
const pendingCaps = new Map();   // approval_id → the daily cap asked for: redeeming must repeat it (#17 review L4)
// Token check before holding it: what the door accepts, so a malformed mint can never end up in a header error (L1).
const TOKEN_RE = /^[A-Za-z0-9_.-]{20,4096}$/;
// The wallet the live session is for (the JWT's sub). A held token is used only by that same wallet: if the machine's
// session changes to another wallet while this server runs, the held token is dropped and one is minted for the new
// wallet (#17 review round 2, P1).
const subOf = (t) => { try { return t ? JSON.parse(Buffer.from(String(t).split('.')[1], 'base64url').toString()).sub || null : null; } catch (_) { return null; } };
const sessionSub = () => subOf(sessionToken());
// Kept for its wallet, never used for another (no re-mint, no extra charge, when that wallet's session comes back).
const live = () => { if (!held) return false; const me = sessionSub(); if (!me || me !== held.wallet) return false; return Date.parse(held.expires_at) - Date.now() > 60 * 1000; };

async function onboard({ daily_cap_dd, approval_id } = {}, { fileConsent = true } = {}) {
  // One session for the whole onboarding: the token is minted with it and held for its wallet, even if the machine's
  // session changes while this runs (#17 review round 3).
  const session = sessionToken();
  const api = dp(session), wallet = subOf(session);
  if (!session) return { ok: false, error: process.env.DEMIPASS_EXPECT_DID ? `no DemiPass session for ${process.env.DEMIPASS_EXPECT_DID} (the wallet this server was onboarded as) on this machine` : 'no DemiPass session on this machine: sign in first (demipass_login, or set DEMIPASS_TOKEN)' };
  if (approval_id && !daily_cap_dd && pendingCaps.has(Number(approval_id))) daily_cap_dd = pendingCaps.get(Number(approval_id));
  let c;
  if (!fileConsent) {
    // Submitting (and the free tools) never file a consent (#17 review L3): after a person said no, a submit must not ask
    // their phone again. The active consent found here is used as it is; consentAtLeast is never called on this path,
    // since it reads again and could file one if the consent were revoked in between (#27 independent review, 2).
    const all = await api.consents();
    const mine = (all.mine || []).find(x => x.service === SERVICE && x.status === 'active');
    if (!mine) return { ok: false, status: 'not_onboarded', error: 'not onboarded: run fleetgate_onboard and approve it in the DemiPass app' };
    c = { consent: mine, existing: true };
  } else {
    // services().onboard's two steps; the token carries a follow-up budget so the submission's review rounds can bill.
    c = await consentAtLeast(api, { service: SERVICE, cap: daily_cap_dd || DEFAULT_CAP, explicit: Boolean(daily_cap_dd), approvalId: approval_id });
  }
  let r = c;
  if (!c.pending) {
    // Ordinary charges (the door's intake) stay under the server's default cap; the review rounds a submission starts
    // bill afterwards against the follow-up budget, up to the whole daily consent (the door needs at least ~one round).
    const t = await api.mintToken({ service: SERVICE, ttl: '24h', followUpDd: c.consent.daily_cap_dd });
    r = { consent: c.consent, existing: c.existing, token: { token: t.token, token_id: t.token_id, expires_at: t.expires_at, cap_dd: t.cap_dd } };
  }
  if (r.pending) {
    pendingCaps.set(Number(r.pending.approval_id), r.pending.daily_cap_dd);
    return { ok: false, status: 'approval_pending', approval_id: r.pending.approval_id, expires_at: r.pending.expires_at, daily_cap_dd: r.pending.daily_cap_dd,
             next: `Approve "let a wallet pay fleetgate" (${r.pending.daily_cap_dd} DD/day) in the DemiPass app (Requests), then call fleetgate_onboard again with approval_id ${r.pending.approval_id} and daily_cap_dd ${r.pending.daily_cap_dd}.` };
  }
  if (!TOKEN_RE.test(String(r.token.token || ''))) return { ok: false, error: 'DemiPass returned a malformed service token; not held' };
  const ready = await fleetgateAdmission({ endpoint: await door(), token: r.token.token, wallet });
  // A refused admission drops the token just minted; anything the door said is scrubbed of it first, since scrub() at the
  // end only knows a held token (#27 independent review, 1).
  if (!ready.ok) { held = null; admissionSeen = null; return redact({ ...ready, consent: { id: r.consent.id, daily_cap_dd: r.consent.daily_cap_dd } }, r.token.token); }
  admissionSeen = ready.admission;
  held = { token: r.token.token, token_id: r.token.token_id, expires_at: r.token.expires_at, cap_dd: r.token.cap_dd, wallet };
  consentSeen = r.consent || consentSeen;
  const price = await submitPrice();
  const low = price && r.consent && r.consent.daily_cap_dd < price;
  // Spend only if the session still belongs to the wallet this onboarding started with (#27 independent review r2, 2).
  return { ok: true, service: SERVICE, admission: admissionSeen, ...(ready.spend && sessionSub() === wallet ? { spend: ready.spend } : {}), consent: r.consent ? { id: r.consent.id, daily_cap_dd: r.consent.daily_cap_dd, existing: Boolean(r.existing) } : null,
           token_id: held.token_id, expires_at: held.expires_at, cap_dd: held.cap_dd,
           ...(low ? { warning: `your daily consent (${r.consent.daily_cap_dd} DD) is below one submission (${price} DD): every submit would be refused. Call fleetgate_onboard with a higher daily_cap_dd to replace it (one approval).` } : {}) };
}

// A live token, minting one when the consent already exists; an onboarding that needs an approval is reported, not waited on.
async function submitPrice() {
  try { const r = await http('GET', (await door()) + '/v1/prices'); const a = ((r.data && r.data.actions) || []); return a.filter(x => x.action === 'submit').reduce((n, x) => n + (x.price_dd || 0), 0) || null; }
  catch (_) { return null; }
}
async function token() {
  if (live()) return held.token;
  const r = await onboard({}, { fileConsent: false });
  if (!r.ok) throw Object.assign(new Error(r.error || 'not onboarded: run fleetgate_onboard and approve it in the DemiPass app'), { result: r });
  return held.token;
}

async function http(method, url, { auth, body } = {}) {
  const headers = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (auth) headers.authorization = 'Bearer ' + auth;
  const r = await require('./http-json').requestJson(method, url, { headers, body, timeoutMs: 180000 });
  // The bearer this request carried is redacted from the answer BEFORE a raw (non-JSON) body is cut to 500 characters:
  // cutting first could leave a token prefix that the later scrub no longer recognises (#27 independent review r3).
  const data = redact(r.data !== null ? r.data : { raw: r.text }, auth);
  if (data && typeof data.raw === 'string') data.raw = data.raw.slice(0, 500);
  return { status: r.status, data };
}

const SUBMISSION_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;   // ids this MCP makes or takes for a new submission (the door accepts 6+)
const MAX_REQUEST = 512 * 1024;                               // the door's MAX_BODY and its proxy's client_max_body_size
// The door's own limits (fleet/door/door.js): checked here too, so a git source too large is refused before a charge.
const MAX_FILES = 20, MAX_FILE = 128 * 1024, MAX_TOTAL = 384 * 1024;
// A ref is a branch, tag or commit: never an option (no leading '-'), no range or reflog syntax.
const GIT_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/;

// The submission's files from the pane's own git checkout: every path that differs between the merge base of `base`
// and `ref`, with its whole content at `ref`. The door can only create or replace UTF-8 text files, so a delete (or
// a rename, which is a delete), a symlink, a submodule, a binary or non-UTF-8 file is refused, naming it. git runs
// without a shell; nothing in the checkout is executed. → { files, head, merge_base, subject } | { error }
// The checkout's top level exactly as git prints it: only git's terminating newline is removed (a trim could turn
// "/work/project " into another checkout, "/work/project"), and a root that isn't valid UTF-8 is refused
// (#28 independent review round 2, 2).
// Every git call reads the objects as committed and never touches the network: replace refs off (#28 independent review
// round 3, 1), the legacy grafts file pointed at /dev/null and lazy fetching off for partial clones (round 4), and no
// GIT_* variable from this process's environment (GIT_DIR, GIT_OBJECT_DIRECTORY, GIT_REPLACE_REF_BASE…) redirects it.
// An object a partial clone doesn't have is then a local error, refused like any other. No program named by the
// checkout's own config runs: signature verification (log.showSignature → gpg.program, round 5), fsmonitor hooks,
// textconv and external diff drivers are all off. A shallow checkout is refused: its synthetic boundaries move the
// merge base (round 5).
const GIT_FIXED = ['--no-replace-objects', '--no-lazy-fetch', '-c', 'log.showSignature=false', '-c', 'core.fsmonitor=false',
  '-c', 'diff.external=', '-c', 'core.hooksPath=/dev/null'];
function gitEnv() {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith('GIT_')) env[k] = v;
  return { ...env, GIT_NO_REPLACE_OBJECTS: '1', GIT_GRAFT_FILE: '/dev/null', GIT_NO_LAZY_FETCH: '1', GIT_TERMINAL_PROMPT: '0' };
}
// The door's own path rule (fleet/door/door.js PATH_RE): ASCII letters, digits, . _ - /; at most 200 characters; no
// leading slash, dot segment or empty segment. Refused here, before anything is sent (#28 independent review round 3, 2).
const DOOR_PATH_RE = /^(?!\/)(?!.*(^|\/)\.)(?!.*\/\/)[A-Za-z0-9._\-/]{1,200}$/;

// --no-lazy-fetch (and GIT_NO_LAZY_FETCH) need git 2.45; an older git would fail every call with an unhelpful
// "unknown option", so the version is checked once and named (round 7, non-blocking).
let gitVersionError;
function gitTooOld() {
  if (gitVersionError === null) return null;   // only a passing check is kept: an upgrade takes effect without a restart
  let err;
  try {
    const m = /git version (\d+)\.(\d+)/.exec(execFileSync('git', ['--version'], { env: gitEnv(), timeout: 10000 }).toString());
    err = !m ? 'git: could not read git\'s version' : (+m[1] > 2 || (+m[1] === 2 && +m[2] >= 45)) ? null
      : `git: version ${m[1]}.${m[2]} is too old; reading a checkout safely needs git 2.45 or newer (--no-lazy-fetch). Upgrade git, or send files instead.`;
  } catch (_) { err = 'git: not found on this machine; send files instead'; }
  if (err === null) gitVersionError = null;
  return err;
}

function topLevel(run) {
  const b = run('rev-parse', '--show-toplevel');
  const raw = b.subarray(0, b.length && b[b.length - 1] === 0x0a ? b.length - 1 : b.length);
  const dir = raw.toString('utf8');
  if (!dir || !Buffer.from(dir, 'utf8').equals(raw) || !path.isAbsolute(dir)) return { error: 'git: the checkout\'s top-level path is not plain UTF-8' };
  return { dir };
}

function filesFromGit(g) {
  if (!g || typeof g !== 'object' || Array.isArray(g)) return { error: 'git: {dir, ref?, base?}' };
  const { dir, ref = 'HEAD', base = 'origin/main' } = g;
  for (const k of Object.keys(g)) if (!['dir', 'ref', 'base'].includes(k)) return { error: `git: unknown field ${k}` };
  if (typeof dir !== 'string' || !path.isAbsolute(dir)) return { error: 'git.dir: the absolute path of your checkout' };
  for (const [k, v] of [['ref', ref], ['base', base]])
    if (typeof v !== 'string' || !GIT_REF_RE.test(v) || v.includes('..') || v.endsWith('.lock')) return { error: `git.${k}: a branch, tag or commit name` };
  if (gitTooOld()) return { error: gitTooOld() };
  // Run at the repository's top level with diff.relative off: a user's git config must not narrow or re-root the change
  // (#28 independent review, 1).
  const at = (cwd) => (...args) => execFileSync('git', [...GIT_FIXED, '-C', cwd, '-c', 'diff.relative=false', '-c', 'diff.ignoreSubmodules=none', ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: gitEnv(), maxBuffer: 16 << 20, timeout: 30000 });
  let run, head, mb, listing;
  try {
    const top = topLevel(at(dir));
    if (top.error) return top;
    run = at(top.dir);
    if (run('rev-parse', '--is-shallow-repository').toString().trim() !== 'false')
      return { error: 'git: this checkout is shallow, so its merge base can\'t be trusted; fetch the full history first (git fetch --unshallow)' };
    head = run('rev-parse', '--verify', '--end-of-options', `${ref}^{commit}`).toString().trim();
    const b = run('rev-parse', '--verify', '--end-of-options', `${base}^{commit}`).toString().trim();
    mb = run('merge-base', b, head).toString().trim();
    listing = run('diff', '--raw', '-z', '--no-renames', '--no-relative', '--ignore-submodules=none', '--no-abbrev', mb, head);
  } catch (e) {
    return { error: `git: ${(String(e.stderr || e.message).trim().split('\n').pop() || 'failed').slice(0, 300)}` };
  }
  // --raw -z: ":<old mode> <new mode> <old sha> <new sha> <status>\0<path>\0" per path, parsed as bytes: a path that is
  // not valid UTF-8 is refused here, never decoded with replacement characters (#28 independent review, 3).
  const parts = [];
  for (let at0 = 0; at0 < listing.length;) { const z = listing.indexOf(0, at0); if (z < 0) break; if (z > at0) parts.push(listing.subarray(at0, z)); at0 = z + 1; }
  const files = [], refused = [];
  for (let i = 0; i + 1 < parts.length; i += 2) {
    const meta = parts[i].toString('latin1').replace(/^:/, '').split(' ');
    const pb = parts[i + 1], p = pb.toString('utf8');
    if (!Buffer.from(p, 'utf8').equals(pb)) { refused.push(`${pb.toString('latin1').replace(/[^\x20-\x7e]/g, '?')}: the path is not UTF-8`); continue; }
    const [oldMode, newMode, , newSha, status] = meta;
    if (status === 'D') { refused.push(`${p}: deleted (the door can't delete or rename files)`); continue; }
    if (!DOOR_PATH_RE.test(p)) { refused.push(`${p.slice(0, 220)}: the door takes paths of ASCII letters, digits, . _ - and /, up to 200 characters, with no dot-file or dot-directory`); continue; }
    if (!['A', 'M'].includes(status)) { refused.push(`${p}: ${status === 'T' ? 'its type changed' : status} (the door writes regular files only)`); continue; }
    // The door writes plain 100644 files: an executable, a symlink, a submodule or any mode change can't be reproduced
    // (#28 independent review, 2).
    if (newMode !== '100644') { refused.push(`${p}: mode ${newMode} (the door writes regular, non-executable files only)`); continue; }
    if (status === 'M' && oldMode !== '100644') { refused.push(`${p}: mode ${oldMode} → ${newMode} (a mode change can't go through the door)`); continue; }
    let buf;
    try { buf = run('cat-file', 'blob', newSha); }
    catch (_) { refused.push(`${p}: its content isn't in this checkout (a partial clone?); fetch it first`); continue; }
    const text = buf.toString('utf8');
    if (buf.includes(0) || !Buffer.from(text, 'utf8').equals(buf)) { refused.push(`${p}: not UTF-8 text`); continue; }
    if (buf.length > MAX_FILE) { refused.push(`${p}: ${buf.length} bytes, over ${MAX_FILE}`); continue; }
    files.push({ path: p, content: text });
  }
  if (refused.length) return { error: `git: ${refused.length} path(s) can't be submitted: ${refused.slice(0, 10).join('; ')}`, refused };
  if (!files.length) return { error: `git: no changes between the merge base ${mb.slice(0, 12)} and ${ref}` };
  if (files.length > MAX_FILES) return { error: `git: ${files.length} changed files, over ${MAX_FILES}` };
  const total = files.reduce((n, f) => n + Buffer.byteLength(f.content, 'utf8'), 0);
  if (total > MAX_TOTAL) return { error: `git: ${total} bytes in all, over ${MAX_TOTAL}` };
  return { files, head, merge_base: mb, subject: run('log', '-1', '--no-show-signature', '--format=%s', head).toString().trim() };
}

async function submit({ repo, title, body, files, git, submission_id, supersedes }) {
  if (typeof repo !== 'string' || !/^[A-Za-z0-9._-]{1,100}$/.test(repo)) return { ok: false, error: 'repo: the name of a repo under atlas/ (e.g. boltcluster)' };
  if (files !== undefined && git !== undefined) return { ok: false, error: 'files or git, not both' };
  let source = null;
  if (git !== undefined) {
    const g = filesFromGit(git);
    if (g.error) return { ok: false, error: g.error, ...(g.refused ? { refused: g.refused } : {}), note: 'Nothing was sent or charged.' };
    files = g.files; source = g;
    if (!title) title = g.subject;
    body = [body || '', '', `From git: \`${g.head.slice(0, 12)}\` over merge base \`${g.merge_base.slice(0, 12)}\` (${g.files.length} files).`].join('\n').trim();
  }
  if (!title) return { ok: false, error: 'title required' };
  if (!Array.isArray(files) || !files.length) return { ok: false, error: 'files: [{path, content}] (the whole new content of each file), or git: {dir, ref, base}' };
  // An earlier submission may have been made directly at the door, whose ids start at 6 characters (round 6, 2).
  if (supersedes !== undefined && (typeof supersedes !== 'string' || !FOLLOW_ID_RE.test(supersedes))) return { ok: false, error: 'supersedes: the submission_id of your own earlier submission to this repo' };
  const sid = submission_id || crypto.randomBytes(12).toString('hex');
  if (!SUBMISSION_RE.test(sid)) return { ok: false, error: 'submission_id: 8-64 letters, digits, _ or -, starting with a letter or digit' };
  if (supersedes !== undefined && supersedes === sid) return { ok: false, error: 'supersedes: an earlier submission, not this one' };
  const payload = { submission_id: sid, repo, title, ...(body ? { body } : {}), files, ...(supersedes !== undefined ? { supersedes } : {}) };
  // The door (and its proxy) refuse a request body over 512 KiB; JSON escaping can grow content well past its own size
  // (a backslash doubles), so the serialized request is measured here, before anything is sent (round 6, 1).
  const wire = Buffer.byteLength(JSON.stringify(payload), 'utf8');
  if (wire > MAX_REQUEST) return { ok: false, error: `the request would be ${wire} bytes once encoded, over the door's ${MAX_REQUEST}; submit fewer or smaller files`, note: 'Nothing was sent or charged.' };
  const url = (await door()) + '/v1/pulls';
  // Minting is DemiPass's answer, not the door's: its refusal (an expired session, no consent) comes back as it is, with
  // the submission id, and says the door was not contacted (#17 review round 5).
  const mint = async () => { try { return { auth: await token() }; } catch (e) { return { refused: { ...errBody(e), submission_id: sid, note: 'DemiPass refused the token; nothing was sent to the door.' } }; } };
  let r;
  let m = await mint(); if (m.refused) return m.refused;
  try {
    r = await http('POST', url, { auth: m.auth, body: payload });
    if (r.status === 401) {   // expired or revoked: re-mint once
      held = null; m = await mint(); if (m.refused) return m.refused;
      r = await http('POST', url, { auth: m.auth, body: payload });
    }
  } catch (e) {
    // The door may have charged before the connection dropped: hand back the id, so the retry replays (#17 review H1).
    if (e.result) return { ...e.result, submission_id: sid };
    return { ok: false, submission_id: sid, error: e.name === 'TimeoutError' ? 'the door timed out' : 'the door could not be reached',
             next: `Retry fleetgate_submit with submission_id "${sid}": if the door already charged, it replays that charge and finds the PR.` };
  }
  if (r.status === 201) return { ok: true, submission_id: sid, ...r.data, ...(source ? { from_git: { head: source.head, merge_base: source.merge_base, files: source.files.map(f => f.path) } } : {}), note: 'The release controller evaluates it under the signed charter. A retry with the same submission_id replays, never double-charges.',
    next: `fleetgate_follow {repo: "${repo}", submission_id: "${sid}"} shows what the gate is waiting for, and on whom (free).` };
  return { ok: false, http_status: r.status, submission_id: sid, ...(r.data || {}),
           ...(r.status === 402 ? { hint: 'DemiPass refused the charge: no consent, not enough DD, or a cap. Nothing was created.' } : {}) };
}

async function status() {
  const health = await http('GET', (await door()) + '/health').catch(e => ({ status: 0, data: { error: e.message } }));
  let ready;
  try {
    // Existing users self-reconcile on their next status call without filing consent or spending.
    ready = held && held.wallet !== sessionSub() ? { ok:false, status:'wallet_changed', error:'The held token belongs to another wallet; onboard explicitly' } : live() ? await fleetgateAdmission({ endpoint: await door(), token: held.token, wallet: held.wallet }) : await onboard({}, { fileConsent: false });
  } catch (e) { ready = errBody(e); }
  admissionSeen = ready.ok ? ready.admission : null;
  return { ok: health.status === 200 && health.data && health.data.ok === true && Boolean(ready.ok), door: await door(),
    door_health: health.status === 200 ? health.data : { http_status: health.status, ...(health.data || {}) },
    onboarded: Boolean(live() && ready.ok), admission: admissionSeen, ...(ready.ok ? {} : { readiness: ready }),
    token_id: live() ? held.token_id : null, expires_at: live() ? held.expires_at : null,
    consent: consentSeen ? { id: consentSeen.id, daily_cap_dd: consentSeen.daily_cap_dd } : null,
    // Spend only as this very call's admission check verified it, and only if the held token still belongs to the
    // session's wallet once that check returns: never a cached figure (Codex connector P2 on #27), never across a switch
    // made while the check was in flight (#27 independent review, 3).
    ...(ready.ok && ready.spend && live() ? { spend: ready.spend } : {}),
    ...(admissionSeen ? { next: 'Before building, fleetgate_check {repo, paths} says whether the paths would be admitted (free).' } : {}) };
}

// One authenticated call to a free door route, re-minting once on 401 (as submit does). Never charges. The call is bound
// to the wallet the machine's session names when it starts: if the session switches wallets before the request is
// sent, before the retry, or before the answer is shown, nothing from the door is returned (#27 independent review r2, 1).
const SWITCHED = { refused: { ok: false, status: 'wallet_changed', error: 'the DemiPass session on this machine switched wallets during this call; nothing from it is shown. Call again.' } };
async function doorCall(method, route, body) {
  const me = sessionSub();
  if (!me) return { refused: { ok: false, error: 'no DemiPass session on this machine: sign in first (demipass_login, or set DEMIPASS_TOKEN)' } };
  const mine = () => held && held.wallet === me && sessionSub() === me;
  let auth;
  try { auth = await token(); } catch (e) {
    const b = errBody(e);
    // A door without /v1/onboard (older than fleetgate-door/2) refuses admission with a 404 (#27 independent review, 5).
    if (b.status === 'admission_required' && b.http_status === 404) return { refused: { ok: false, error: 'this door predates admission, follow and path checks (fleetgate-door/3)' } };
    return { refused: b };
  }
  if (!mine()) return SWITCHED;
  const url = (await door()) + route;
  try {
    let r = await http(method, url, { auth, body });
    if (r.status === 401) {
      held = null;
      try { auth = await token(); } catch (e) { return { refused: errBody(e) }; }
      if (!mine()) return SWITCHED;
      r = await http(method, url, { auth, body });
    }
    if (sessionSub() !== me) return SWITCHED;
    return { r };
  } catch (e) {
    return { refused: { ok: false, error: e.name === 'TimeoutError' ? 'the door timed out' : 'the door could not be reached' } };
  }
}
// A door older than fleetgate-door/3 answers its plain 404 {route}; say so instead of passing a bare "not found" on.
const OLD_DOOR = (r) => r.status === 404 && r.data && r.data.route && !r.data.code;
const FOLLOW_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{5,63}$/;   // the door's own submission pattern

async function check({ repo, paths }) {
  if (typeof repo !== 'string' || !/^[A-Za-z0-9._-]{1,100}$/.test(repo)) return { ok: false, error: 'repo: the name of a repo under atlas/ (e.g. boltcluster)' };
  if (!Array.isArray(paths) || !paths.length || paths.length > 20 || !paths.every(x => typeof x === 'string' && x.length && x.length <= 200))
    return { ok: false, error: 'paths: 1-20 repository paths, e.g. ["docs/notes.md", "tests/new.test.js"]' };
  const { r, refused } = await doorCall('POST', '/v1/check', { repo, paths });
  if (refused) return refused;
  if (OLD_DOOR(r)) return { ok: false, error: 'this door predates path checks (fleetgate-door/3); fleetgate_status lists the lanes to compare by hand' };
  if (r.status === 200) return { ...r.data, ...(r.data.ok ? { next: 'Every path is admitted in one lane: fleetgate_submit with these paths.' } : {}) };
  return { ok: false, http_status: r.status, ...(r.data || {}) };
}

async function follow({ repo, submission_id }) {
  if (typeof repo !== 'string' || !/^[A-Za-z0-9._-]{1,100}$/.test(repo)) return { ok: false, error: 'repo: the repo under atlas/ you submitted to (e.g. boltcluster)' };
  if (typeof submission_id !== 'string' || !FOLLOW_ID_RE.test(submission_id)) return { ok: false, error: 'submission_id: the one fleetgate_submit returned' };
  const { r, refused } = await doorCall('GET', `/v1/pulls/${encodeURIComponent(repo)}/${encodeURIComponent(submission_id)}`);
  if (refused) return refused;
  if (OLD_DOOR(r)) return { ok: false, error: 'this door predates following a submission (fleetgate-door/3)' };
  if (r.status === 200) return r.data;
  if (r.status === 404) return { ok: false, http_status: 404, ...(r.data || {}), hint: 'Only this wallet\'s own submissions are visible: check the repo and the submission_id fleetgate_submit returned.' };
  return { ok: false, http_status: r.status, ...(r.data || {}) };
}

const TOOLS = [
  { name: 'fleetgate_onboard',
    description: 'FLEETGATE: put this pane on the FLEETGATE release gate as its own DemiPass wallet. Checks for a consent to pay fleetgate; if there is none it files one (status approval_pending + approval_id) — the person approves it in the DemiPass app, then call again with approval_id. Then mints a fleetgate service token held only inside this MCP server (never shown). Also verifies the signed intake lane for this identity. Payment consent alone is not readiness. Re-minting and admission checks are automatic; this grants no merge authority.',
    inputSchema: { type: 'object', properties: {
      daily_cap_dd: { type: 'integer', description: `Most fleetgate may charge this wallet per 24 h (default ${DEFAULT_CAP}; intake and metered reviews share this cap; see prices)` },
      approval_id: { type: 'integer', description: 'The approval_id from an earlier approval_pending answer, once approved in the app' } } } },
  { name: 'fleetgate_prices', description: 'FLEETGATE: the door\'s public price list (DD per action, margin included).', inputSchema: { type: 'object', properties: {} } },
  { name: 'fleetgate_submit',
    description: 'FLEETGATE: submit a pull request to a chartered repo under atlas/ through the door. Give the change as files (each file\'s whole new content) or as git {dir, ref, base}: the changed files between base and ref in your own checkout (deletes, renames, symlinks and binaries are refused before anything is sent). Intake charged once; review model calls billed separately (see fleetgate_prices) to this pane\'s wallet. The gate evaluates it under the signed charter; this never merges or reviews. To change a submission or rebuild it on a moved main, submit again with a new submission_id and supersedes: the old one. Not allowed: dotfiles, charters/, fleet/{controller,review,ci,door}/; at most 20 files, 128 KB each, 384 KB in all.',
    inputSchema: { type: 'object', required: ['repo'], properties: {
      repo: { type: 'string', description: 'Repo name under atlas/ (e.g. boltcluster)' },
      title: { type: 'string' }, body: { type: 'string', description: 'PR description' },
      files: { type: 'array', items: { type: 'object', required: ['path', 'content'], properties: { path: { type: 'string' }, content: { type: 'string', description: 'The whole new file content' } } } },
      git: { type: 'object', description: 'Instead of files: {dir: absolute path of your checkout, ref: the commit to submit (default HEAD), base: what it is based on (default origin/main)}. Title defaults to the commit subject.',
        properties: { dir: { type: 'string' }, ref: { type: 'string' }, base: { type: 'string' } } },
      supersedes: { type: 'string', description: 'The submission_id of your own earlier submission to this repo: once this one is open, the door closes that one' },
      submission_id: { type: 'string', description: 'Idempotency key (8-64 of A-Z a-z 0-9 _ -). Reuse it to retry the same submission without a second charge; omitted → a fresh one, returned.' } } } },
  { name: 'fleetgate_status', description: 'FLEETGATE: free readiness check: repairs existing consented sessions, verifies current signed admission and door health. Shows the lanes this pane may submit to (repos, paths, add-only, denied) and the service token\'s spend. No payment consent is filed.', inputSchema: { type: 'object', properties: {} } },
  { name: 'fleetgate_check',
    description: 'FLEETGATE: free, before building or paying: would these paths be admitted? Each path is checked against the signed lanes exactly as a submission is (add-only paths are looked up on main), and the answer names the one lane that would take them all, or why not. Nothing is charged or created.',
    inputSchema: { type: 'object', required: ['repo', 'paths'], properties: {
      repo: { type: 'string', description: 'Repo name under atlas/ (e.g. boltcluster)' },
      paths: { type: 'array', items: { type: 'string' }, description: 'The repository paths you would submit (1-20)' } } } },
  { name: 'fleetgate_follow',
    description: 'FLEETGATE: free: where your submission stands. The release controller\'s own rules evaluated now on the PR\'s exact head: every check, the verdict, CI, each reviewer seat (on the head or not; findings when changes were requested), and next {who, what}: ci, you, operator, closer, release-controller or nobody. Only this wallet\'s own submissions are visible. A submission is never amended: a fix is a new submission_id.',
    inputSchema: { type: 'object', required: ['repo', 'submission_id'], properties: {
      repo: { type: 'string', description: 'The repo under atlas/ you submitted to' },
      submission_id: { type: 'string', description: 'The submission_id fleetgate_submit returned' } } } },
];
const HANDLERS = {
  fleetgate_onboard: onboard,
  fleetgate_prices: async () => { const r = await http('GET', (await door()) + '/v1/prices'); return r.status === 200 ? { ok: true, ...r.data } : { ok: false, http_status: r.status, ...(r.data || {}) }; },
  fleetgate_submit: submit,
  fleetgate_status: status,
  fleetgate_check: check,
  fleetgate_follow: follow,
};

// Errors never carry the token: a ServiceError's body is DemiPass's answer, and our own errors name no secret.
function redact(x, t) { return t ? JSON.parse(JSON.stringify(x).split(t).join('[token]')) : x; }
function scrub(x) { return redact(x, held && held.token); }
function errBody(e) { return { ok: false, error: e.message, ...(e.result || {}), ...(e.body && typeof e.body === 'object' ? { demipass: e.body } : {}), ...(e.status ? { http_status: e.status } : {}) }; }

async function handleMessage(msg) {
  const { id, method, params } = msg;
  if (method === 'initialize') return { jsonrpc: '2.0', id, result: { protocolVersion: (params && params.protocolVersion) || '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'fleetgate', version: require('./package.json').version } } };
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

module.exports = { handleMessage, _reset: () => { held = null; consentSeen = null; doorCached = null; pendingCaps.clear(); } };

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
