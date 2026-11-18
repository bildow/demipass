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
 *   fleetgate_follow({repo, submission_id} | {review_id})   free: this wallet's submission as the release controller sees
 *                                                       it now (every check, each reviewer seat) and the one next step; or
 *                                                       a review-only request's state and, once done, every seat's verdict
 *   fleetgate_review({git, title?, note?, review_id?})  the three seats review a change from your checkout that does not
 *                                                       merge here (any repository); intake charged once, rounds metered
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
const { sessionToken, consentAtLeast, paneRulesPermission } = require('./onboard.js');
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
  // A call that ran out of time during discovery caches nothing: the next call discovers again (#30 independent review r3).
  checkAlive();
  u = (u || DOOR_DEFAULT).replace(/\/+$/, '');
  const bad = doorRefusal(u); if (bad) throw new Error(`FLEETGATE door ${u}: ${bad}`);
  return (doorCached = u);
}
// The one default, shared with demipass-onboard (fleetgate-admission.js); an existing smaller consent is never silently raised.
const DEFAULT_CAP = require('./fleetgate-admission').fleetgateDefaultCap();
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
  // The owner's "Write agent instruction files" permission comes before this wallet first uses Fleet (Aaron
  // 2026-11-18; #40 review M2: this path does not go through demipass-onboard, so it checks for itself). The silent
  // re-mint of a held token (fileConsent false) does not re-ask: that wallet already passed.
  if (fileConsent) {
    checkAlive();
    const perm = await paneRulesPermission(session);
    if (!perm.enabled) return { ok: false, status: 'needs_permission', error: `"Write agent instruction files" is not enabled for ${perm.person || 'this wallet'}; Fleet and pane onboarding need it. ${perm.next || 'Enable it in the DemiPass app (Settings → Agents).'}` };
  }
  if (approval_id && !daily_cap_dd && pendingCaps.has(Number(approval_id))) daily_cap_dd = pendingCaps.get(Number(approval_id));
  let c;
  checkAlive();   // an expired call starts no DemiPass request (#30 independent review r4)
  if (!fileConsent) {
    // Submitting (and the free tools) never file a consent (#17 review L3): after a person said no, a submit must not ask
    // their phone again. The active consent found here is used as it is; consentAtLeast is never called on this path,
    // since it reads again and could file one if the consent were revoked in between (#27 independent review, 2).
    const all = await api.consents();
    checkAlive();
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
    checkAlive();   // never mint for a call that already answered
    const t = await api.mintToken({ service: SERVICE, ttl: '24h', followUpDd: c.consent.daily_cap_dd });
    checkAlive();
    r = { consent: c.consent, existing: c.existing, token: { token: t.token, token_id: t.token_id, expires_at: t.expires_at, cap_dd: t.cap_dd } };
  }
  if (r.pending) {
    pendingCaps.set(Number(r.pending.approval_id), r.pending.daily_cap_dd);
    return { ok: false, status: 'approval_pending', approval_id: r.pending.approval_id, expires_at: r.pending.expires_at, daily_cap_dd: r.pending.daily_cap_dd,
             next: `Approve "let a wallet pay fleetgate" (${r.pending.daily_cap_dd} DD/day) in the DemiPass app (Requests), then call fleetgate_onboard again with approval_id ${r.pending.approval_id} and daily_cap_dd ${r.pending.daily_cap_dd}.` };
  }
  if (!TOKEN_RE.test(String(r.token.token || ''))) return { ok: false, error: 'DemiPass returned a malformed service token; not held' };
  const endpoint = await door();
  checkAlive();   // after discovery too: an expired call starts no admission request (#30 independent review r3)
  const ready = await fleetgateAdmission({ endpoint, token: r.token.token, wallet, timeoutMs: leftMs(QUICK_MS) });
  checkAlive();   // a call that already answered changes nothing
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

// ── The payment ask (Aaron 2026-11-17: "I can't have agents and panes block on this; it would be considered a bug /
// design flaw"). The door (fleetgate-door/5) answers a review or a PR whose payment was refused with
// payment: {refused, needed_dd, resumable, ask, next}. When the ask is a raise of this wallet's fleetgate daily consent,
// this server files it: one approval card in the owner's DemiPass app, sized to the current cap + what the step needs
// (rounded up to 500 DD, at most DemiPass's 100,000), and redeems it on a later call once approved. The work itself
// waits at the door and resumes by itself; the pane only keeps following.
// This is the one place a free tool (fleetgate_follow) files a consent, a deliberate exception to #17 review L3, kept
// as narrow as that rule's reason: at most ONE ask per refusal episode (wallet + review or PR head) per server process,
// never re-filed once the owner declined it or let it expire, and FLEETGATE_AUTO_ASK=0 turns it off (the next step is
// then said, not filed).
const AUTO_ASK = process.env.FLEETGATE_AUTO_ASK !== '0';
const CONSENT_MAX_DD = 100000;
const NO_REASK_MS = 24 * 3600e3;
// A filing whose outcome is unknown holds the wallet's automatic asks for as long as the card it may have made can be
// pending (DemiPass keeps a consent approval 24 h): never a second card beside it (#35 r3, 2).
const FILING_HOLD_MS = 24 * 3600e3;   // after the owner declines (or lets expire) a raise, no automatic ask for a day
// `${wallet}|${subject}` → the ask record. Subjects that meet the same pending ask share ONE record (the same object),
// so its outcome, approved, declined or expired, is every subject's (#35 independent review 2).
const asks = new Map();
const askView = (a, extra = {}) => ({ status: a.status, ...(a.approval_id ? { approval_id: a.approval_id } : {}), daily_cap_dd: a.daily_cap_dd, ...extra });
const posInt = (x) => { const n = Number(x); return Number.isFinite(n) && n > 0 ? Math.ceil(n) : 0; };   // #35 r1, 3
// The wallet the answer belongs to is re-checked after the ask's own requests, as doorCall checks it after the door's
// (Codex connector P2 on #35): a session that switched wallet meanwhile is shown nothing of the first wallet's work.
async function payAsk(result, subject) {
  const before = sessionSub();
  const out = await payAskInner(result, subject);
  if (out !== result && sessionSub() !== before) return { ok: false, status: 'wallet_changed', error: 'the session switched to another wallet while this ran; nothing of the earlier wallet\'s work is shown. Ask again.' };
  return out;
}
async function payAskInner(result, subject) {
  const p = result && result.payment;
  if (!p || !p.ask || !p.resumable) return result;
  if (p.ask.kind === 'fund') return fundAsk(result, subject, p);
  if (p.ask.kind !== 'consent') return { ...result, ask: { status: 'yours', kind: p.ask.kind, next: p.next } };
  if (!AUTO_ASK) return { ...result, ask: { status: 'off', next: `${p.next} (FLEETGATE_AUTO_ASK=0: file it yourself with fleetgate_onboard {daily_cap_dd}).` } };
  const session = sessionToken(), wallet = subOf(session);
  if (!session || !wallet) return result;
  const api = dp(session), key = `${wallet}|${subject}`;
  const walletAsks = () => [...new Set([...asks.values()].filter(a => a.wallet === wallet))];
  try {
    // An ask already filed for this wallet and still waiting: this subject shares it; redeem it if the owner approved.
    // A filing whose answer never came (the deadline, a dropped connection): a card MAY exist, so nothing else is filed
    // for this wallet until it is older than FILING_HOLD_MS (#35 r2, 1).
    // A filing whose outcome is unknown (in flight, or its answer never came): a card MAY exist, so nothing else is filed
    // for this wallet until it could no longer be pending. Never re-sent: after a decline a resend would make a new card
    // (#35 r3, 1). The owner finds the card in the app; the pane is told so.
    const filing = walletAsks().find(a => a.status === 'filing' && Date.now() - a.started < FILING_HOLD_MS);
    if (filing) { asks.set(key, filing); return { ...result, ask: { status: 'filing', daily_cap_dd: filing.daily_cap_dd, next: filing.inflight
      ? `An ask for ${filing.daily_cap_dd} DD/day is being filed; nothing more is filed for this wallet meanwhile. Keep following.`
      : `An ask for ${filing.daily_cap_dd} DD/day was sent but its answer was lost; nothing more is filed automatically for this wallet for a day. If a card is in the DemiPass app, the owner approves it there and the pane redeems it with fleetgate_onboard {approval_id, daily_cap_dd: ${filing.daily_cap_dd}}. Keep following.` } }; }
    const pend = (asks.get(key) && asks.get(key).status === 'asked') ? asks.get(key) : walletAsks().find(a => a.status === 'asked');
    if (pend) {
      asks.set(key, pend);
      checkAlive();
      let r;
      try { r = await api.consent({ service: SERVICE, dailyCapDd: pend.daily_cap_dd, approvalId: pend.approval_id, onRequestCapDd: pend.on_request_cap_dd }); }
      catch (e) {
        if (e.pending) return { ...result, ask: askView(pend, { next: `Waiting for the owner to approve "let a wallet pay fleetgate" at ${pend.daily_cap_dd} DD/day in the DemiPass app (approval ${pend.approval_id}). Nothing for you to do: keep following; the work resumes by itself once it is approved.` }) };
        if (e.status === 403 || e.status === 410) {
          pend.status = e.status === 403 ? 'declined' : 'expired'; pend.ended = Date.now();   // recorded even past the deadline
          return { ...result, ask: askView(pend, { next: `The owner ${pend.status === 'declined' ? 'declined' : 'did not answer'} the raise to ${pend.daily_cap_dd} DD/day (approval ${pend.approval_id}); it is not asked again. ${p.next}` }) };
        }
        throw e;
      }
      // Approved and redeemed: recorded even if the deadline passed while DemiPass answered.
      pend.status = 'raised'; pend.ended = Date.now();
      consentSeen = { id: r.consent_id, service: r.service, daily_cap_dd: r.daily_cap_dd, status: 'active' };
      return { ...result, ask: askView(pend, { daily_cap_dd: r.daily_cap_dd || pend.daily_cap_dd,
        next: 'The owner approved the raise. The work resumes by itself within 5 minutes; sending the same request again with the same id (fleetgate_review) resumes it now.' }) };
    }
    const mine = asks.get(key);
    if (mine) return { ...result, ask: askView(mine, { next: mine.status === 'raised' ? 'Raised already for this refusal; if the work still waits, the step needs more than the raise: the owner can file it with fleetgate_onboard {daily_cap_dd}.' : `The owner ${mine.status} the raise; it is not asked again. ${p.next}` }) };
    // The owner said no (or let it lapse) to a raise for this wallet within a day: never ask again automatically.
    const refusedLately = walletAsks().find(a => ['declined', 'expired'].includes(a.status) && Date.now() - (a.ended || 0) < NO_REASK_MS);
    if (refusedLately) return { ...result, ask: askView(refusedLately, { next: `The owner ${refusedLately.status} a raise for this wallet within the last day; this server does not ask again. ${p.next}` }) };
    // File the one ask for this episode: ONE request, checked against the deadline before it starts, and recorded
    // whatever the deadline says once DemiPass answers, so a card that was filed is never forgotten (#35 r1, 1).
    checkAlive();
    const all = await api.consents();
    const active = (all.mine || []).find(x => x.service === SERVICE && x.status === 'active');
    const current = active ? active.daily_cap_dd : 0;
    const more = posInt(p.ask.more_dd) || posInt(p.needed_dd) || 500;
    const target = Math.min(CONSENT_MAX_DD, Math.ceil((current + more) / 500) * 500);
    if (!(target > current)) return { ...result, ask: { status: 'at_max', daily_cap_dd: current, next: `The fleetgate daily consent is already at DemiPass's most (${current} DD): the step waits for tomorrow's allowance.` } };
    checkAlive();
    // The raise keeps the consent's Conduit opt-in (dustforge#131 review 2): without it an approved raise would end it.
    const keepOptIn = active && Number.isInteger(active.on_request_cap_dd) && active.on_request_cap_dd > 0 ? active.on_request_cap_dd : undefined;
    // Reserved before the request leaves, for the whole wallet: a call that times out (or a second subject) while this
    // POST is in flight finds 'filing' and files nothing (#35 r2, 1). The same record is settled by the answer.
    const a = { wallet, subject, daily_cap_dd: target, ...(keepOptIn ? { on_request_cap_dd: keepOptIn } : {}), status: 'filing', inflight: true, started: Date.now(), at: new Date().toISOString() };
    asks.set(key, a);
    let r;
    try { r = await api.consent({ service: SERVICE, dailyCapDd: target, onRequestCapDd: keepOptIn }); }
    catch (e) {
      a.inflight = false;
      if (!e.pending) {
        // An answer that says nothing was filed (a 4xx without an approval) frees the reservation; anything else keeps it.
        if (e.status >= 400 && e.status < 500) asks.delete(key);
        throw e;
      }
      if (a.status !== 'filing') return { ...result, ask: askView(a) };   // settled meanwhile: never overwritten
      a.approval_id = e.body.approval_id; a.status = 'asked'; pendingCaps.set(Number(a.approval_id), target);
      return { ...result, ask: askView(a, { from_dd: current, next: `Asked the owner to raise the fleetgate daily consent from ${current} to ${target} DD/day: one approval in the DemiPass app (approval ${a.approval_id}). Nothing for you to do: keep following; the work resumes by itself once it is approved.` }) };
    }
    Object.assign(a, { daily_cap_dd: r.daily_cap_dd || target, status: 'raised', ended: Date.now(), inflight: false });
    consentSeen = { id: r.consent_id, service: r.service, daily_cap_dd: r.daily_cap_dd, status: 'active' };
    return { ...result, ask: askView(a, { from_dd: current, next: 'Raised. The work resumes by itself within 5 minutes.' }) };
  } catch (e) {
    if (e && e.name === 'TimeoutError') throw e;
    return { ...result, ask: { status: 'error', error: String((e && e.message) || e).slice(0, 200), next: p.next } };
  }
}

// A `fund` refusal (the paying wallet is short, dustforge#131's raise): file ONE fund ask on that wallet
// (POST /api/billing/fund-asks, dustforge#133), a card the owner sees in the DemiPass app and on the phone, which closes
// by itself once the balance covers the need. Before this the pane was handed a sentence and DemiPass held nothing
// (Aaron 2026-11-18: "The app doesn't hold the request anywhere"). One filing per refusal episode (wallet + subject) per
// process; later follows read its status instead of filing again. It moves no DD: the owner funds the wallet.
const fundAsks = new Map();   // `${wallet}|${subject}` → { notice_id, status }
const FUND_SUBJECT_RE = /[^A-Za-z0-9_#+-]/g;   // what DemiPass accepts in a subject (nothing that reads as a link or address)
const FUND_HOLD_MS = 24 * 3600e3;   // after the owner dismissed: as the consent path's NO_REASK_MS
const FUND_RETRY_MS = 5 * 60e3;     // after DemiPass did not file one
const FUND_COVERED_MS = 2 * 60e3;   // after DemiPass said the balance covers it
async function fundAsk(result, subject, p) {
  if (!AUTO_ASK) return { ...result, ask: { status: 'off', kind: 'fund', next: `${p.next} (FLEETGATE_AUTO_ASK=0: nothing was filed.)` } };
  const session = sessionToken(), wallet = subOf(session);
  if (!session || !wallet) return { ...result, ask: { status: 'yours', kind: 'fund', next: p.next } };
  const key = `${wallet}|${subject}`, mine = fundAsks.get(key), t = Date.now();
  const say = (a, next) => ({ ...result, ask: { status: a.status, kind: 'fund', ...(a.notice_id ? { notice_id: a.notice_id } : {}), next } });
  try {
    // An open card: follow it. 'covered' is never kept: the door refusing again means a later step needs more, and a
    // new filing is right (DemiPass answers "covered" and files nothing while the balance still covers it) (#37 r2).
    if (mine && mine.status === 'asked' && mine.notice_id) {
      checkAlive();
      const r = await http('GET', `${DEMIPASS_URL}/api/billing/fund-asks/${mine.notice_id}`, { auth: session });
      const fa = r.status === 200 && r.data && r.data.fund_ask ? r.data.fund_ask : null;
      if (!fa) return say(mine, `Waiting for the owner to fund the wallet (card ${mine.notice_id} in the DemiPass app; its status could not be read just now). Keep following.`);
      if (fa.status === 'open') return say(mine, `Waiting for the owner to fund the wallet (${fa.short_dd} DD short; card ${mine.notice_id} in the DemiPass app). Nothing for you to do: keep following; the work resumes by itself once it is funded.`);
      if (fa.status === 'dismissed' || fa.status === 'lapsed') { Object.assign(mine, { status: fa.status, until: t + FUND_HOLD_MS });
        return say(mine, `The owner ${fa.status === 'dismissed' ? 'dismissed' : 'let lapse'} the fund ask (card ${mine.notice_id}); it is not filed again today. ${p.next}`); }
      fundAsks.delete(key);   // covered (or superseded): this refusal is a new need; file below
    } else if (mine && mine.status === 'filing' && t - mine.started < 30e3) {
      // One in flight at a time; a filing whose answer never came is retried after 30 s (one card per work key).
      return say(mine, 'A fund ask is being filed; nothing more is filed meanwhile. Keep following.');
    } else if (mine && mine.until && t < mine.until) {
      // Settled for a while: the owner dismissed (24 h), or DemiPass did not file it (5 min) — not re-sent every follow.
      if (mine.status === 'not_filed') return { ...result, ask: { status: 'yours', kind: 'fund', next: p.next, not_filed: mine.why } };
      if (mine.status === 'covered') return { ...result, ask: { status: 'covered', kind: 'fund', next: 'The wallet covers it now. The work resumes by itself within minutes; nothing to file.' } };
      return say(mine, `${mine.status === 'lapsed' ? 'The owner let the fund ask lapse' : 'The owner dismissed fund asks for this wallet recently'}; none is filed again until ${new Date(mine.until).toISOString()}. ${p.next}`);
    }
    const need = posInt(p.needed_dd);
    if (!need) return { ...result, ask: { status: 'yours', kind: 'fund', next: p.next } };
    checkAlive();   // before the reservation: a call already out of time reserves nothing (#37 r3)
    const a = { status: 'filing', started: t }; fundAsks.set(key, a);
    const body = { need_dd: need, service: SERVICE, subject: String(subject).replace(FUND_SUBJECT_RE, '-').replace(/^[^A-Za-z0-9]+/, '').slice(0, 80) || 'work',
      ...(p.lapses_at ? { lapses_at: p.lapses_at } : {}), from: 'fleetgate pane' };
    checkAlive();
    const r = await http('POST', `${DEMIPASS_URL}/api/billing/fund-asks`, { auth: session, body });
    if (r.status === 202 && r.data && r.data.notice_id) {
      Object.assign(a, { status: 'asked', notice_id: r.data.notice_id });
      return say(a, `Asked the owner to fund the wallet: ${r.data.short_dd} DD short (card ${a.notice_id} in the DemiPass app, and a phone notification). Nothing for you to do: keep following; the work resumes by itself once it is funded.`);
    }
    // Covered: held 2 minutes (the door resumes within minutes), then a refusal that persists asks again (#37 r3).
    if (r.status === 200 && r.data && r.data.covered) { Object.assign(a, { status: 'covered', until: t + FUND_COVERED_MS }); return { ...result, ask: { status: 'covered', kind: 'fund', next: 'The wallet covers it now. The work resumes by itself within minutes; nothing to file.' } }; }
    if (r.status === 409 && r.data && r.data.dismissed) { Object.assign(a, { status: 'dismissed', until: t + FUND_HOLD_MS });
      return say(a, `The owner dismissed fund asks for this wallet recently; none is filed again today. ${p.next}`); }
    // Not filed (an older DemiPass without the route, a cap, an agent wallet): said, and not re-sent for 5 minutes.
    const why = String((r.data && r.data.error) || `HTTP ${r.status}`).slice(0, 200);
    Object.assign(a, { status: 'not_filed', why, until: t + FUND_RETRY_MS });
    return { ...result, ask: { status: 'yours', kind: 'fund', next: p.next, not_filed: why } };
  } catch (e) {
    if (e && e.name === 'TimeoutError') throw e;
    return { ...result, ask: { status: 'error', kind: 'fund', error: String((e && e.message) || e).slice(0, 200), next: p.next } };
  }
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

// 15 s for the free, read-only calls (health, prices, check, follow, the registry); 180 s only for submit and review,
// which create a PR or queue a packet (code pass 2026-11-16, item 7).
const QUICK_MS = 15000, SLOW_MS = 180000;
// A free tool call (status, prices, check, follow) has ONE 15 s deadline across all its requests and retries, not
// 15 s per request (#30 independent review): each request gets only what is left, and the call answers by then.
const { AsyncLocalStorage } = require('async_hooks');
const deadline = new AsyncLocalStorage();
const FREE_TOOLS = new Set(['fleetgate_status', 'fleetgate_prices', 'fleetgate_check', 'fleetgate_follow']);
// When the deadline is reached the call's context is marked dead: the call answers "timed_out" at that moment, and
// whatever of it is still running can send no further request and change no shared state (held token, consent,
// admission) once its awaits return (#30 independent review r2).
const leftMs = (cap) => { const d = deadline.getStore(); return d ? Math.min(cap, d.at - Date.now()) : cap; };
const alive = () => { const d = deadline.getStore(); return !d || (!d.dead && Date.now() < d.at); };
function checkAlive() { if (!alive()) throw Object.assign(new Error(`this call ran out of its ${QUICK_MS / 1000} s; nothing more was done`), { name: 'TimeoutError' }); }
function withDeadline(fn) {
  const ctx = { at: Date.now() + QUICK_MS, dead: false };
  let timer;
  const late = new Promise(ok => { timer = setTimeout(() => { ctx.dead = true; ok({ ok: false, status: 'timed_out', error: `no answer within ${QUICK_MS / 1000} s (the door or DemiPass is slow); nothing was charged. Try again shortly.` }); }, QUICK_MS); });
  return Promise.race([deadline.run(ctx, fn), late]).finally(() => clearTimeout(timer));
}
async function http(method, url, { auth, body, timeoutMs = QUICK_MS } = {}) {
  checkAlive();
  timeoutMs = leftMs(timeoutMs);
  if (timeoutMs <= 0) throw Object.assign(new Error(`no time left of this call's ${QUICK_MS / 1000} s`), { name: 'TimeoutError' });
  const headers = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (auth) headers.authorization = 'Bearer ' + auth;
  const r = await require('./http-json').requestJson(method, url, { headers, body, timeoutMs });
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
// git gets neither GIT_* nor DEMIPASS_* variables of this process (a DemiPass token has no business in git's
// environment), and the global and system config files are closed as a class (GIT_CONFIG_GLOBAL=/dev/null,
// GIT_CONFIG_NOSYSTEM=1) rather than their settings enumerated; the checkout's own config is neutralized per setting
// above (code pass 2026-11-16, item 3).
function gitEnv(base = process.env) {
  const env = {};
  for (const [k, v] of Object.entries(base)) if (!k.startsWith('GIT_') && !k.startsWith('DEMIPASS_')) env[k] = v;
  return { ...env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_NO_REPLACE_OBJECTS: '1', GIT_GRAFT_FILE: '/dev/null', GIT_NO_LAZY_FETCH: '1', GIT_TERMINAL_PROMPT: '0' };
}
// The door's own path rule (fleet/door/door.js PATH_RE): ASCII letters, digits, . _ - /; at most 200 characters; no
// leading slash, dot segment or empty segment. Refused here, before anything is sent (#28 independent review round 3, 2).
const DOOR_PATH_RE = /^(?!\/)(?!.*(^|\/)\.)(?!.*\/\/)[A-Za-z0-9._\-/]{1,200}$/;

// --no-lazy-fetch (and GIT_NO_LAZY_FETCH) need git 2.45; an older git would fail every call with an unhelpful
// "unknown option", so the version is checked once and named (round 7, non-blocking).
// This machine's git against the 2.45 the git path needs, as fleetgate_status reports it (so a pane learns it before a
// git-path submit or review refuses) and as gitTooOld() checks it. → { version, required, ok, error? }
const GIT_REQUIRED = '2.45';
let gitVersionOk = null;   // only a passing check is kept: an upgrade takes effect without a restart
const GIT_MISSING = { version: null, required: GIT_REQUIRED, ok: false, error: 'git not found on this machine: fleetgate_submit {git} and fleetgate_review will refuse; fleetgate_submit {files} works' };
// Not found only when it isn't there; a git that exists but can't run says so (#31 independent review r2).
const gitFailure = (err) => err && err.code === 'ENOENT' ? GIT_MISSING
  : { version: null, required: GIT_REQUIRED, ok: false, error: `git could not run (${String((err && (err.code || err.message)) || 'error').slice(0, 80)}): fleetgate_submit {git} and fleetgate_review will refuse; fleetgate_submit {files} works` };
function parseGitVersion(out) {
  const m = /git version (\d+)\.(\d+)(?:\.(\d+))?/.exec(out);
  if (!m) return { version: null, required: GIT_REQUIRED, ok: false, error: `could not read git's version (${String(out).slice(0, 60)})` };
  const ok = +m[1] > 2 || (+m[1] === 2 && +m[2] >= 45);
  return { version: `${m[1]}.${m[2]}${m[3] !== undefined ? `.${m[3]}` : ''}`, required: GIT_REQUIRED, ok,
    ...(ok ? {} : { error: `git ${m[1]}.${m[2]} is older than ${GIT_REQUIRED}: fleetgate_submit {git} and fleetgate_review will refuse; fleetgate_submit {files} works. Upgrade git (Ubuntu: ppa:git-core/ppa).` }) };
}
// Synchronous, for the git path itself (submit, review), which isn't under a free call's deadline.
function gitVersionInfo() {
  if (gitVersionOk) return gitVersionOk;
  let info;
  try { info = parseGitVersion(execFileSync('git', ['--version'], { env: gitEnv(), timeout: 10000 }).toString().trim()); }
  catch (e) { info = gitFailure(e); }
  if (info.ok) gitVersionOk = info;
  return info;
}
// Asynchronous, for fleetgate_status: never blocks the event loop and is bounded by the call's remaining time, so a
// slow or hung git can't carry status past its 15 s (#31 independent review).
function gitVersionInfoAsync() {
  if (gitVersionOk) return Promise.resolve(gitVersionOk);
  const timeout = Math.max(1, leftMs(10000));
  return new Promise(resolve => require('child_process').execFile('git', ['--version'], { env: gitEnv(), timeout }, (err, stdout) => {
    const info = err ? (err.killed ? { version: null, required: GIT_REQUIRED, ok: false, error: 'git --version did not answer in time' } : gitFailure(err)) : parseGitVersion(String(stdout).trim());
    if (info.ok && alive()) gitVersionOk = info;
    resolve(info);
  }));
}
function gitTooOld() {
  const g = gitVersionInfo();
  if (g.ok) return null;
  return g.version ? `git: version ${g.version} is too old; reading a checkout safely needs git ${GIT_REQUIRED} or newer (--no-lazy-fetch). Upgrade git, or send files instead.`
    : `git: ${g.error.replace(/:.*$/, '')}; send files instead`;
}

// The checkout's own git directory, exactly as git prints it (only its terminating newline removed: a trim could turn
// "/work/project " into "/work/project", #28 r2). Every later command is pinned to it with --git-dir, so the
// checkout's config (core.worktree) can't send git to another repository (#29 r3); comparing two commits needs no
// work tree.
function topLevel(run) {
  const b = run('rev-parse', '--absolute-git-dir');
  const raw = b.subarray(0, b.length && b[b.length - 1] === 0x0a ? b.length - 1 : b.length);
  const dir = raw.toString('utf8');
  if (!dir || !Buffer.from(dir, 'utf8').equals(raw) || !path.isAbsolute(dir)) return { error: 'git: the checkout\'s git directory path is not plain UTF-8' };
  return { dir };
}

function filesFromGit(g) {
  if (!g || typeof g !== 'object' || Array.isArray(g)) return { error: 'git: {dir, ref?, base?}' };
  const { dir, ref = 'HEAD', base = 'origin/main' } = g;
  for (const k of Object.keys(g)) if (!['dir', 'ref', 'base'].includes(k)) return { error: `git: unknown field ${k}` };
  if (typeof dir !== 'string' || !path.isAbsolute(dir)) return { error: 'git.dir: the absolute path of your checkout' };
  for (const [k, v] of [['ref', ref], ['base', base]])
    if (typeof v !== 'string' || !GIT_REF_RE.test(v) || v.includes('..') || v.endsWith('.lock')) return { error: `git.${k}: a branch, tag or commit name` };
  const tooOld = gitTooOld();   // once per call (code pass 2026-11-16, item 9)
  if (tooOld) return { error: tooOld };
  // Run at the repository's top level with diff.relative off: a user's git config must not narrow or re-root the change
  // (#28 independent review, 1).
  const at = (cwd, gd) => (...args) => execFileSync('git', [...GIT_FIXED, ...(gd ? [`--git-dir=${gd}`] : []), '-C', cwd, '-c', 'diff.relative=false', '-c', 'diff.ignoreSubmodules=none', ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: gitEnv(), maxBuffer: 16 << 20, timeout: 30000 });
  let run, head, mb, listing;
  try {
    const top = topLevel(at(dir));
    if (top.error) return top;
    run = at(top.dir, top.dir);
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
    // The size first: a file over the door's limit is refused with its size, without reading it, and only an object
    // that isn't here at all reads as a partial clone (code pass 2026-11-16, item 8).
    let size;
    try { size = Number(run('cat-file', '-s', newSha).toString().trim()); }
    catch (_) { refused.push(`${p}: its content isn't in this checkout (a partial clone?); fetch it first`); continue; }
    if (!(size <= MAX_FILE)) { refused.push(`${p}: ${size} bytes, over ${MAX_FILE}`); continue; }
    let buf;
    try { buf = run('cat-file', 'blob', newSha); }
    catch (e) { refused.push(`${p}: could not read it (${String(e.message).split('\n')[0].slice(0, 120)})`); continue; }
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

// A review-only packet from the pane's own checkout: head, the merge base with `base`, every changed path (deletes and
// renames too: a review reads them), the unified diff, and the origin remote as a plain https URL (credentials and
// non-https remotes left out). → { packet } | { error }
const MAX_REVIEW_DIFF = 400000;
function packetFromGit(g) {
  if (!g || typeof g !== 'object' || Array.isArray(g)) return { error: 'git: {dir, ref?, base?}' };
  const { dir, ref = 'HEAD', base = 'origin/main' } = g;
  for (const k of Object.keys(g)) if (!['dir', 'ref', 'base'].includes(k)) return { error: `git: unknown field ${k}` };
  if (typeof dir !== 'string' || !path.isAbsolute(dir)) return { error: 'git.dir: the absolute path of your checkout' };
  for (const [k, v] of [['ref', ref], ['base', base]])
    if (typeof v !== 'string' || !GIT_REF_RE.test(v) || v.includes('..') || v.endsWith('.lock')) return { error: `git.${k}: a branch, tag or commit name` };
  // At the top level, with diff.relative off and fixed a/ b/ prefixes: a user's git config must not narrow, re-root or
  // re-shape the packet (as for submissions, #28 independent review).
  const tooOld = gitTooOld();   // once per call (code pass 2026-11-16, item 9)
  if (tooOld) return { error: tooOld };
  // diff.submodule=short: a submodule's own diff would run its own textconv and external drivers, which the parent's
  // --no-textconv doesn't reach (#29 r1, 1). core.bigFileThreshold high and --text below: the checkout's config or
  // attributes can't turn a change into "Binary files differ" and hide it (#29 r1, 2).
  const at = (cwd, gd) => (...args) => execFileSync('git', [...GIT_FIXED, ...(gd ? [`--git-dir=${gd}`] : []), '-C', cwd, '-c', 'diff.relative=false', '-c', 'diff.noprefix=false', '-c', 'diff.mnemonicPrefix=false', '-c', 'diff.ignoreSubmodules=none',
    '-c', 'diff.submodule=short', '-c', 'core.bigFileThreshold=2047m', ...args],
    { stdio: ['ignore', 'pipe', 'pipe'], env: gitEnv(), maxBuffer: 32 << 20, timeout: 60000 });
  let run, head, mb, raw, diffBuf;
  try {
    const top = topLevel(at(dir));
    if (top.error) return top;
    run = at(top.dir, top.dir);
    if (run('rev-parse', '--is-shallow-repository').toString().trim() !== 'false')
      return { error: 'git: this checkout is shallow, so its merge base can\'t be trusted; fetch the full history first (git fetch --unshallow)' };
    head = run('rev-parse', '--verify', '--end-of-options', `${ref}^{commit}`).toString().trim();
    const b = run('rev-parse', '--verify', '--end-of-options', `${base}^{commit}`).toString().trim();
    mb = run('merge-base', b, head).toString().trim();
    raw = run('diff', '--raw', '-z', '--no-renames', '--no-relative', '--ignore-submodules=none', '--no-abbrev', mb, head);
    diffBuf = run('diff', '--no-color', '--no-ext-diff', '--no-textconv', '--text', '--submodule=short', '--no-renames', '--no-relative', '--ignore-submodules=none', '--full-index', '--src-prefix=a/', '--dst-prefix=b/', mb, head);
  } catch (e) {
    return { error: `git: ${(String(e.stderr || e.message).trim().split('\n').pop() || 'failed').slice(0, 300)}` };
  }
  const parts = [];
  for (let i0 = 0; i0 < raw.length;) { const z = raw.indexOf(0, i0); if (z < 0) break; if (z > i0) parts.push(raw.subarray(i0, z)); i0 = z + 1; }
  const files = [];
  for (let i = 0; i + 1 < parts.length; i += 2) {
    const pb = parts[i + 1], p = pb.toString('utf8');
    if (!Buffer.from(p, 'utf8').equals(pb)) return { error: `git: a changed path is not UTF-8 (${pb.toString('latin1').replace(/[^\x20-\x7e]/g, '?')})` };
    // The door's review rule for a path: 1-300 characters, no NUL or newline (#29 r1, 4).
    if (p.length > 300 || /[\0\n]/.test(p)) return { error: `git: the door takes changed paths of up to 300 characters without newlines (${p.slice(0, 80).replace(/\n/g, '\\n')}…)` };
    files.push({ status: parts[i].toString('latin1').split(' ')[4], path: p });
  }
  if (!files.length) return { error: `git: no changes between the merge base ${mb.slice(0, 12)} and ${ref}` };
  if (files.length > 300) return { error: `git: ${files.length} changed files, over 300 for one review` };
  const diff = diffBuf.toString('utf8');
  if (!Buffer.from(diff, 'utf8').equals(diffBuf)) return { error: 'git: the diff is not UTF-8 text (a binary file in the change?); reviews take text changes' };
  if (diff.length > MAX_REVIEW_DIFF) return { error: `git: the diff is ${diff.length} characters, over ${MAX_REVIEW_DIFF} for one review` };
  // The origin remote only if it is an https URL: credentials, query and fragment dropped, and only the door's plain
  // form kept. An ssh or other remote is left out, never rewritten into an https location it may not have (#29 r1, 3).
  let remote;
  try {
    const url = new URL(run('remote', 'get-url', 'origin').toString().trim());
    const plain = `https://${url.host}${url.pathname.replace(/\.git$/, '')}`;
    if (url.protocol === 'https:' && /^https:\/\/[A-Za-z0-9.-]{1,100}(:[0-9]{1,5})?\/[A-Za-z0-9._\/-]{1,200}$/.test(plain)) remote = plain;
  } catch (_) { remote = undefined; }
  // The door takes SHA-1 commit ids (40 hex); a SHA-256 repository is refused here, before anything is sent (#29 r2, 1).
  if (!/^[0-9a-f]{40}$/.test(head) || !/^[0-9a-f]{40}$/.test(mb)) return { error: 'git: this repository uses commit ids the door does not take (SHA-256); reviews take SHA-1 repositories' };
  return { packet: { source: { ...(remote ? { remote } : {}), head, base: mb }, files, diff,
    subject: run('log', '-1', '--no-show-signature', '--format=%s', head).toString().trim() } };
}

async function review({ git, title, note, review_id }) {
  const p = packetFromGit(git);
  if (p.error) return { ok: false, error: p.error, note: 'Nothing was sent or charged.' };
  // A supplied id must be a string (no coercion); only an omitted one is generated, so a retry never becomes a second,
  // separately charged review (#29 r2, 2).
  if (review_id !== undefined && typeof review_id !== 'string') return { ok: false, error: 'review_id: a string (8-64 letters, digits, _ or -)' };
  const id = review_id === undefined ? `review-${crypto.randomBytes(8).toString('hex')}` : review_id;
  if (!SUBMISSION_RE.test(id)) return { ok: false, error: 'review_id: 8-64 letters, digits, _ or -, starting with a letter or digit' };
  if (note !== undefined && (typeof note !== 'string' || note.length > 4000)) return { ok: false, error: 'note: up to 4000 characters' };
  const t = typeof title === 'string' && title.trim() ? title.trim().slice(0, 200) : p.packet.subject.slice(0, 200) || 'review';
  const reqBody = { review_id: id, title: t, ...(note ? { note } : {}), source: p.packet.source, files: p.packet.files, diff: p.packet.diff };
  const wire = Buffer.byteLength(JSON.stringify(reqBody), 'utf8');
  if (wire > MAX_REQUEST) return { ok: false, review_id: id, error: `the review request would be ${wire} bytes once encoded, over the door's ${MAX_REQUEST}; review a smaller change`, note: 'Nothing was sent or charged.' };
  const { r, refused } = await doorCall('POST', '/v1/reviews', reqBody, SLOW_MS);
  if (refused) return { ...refused, review_id: id, next: `If the door may have charged, retry with review_id "${id}": the same diff replays and is never charged twice.` };
  if (OLD_DOOR(r)) return { ok: false, review_id: id, error: 'this door predates review-only requests (fleetgate-door/4)' };
  if (r.status === 202) return payAsk({ ...r.data, review_id: id, files: p.packet.files.length, next: r.data.payment ? r.data.next : `fleetgate_follow {review_id: "${id}"} shows its state and, once done, every seat's verdict (free).` }, `review:${id}`);
  return { ok: false, http_status: r.status, review_id: id, ...(r.data || {}) };
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
  if (submission_id !== undefined && typeof submission_id !== 'string') return { ok: false, error: 'submission_id: a string (8-64 letters, digits, _ or -)' };
  const sid = submission_id === undefined ? crypto.randomBytes(12).toString('hex') : submission_id;
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
    r = await http('POST', url, { auth: m.auth, body: payload, timeoutMs: SLOW_MS });
    if (r.status === 401) {   // expired or revoked: re-mint once
      held = null; m = await mint(); if (m.refused) return m.refused;
      r = await http('POST', url, { auth: m.auth, body: payload, timeoutMs: SLOW_MS });
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
  const gitProbe = gitVersionInfoAsync();   // alongside the network work, never after it
  const health = await http('GET', (await door()) + '/health').catch(e => ({ status: 0, data: { error: e.message } }));
  checkAlive();   // a health answer that raced the deadline starts nothing more (#30 independent review r4)
  let ready;
  // A door that didn't answer at all is reported as such; its admission check would only wait out a second timeout
  // (status answers within one 15 s timeout against a dead door: code pass 2026-11-16, item 7).
  if (health.status === 0) ready = { ok: false, status: 'door_unreachable', error: `the door did not answer: ${String((health.data && health.data.error) || 'no answer').slice(0, 200)}` };
  else try {
    // Existing users self-reconcile on their next status call without filing consent or spending.
    ready = held && held.wallet !== sessionSub() ? { ok:false, status:'wallet_changed', error:'The held token belongs to another wallet; onboard explicitly' } : live() ? await (async () => { const endpoint = await door(); checkAlive(); return fleetgateAdmission({ endpoint, token: held.token, wallet: held.wallet, timeoutMs: leftMs(QUICK_MS) }); })() : await onboard({}, { fileConsent: false });
  } catch (e) { ready = errBody(e); }
  checkAlive();
  admissionSeen = ready.ok ? ready.admission : null;
  const gitInfo = await gitProbe;
  checkAlive();
  return { ok: health.status === 200 && health.data && health.data.ok === true && Boolean(ready.ok), door: await door(),
    // This machine's git against what the git path needs: a pane learns it here, before a git-path call refuses.
    git: gitInfo,
    door_health: health.status === 200 ? health.data : { http_status: health.status, ...(health.data || {}) },
    onboarded: Boolean(live() && ready.ok), admission: admissionSeen, ...(ready.ok ? {} : { readiness: ready }),
    token_id: live() ? held.token_id : null, expires_at: live() ? held.expires_at : null,
    consent: consentSeen ? { id: consentSeen.id, daily_cap_dd: consentSeen.daily_cap_dd } : null,
    ...((() => { const me = sessionSub(); const mine = [...new Map([...asks.entries()].filter(([, a]) => a.wallet === me)).entries()]; return mine.length ? { payment_asks: mine.map(([k, a]) => ({ subject: k.slice(k.indexOf('|') + 1), ...askView(a), at: a.at })) } : {}; })()),
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
async function doorCall(method, route, body, timeoutMs = QUICK_MS) {
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
    let r = await http(method, url, { auth, body, timeoutMs });
    checkAlive();
    if (r.status === 401) {
      held = null;
      try { auth = await token(); } catch (e) { return { refused: errBody(e) }; }
      if (!mine()) return SWITCHED;
      r = await http(method, url, { auth, body, timeoutMs });
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

async function follow({ repo, submission_id, review_id }) {
  if (review_id !== undefined) {
    if (typeof review_id !== 'string' || !FOLLOW_ID_RE.test(review_id)) return { ok: false, error: 'review_id: the one fleetgate_review returned' };
    const { r, refused } = await doorCall('GET', `/v1/reviews/${encodeURIComponent(review_id)}`);
    if (refused) return refused;
    if (OLD_DOOR(r)) return { ok: false, error: 'this door predates review-only requests (fleetgate-door/4)' };
    if (r.status === 200) return payAsk(r.data, `review:${review_id}`);
    return { ok: false, http_status: r.status, ...(r.data || {}), ...(r.status === 404 ? { hint: 'Only this wallet\'s own reviews are visible.' } : {}) };
  }
  if (typeof repo !== 'string' || !/^[A-Za-z0-9._-]{1,100}$/.test(repo)) return { ok: false, error: 'repo: the repo under atlas/ you submitted to (e.g. boltcluster)' };
  if (typeof submission_id !== 'string' || !FOLLOW_ID_RE.test(submission_id)) return { ok: false, error: 'submission_id: the one fleetgate_submit returned' };
  const { r, refused } = await doorCall('GET', `/v1/pulls/${encodeURIComponent(repo)}/${encodeURIComponent(submission_id)}`);
  if (refused) return refused;
  if (OLD_DOOR(r)) return { ok: false, error: 'this door predates following a submission (fleetgate-door/3)' };
  if (r.status === 200) return payAsk(r.data, `pull:${repo}/${submission_id}@${(r.data.pull && r.data.pull.head) || ''}`);
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
    description: 'FLEETGATE: submit a pull request to a chartered repo under atlas/ through the door. Give the change as files (each file\'s whole new content) or as git {dir, ref, base}: the changed files between base and ref in your own checkout (deletes, renames, symlinks and binaries are refused before anything is sent). Intake charged once; review model calls billed separately (see fleetgate_prices) to this pane\'s wallet. The gate evaluates it under the signed charter; this never merges or reviews. To change a submission or rebuild it on a moved main, submit again with a new submission_id and supersedes: the old one. Which paths a repo admits: fleetgate_status (its lanes) and fleetgate_check {repo, paths} (free, before you pay). At most 20 files, 128 KB each, 384 KB in all.',
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
    description: 'FLEETGATE: free: where your submission or review stands. When the payer can\'t pay yet (the daily consent used up), the answer says so in payment {refused, needed_dd, next} and this tool files ONE raise of your fleetgate daily consent for the owner to approve in the DemiPass app (ask {status: asked|raised|declined|expired}); when the paying wallet is short of funds it files ONE fund ask instead, a card the owner funds in the app (ask {kind: fund, status: asked|covered|dismissed|lapsed}); the work waits at the door and resumes by itself once approved: nothing to work out, just keep following. where your submission stands. The release controller\'s own rules evaluated now on the PR\'s exact head: every check, the verdict, CI, each reviewer seat (on the head or not; findings when changes were requested), and next {who, what}: ci, you, operator, closer, release-controller or nobody. Only this wallet\'s own submissions are visible. A submission is never amended: a fix is a new submission_id.',
    inputSchema: { type: 'object', properties: {
      repo: { type: 'string', description: 'The repo under atlas/ you submitted to' },
      submission_id: { type: 'string', description: 'The submission_id fleetgate_submit returned' },
      review_id: { type: 'string', description: 'Instead: the review_id fleetgate_review returned' } } } },
  { name: 'fleetgate_review',
    description: 'FLEETGATE: the three reviewer seats (three model vendors) review a change from your own git checkout that does not merge here: another repository (GitHub, private or public) or work not ready to submit. The diff between the merge base of base and ref (at most 400,000 characters) is sent; nothing merges and nothing is posted to any repository. Intake charged once; each model call billed as it runs (see fleetgate_prices). Follow it with fleetgate_follow {review_id}; the result carries every seat\'s verdict and findings and a receipt digest over the exact head, base and diff.',
    inputSchema: { type: 'object', required: ['git'], properties: {
      git: { type: 'object', description: '{dir: absolute path of your checkout, ref: the commit to review (default HEAD), base: what it is based on (default origin/main)}',
        properties: { dir: { type: 'string' }, ref: { type: 'string' }, base: { type: 'string' } } },
      title: { type: 'string', description: 'Default: the commit subject' },
      note: { type: 'string', description: 'What the reviewers should know (up to 4000 characters); data to them, not instructions' },
      review_id: { type: 'string', description: 'Idempotency key (8-64 of A-Z a-z 0-9 _ -); omitted → a fresh one, returned. A retry with the same id and diff is never charged twice.' } } } },
];
const HANDLERS = {
  fleetgate_onboard: onboard,
  fleetgate_prices: async () => { const r = await http('GET', (await door()) + '/v1/prices'); return r.status === 200 ? { ok: true, ...r.data } : { ok: false, http_status: r.status, ...(r.data || {}) }; },
  fleetgate_submit: submit,
  fleetgate_status: status,
  fleetgate_check: check,
  fleetgate_follow: follow,
  fleetgate_review: review,
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
    const args = (params && params.arguments) || {};
    let out; try { out = FREE_TOOLS.has(params.name) ? await withDeadline(() => h(args)) : await h(args); } catch (e) { out = errBody(e); }
    out = scrub(out);
    return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }], ...(out && out.ok === false ? { isError: true } : {}) } };
  }
  if (id === undefined) return null;
  return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
}

module.exports = { handleMessage, _gitEnv: gitEnv, _fundAsks: fundAsks, _reset: () => { held = null; consentSeen = null; doorCached = null; pendingCaps.clear(); asks.clear(); fundAsks.clear(); } };

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
