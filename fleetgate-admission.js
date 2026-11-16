'use strict';
// Free authenticated readiness, shared by generic service setup and the running Fleetgate MCP.
async function fleetgateAdmission({ endpoint, token, wallet, timeoutMs = 15000 }) {
  const no = (error, extra = {}) => ({ ok: false, status: 'admission_required', error, ...extra });
  try {
    const u = new URL(endpoint);
    if (u.username || u.password || u.search || u.hash || !(u.protocol === 'https:' || (u.protocol === 'http:' && ['127.0.0.1','localhost','[::1]'].includes(u.hostname)))) return no('Fleetgate admission requires an HTTPS endpoint');
    const r = await require('./http-json').requestJson('POST', endpoint.replace(/\/+$/, '') + '/v1/onboard', {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: {}, timeoutMs: Math.max(1, Math.min(15000, timeoutMs)) });
    const d = r.data, a = d && d.admission;
    if (r.status !== 200 || !d || d.ok !== true) return no('Fleetgate admission refused or unavailable; payment consent alone is not readiness', { http_status:r.status, detail:d && typeof d.error === 'string' ? d.error : 'No admission evidence' });
    if (d.wallet !== wallet || !a || a.ok !== true || a.protocol !== 1 || a.release_authorized !== false || !/^[0-9a-f]{64}$/.test(a.charter_sha256) || !Array.isArray(a.lanes) || !a.lanes.length || !a.lanes.every(l => typeof l.name === 'string' && Array.isArray(l.repos) && l.repos.length && ['paths','add_only','deny'].every(k => Array.isArray(l[k]) && l[k].every(v => typeof v === 'string')))) return no('Fleetgate returned invalid or wrong-wallet admission evidence');
    // The token's spend as the door reports it from DemiPass verify (fleetgate-door/3); only well-formed numbers.
    const sp = d.spend, num = v => Number.isSafeInteger(v) && v >= 0;
    const spend = sp && num(sp.token_cap_dd) && num(sp.token_spent_dd) && num(sp.follow_up_dd)
      ? { token_cap_dd: sp.token_cap_dd, token_spent_dd: sp.token_spent_dd, follow_up_dd: sp.follow_up_dd } : null;
    return { ok:true, admission:a, ...(spend ? { spend } : {}) };
  } catch (_) { return no('Fleetgate admission could not be verified; no submission was attempted'); }
}
// The fleetgate consent's default daily cap, for the MCP's fleetgate_onboard and for demipass-onboard alike (code pass
// 2026-11-16, item 4). It must cover the door's follow-up floor (1,800 DD, atlas/boltcluster #90) plus the intake.
// FLEETGATE_DAILY_CAP_DD overrides it on both paths.
const FLEETGATE_DEFAULT_CAP_DD = 3000;
function fleetgateDefaultCap(env = process.env) {
  const n = Number(env.FLEETGATE_DAILY_CAP_DD);
  return Number.isInteger(n) && n > 0 ? n : FLEETGATE_DEFAULT_CAP_DD;
}
module.exports = { fleetgateAdmission, FLEETGATE_DEFAULT_CAP_DD, fleetgateDefaultCap };
