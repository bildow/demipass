'use strict';
// Free authenticated readiness, shared by generic service setup and the running Fleetgate MCP.
async function fleetgateAdmission({ endpoint, token, wallet }) {
  const no = (error, extra = {}) => ({ ok: false, status: 'admission_required', error, ...extra });
  try {
    const u = new URL(endpoint);
    if (u.username || u.password || u.search || u.hash || !(u.protocol === 'https:' || (u.protocol === 'http:' && ['127.0.0.1','localhost','[::1]'].includes(u.hostname)))) return no('Fleetgate admission requires an HTTPS endpoint');
    const r = await require('./http-json').requestJson('POST', endpoint.replace(/\/+$/, '') + '/v1/onboard', {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: {}, timeoutMs: 15000 });
    const d = r.data, a = d && d.admission;
    if (r.status !== 200 || !d || d.ok !== true) return no('Fleetgate admission refused or unavailable; payment consent alone is not readiness', { http_status:r.status, detail:d && typeof d.error === 'string' ? d.error : 'No admission evidence' });
    if (d.wallet !== wallet || !a || a.ok !== true || a.protocol !== 1 || a.release_authorized !== false || !/^[0-9a-f]{64}$/.test(a.charter_sha256) || !Array.isArray(a.lanes) || !a.lanes.length || !a.lanes.every(l => typeof l.name === 'string' && Array.isArray(l.repos) && l.repos.length && ['paths','add_only','deny'].every(k => Array.isArray(l[k]) && l[k].every(v => typeof v === 'string')))) return no('Fleetgate returned invalid or wrong-wallet admission evidence');
    return { ok:true, admission:a };
  } catch (_) { return no('Fleetgate admission could not be verified; no submission was attempted'); }
}
module.exports = { fleetgateAdmission };
