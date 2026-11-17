"use strict";
// Disposable issuer keys only. No test identity is independent custody evidence.
const p = require("../../sealed/crypto"), e = require("../../sealed/enrollment"), r = require("../../sealed/revocation");
async function statusFixture(policy, now = Date.now()) {
  const issuers = await Promise.all([0,1,2].map(i => p.identity("status-issuer-" + i)));
  const trusted = policy.guardians.map((g,i) => ({ guardian_id:g.id, issuer_id:"issuer-"+i,
    issuer_key:issuers[i].publicKey.sign, deployment_sha256:p.hash({deployment:i}) }));
  const sign = (body,i) => ({...body,signature:p.sign(body,issuers[i].signPrivate)});
  const evidence = policy.guardians.map((g,i) => sign({format:e.FORMAT, policy_hash:p.hash(policy),
    guardian_id:g.id,guardian_fingerprint:p.keyId(g.publicKey),approval_key_hash:p.hash(g.approvalKey),
    domains:g.domains,deployment_sha256:trusted[i].deployment_sha256,issued_at:now-1000,
    expires_at:now+600000,issuer_id:trusted[i].issuer_id},i));
  const packet = (serial=1, revoked=false, at=now) => ({evidence,
    snapshots:policy.guardians.map((g,i)=>sign({format:r.FORMAT,policy_hash:p.hash(policy),
      guardian_id:g.id,issuer_id:trusted[i].issuer_id,serial,state:revoked&&i===0?"revoked":"active",
      issued_at:at-100,expires_at:at+120000},i))});
  return {trusted,packet,sign};
}
module.exports={statusFixture};
