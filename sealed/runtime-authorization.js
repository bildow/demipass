"use strict";
// An operator-owned, short-lived launch permit. Never accepted through MCP/HTTP.
// This binds an operator decision; it cannot prove separate physical custodians.
const p=require('./crypto'),{readPrivate}=require('./client');
const permits=new WeakMap();
function loadAuthorization(file, policy, role) {
  if(typeof file!=='string'||!require('node:path').isAbsolute(file))throw Error('absolute operator permit required');
  const permit=readPrivate(file);
  p.fields(permit,['format','state','role','policy_hash','source_sha256','custody_tome_commit','acceptance_sha256','expires_at']);
  if(permit.format!=='conduit-runtime-permit-v1'||permit.state!=='armed'||permit.role!==role||
     !['guardian','coordinator','endpoint'].includes(role)||permit.policy_hash!==p.hash(policy)||
     !/^[a-f0-9]{40}$/.test(permit.custody_tome_commit)||!/^[a-f0-9]{64}$/.test(permit.acceptance_sha256)||
     !/^[a-f0-9]{64}$/.test(permit.source_sha256))throw Error('operator permit held');
  const obj=Object.freeze({});permits.set(obj,{file,permit,digest:p.hash(permit)});
  assertAuthorization(obj,policy,role);return obj;
}
function assertAuthorization(obj,policy,role) {
  const s=permits.get(obj);if(!s)throw Error('operator launch authorization required');
  const now=Date.now();
  if(!Number.isSafeInteger(s.permit.expires_at)||s.permit.expires_at<=now||s.permit.expires_at>now+86400000||
     (role&&s.permit.role!==role)||s.permit.policy_hash!==p.hash(policy)||policy.assurance!=='reviewed'||
     p.hash(readPrivate(s.file))!==s.digest||require('./readiness').sourceDigest()!==s.permit.source_sha256)
    throw Error('operator permit expired, changed or source mismatched');
  return s.permit;
}
module.exports={loadAuthorization,assertAuthorization};
