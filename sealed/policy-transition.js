"use strict";
// Non-mutating transition review. This never installs pins, rewrites capsules or enables live release.
const p=require("./crypto"),{verifyEnrollment}=require("./enrollment"),{evaluate}=require("./revocation");
const FORMAT="conduit-policy-transition-v1";
function reviewTransition(input) {
  p.fields(input,["current","next","proposal","approvals","now"]);
  const encoded=p.canonical(input);if(Buffer.byteLength(encoded)>131072)throw Error("transition packet too large");
  const {current,next,proposal,approvals,now}=JSON.parse(encoded);
  p.fields(current,["policy","trusted","evidence","snapshots","previous"]);
  p.fields(next,["policy","trusted","evidence"]);
  p.policyForUse(current.policy,{fixture:true});p.policyForUse(next.policy,{fixture:true});
  const status=evaluate({...current,now}),enrollment=verifyEnrollment({...next,now});
  p.fields(proposal,["format","from_policy","to_policy","from_context","to_context","current_checkpoint",
    "from_epoch","to_epoch","nonce","issued_at","expires_at"]);
  if(proposal.format!==FORMAT||proposal.from_policy!==p.hash(current.policy)||proposal.to_policy!==p.hash(next.policy)||
    proposal.from_context!==p.hash({policy:current.policy,trusted:current.trusted})||
    proposal.to_context!==p.hash({policy:next.policy,trusted:next.trusted})||
    proposal.current_checkpoint!==status.checkpoint_hash||proposal.from_epoch!==current.policy.epoch||
    proposal.to_epoch!==next.policy.epoch||proposal.to_epoch!==proposal.from_epoch+1||
    typeof proposal.nonce!=="string"||!/^[a-f0-9]{32}$/.test(proposal.nonce))throw Error("transition binding mismatch");
  if(!Number.isSafeInteger(proposal.issued_at)||!Number.isSafeInteger(proposal.expires_at)||
    proposal.issued_at<0||proposal.issued_at>now||proposal.expires_at<=now||
    proposal.expires_at<=proposal.issued_at||proposal.expires_at-proposal.issued_at>300000||
    proposal.expires_at>Math.min(status.expires_at,enrollment.expires_at))throw Error("transition lifetime invalid");
  if(!Array.isArray(approvals)||approvals.length<2||approvals.length>3)throw Error("existing governance quorum required");
  const seen=new Set();
  for(const a of approvals){
    p.fields(a,["guardian","signature"]);
    const g=current.policy.guardians.find(g=>g.id===a.guardian);
    if(!g||seen.has(g.id)||status.revoked.includes(g.id)||
      !p.verify({purpose:FORMAT,guardian:g.id,proposal},a.signature,g.approvalKey))throw Error("invalid existing governance approval");
    seen.add(g.id);
  }
  return {status:"fixture_transition_reviewed_not_installed",proposal_hash:p.hash(proposal),
    from_policy:proposal.from_policy,to_policy:proposal.to_policy,approving_guardians:[...seen],
    expires_at:proposal.expires_at,live_guardian_release:false,
    archive_rule:"preserve original identities, pins, ciphertext and paid packages; no automatic rewrap or history reset"};
}
module.exports={FORMAT,reviewTransition};
