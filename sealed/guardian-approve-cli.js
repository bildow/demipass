'use strict';
// Explicit custodian-side operation; no HTTP, enrollment or private key output.
const {readPrivate}=require('./client'),p=require('./crypto'),{validateGrant,approve}=require('./guardian');
function approval(configFile,requestFile){
 const cfg=readPrivate(configFile),r=readPrivate(requestFile);
 p.fields(cfg,['guardian_id','approval_identity','policy','sender','recipient']);p.fields(r,['envelope','capsule','grant']);
 p.policyShape(cfg.policy);const g=cfg.policy.guardians.find(g=>g.id===cfg.guardian_id);
 if(!g||p.canonical(g.approvalKey)!==p.canonical(cfg.approval_identity.publicKey.sign))throw Error('approval identity mismatch');
 const header=p.validateEnvelope(r.envelope,cfg.sender,cfg.recipient);p.validateCapsule(r.envelope,r.capsule);
 if(header.policy_hash!==p.hash(cfg.policy)||header.mode!=='guarded')throw Error('wrong policy');
 validateGrant(r.grant,r.envelope,cfg.recipient);
 return approve(r.grant,cfg.guardian_id,cfg.approval_identity);
}
if(require.main===module){try{if(process.argv.length!==4)throw Error('usage');process.stdout.write(JSON.stringify(approval(process.argv[2],process.argv[3]))+'\n');}catch{process.stderr.write('guardian approval refused; check pinned request, expiry and local identity\n');process.exitCode=2;}}
module.exports={approval};
