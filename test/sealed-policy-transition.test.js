"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),crypto=require("node:crypto"),
 p=require("../sealed/crypto"),{evaluate}=require("../sealed/revocation"),{FORMAT,reviewTransition}=require("../sealed/policy-transition"),
 {statusFixture}=require("./helpers/sealed-status"),{fixture}=require("./helpers/sealed-release-fixture");
async function transition(t){const f=await fixture(t),nextPolicy={...f.policy,epoch:2},status=await statusFixture(nextPolicy,f.time);
 const current={policy:f.policy,trusted:f.status.trusted,...f.feed,previous:null},next={policy:nextPolicy,trusted:status.trusted,evidence:status.packet().evidence};
 const proposal={format:FORMAT,from_policy:p.hash(current.policy),to_policy:p.hash(next.policy),
 from_context:p.hash({policy:current.policy,trusted:current.trusted}),to_context:p.hash({policy:next.policy,trusted:next.trusted}),
 current_checkpoint:evaluate({...current,now:f.time}).checkpoint_hash,from_epoch:1,to_epoch:2,
 nonce:crypto.randomBytes(16).toString("hex"),issued_at:f.time,expires_at:f.time+60000};
 const sign=(proposal,i)=>({guardian:"guardian-"+i,signature:p.sign({purpose:FORMAT,guardian:"guardian-"+i,proposal},f.approvals[i].signPrivate)});
 return {f,sign,input:{current,next,proposal,approvals:[sign(proposal,0),sign(proposal,1)],now:f.time}};}
test("existing distinct governance quorum reviews a monotonic, pin-bound transition without installing authority",async t=>{
 const {input}=await transition(t),before=JSON.stringify(input),out=reviewTransition(input);
 assert.equal(out.status,"fixture_transition_reviewed_not_installed");assert.equal(out.live_guardian_release,false);
 assert.equal(JSON.stringify(input),before);assert.equal(out.approving_guardians.length,2);
});
test("transition rejects duplicate, new/unknown, wrong-audience, expired and altered policy approvals",async t=>{
 const {input}=await transition(t);
 const cases={duplicate:x=>{x.approvals[1]=x.approvals[0];},missing:x=>x.approvals.pop(),
  unknown:x=>{x.approvals[0].guardian="new-guardian";},audience:x=>{x.approvals[0].guardian="guardian-2";},
  pinChange:x=>{x.next.trusted[0].deployment_sha256="0".repeat(64);},
  policyChange:x=>{x.next.policy.guardians[0].domains.admin="changed-admin";},
  epoch:x=>{x.next.policy.epoch=3;},expired:x=>{x.now=x.proposal.expires_at;},
  checkpoint:x=>{x.proposal.current_checkpoint="0".repeat(64);},
  excess:x=>{x.approvals.push(x.approvals[0],x.approvals[0]);}};
 for(const [name,mutate]of Object.entries(cases))await t.test(name,()=>{const x=structuredClone(input);mutate(x);assert.throws(()=>reviewTransition(x));});
});
test("revoked governor cannot vote; two remaining current governors can review the next epoch",async t=>{
 const {f,input,sign}=await transition(t);input.current.snapshots=f.status.packet(2,true).snapshots;
 input.proposal.current_checkpoint=evaluate({...input.current,now:f.time}).checkpoint_hash;
 input.approvals=[sign(input.proposal,0),sign(input.proposal,1)];assert.throws(()=>reviewTransition(input),/governance/);
 input.approvals=[sign(input.proposal,1),sign(input.proposal,2)];assert.equal(reviewTransition(input).live_guardian_release,false);
});
