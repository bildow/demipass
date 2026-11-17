"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),
 {spawnSync}=require("node:child_process"),p=require("../sealed/crypto"),{ReleaseGate}=require("../sealed/release-gate"),
 {Guardian,Coordinator}=require("../sealed/guardian"),{readPrivate}=require("../sealed/client"),{fixture}=require("./helpers/sealed-release-fixture");
test("actual release requires a configured verified gate; request data cannot supply authority",async t=>{
 const f=await fixture(t),base={policy:f.policy,sender:f.sender.publicKey,recipient:f.recipient.publicKey,fixture:true};
 for(const C of [Guardian,Coordinator]) for(const admission of [undefined,{check:()=>({verdict:"evidence_current"})}])
  assert.throws(()=>new C({...base,admission}),/gate/);
 const g=f.gates[0].gate;f.feed={...f.feed,trusted:f.status.trusted};assert.throws(()=>g.check());
});
test("missing, forged, expired and revoked feed refuses real guardian retry and unpaid coordinator",async t=>{
 for(const mode of ["missing","forged","expired","revoked"]) await t.test(mode,async t=>{
  const f=await fixture(t),g=f.guardians[0],req={...f.req,approval:f.req.approvals[g.id]};
  await g.release(req); // Even a previously saved share must pass today's check.
  if(mode==="missing") f.feed={evidence:f.feed.evidence,snapshots:[]};
  if(mode==="forged") f.feed.snapshots[0].signature="A".repeat(86);
  if(mode==="expired") f.time+=120001;
  if(mode==="revoked") f.revoke();
  await assert.rejects(g.release(req));await assert.rejects(f.coordinator.release(f.req,"token"));assert.equal(f.charges,0);
 });
});
test("revocation during guardian crypto prevents response persistence or disclosure",async t=>{
 const f=await fixture(t),wrap=p.wrap; t.after(()=>{p.wrap=wrap;});
 p.wrap=async(...args)=>{const out=await wrap(...args);if(args[2].role==="released-share")f.revoke();return out;};
 await assert.rejects(f.guardians[0].release({...f.req,approval:f.req.approvals["guardian-0"]}),/holds/);
 assert.equal(f.guardians[0].journal.get("guardian:guardian-0:"+f.req.grant.body.request_id),undefined);
 assert.equal(f.gates[0].journal.get("checkpoint").entries["guardian-0"].revoked,true);
});
test("coordinator rechecks after remote responses and immediately before unpaid charge",async t=>{
 for(const when of ["responses","precharge"])await t.test(when,async t=>{
  const f=await fixture(t);
  if(when==="responses"){
   const old=f.coordinator.guardians["guardian-2"];
   f.coordinator.guardians["guardian-2"]=async r=>{const out=await old(r);f.revoke();return out;};
  }else{let n=0;f.meter.precheck=async()=>{if(++n===2)f.revoke();};}
  await assert.rejects(f.coordinator.release(f.req,"token"),/holds/);assert.equal(f.charges,0);
 });
});
test("prepared unpaid retry holds on revocation, paid retry returns only original package",async t=>{
 const f=await fixture(t),charge=f.meter.charge;f.meter.charge=async()=>{throw Error("uncertain charge");};
 await assert.rejects(f.coordinator.release(f.req,"token"),/uncertain/);f.revoke();f.meter.charge=charge;
 await assert.rejects(f.coordinator.release(f.req,"token"),/holds/);assert.equal(f.charges,0);
 const q=await fixture(t),paid=await q.coordinator.release(q.req,"token");q.revoke();
 const replay=await q.coordinator.release(q.req,"token");assert.equal(q.charges,1);assert.equal(replay.replayed,true);
 assert.deepEqual(replay.responses,paid.responses);
 await assert.rejects(q.coordinator.release(await q.message(),"token"),/holds/);assert.equal(q.charges,1);
});
test("uncertain paid lookup recovers original package even after revocation without another charge",async t=>{
 const f=await fixture(t),charge=f.meter.charge;f.meter.charge=async(...args)=>{await charge(...args);throw Error("lost reply");};
 await assert.rejects(f.coordinator.release(f.req,"token"),/lost reply/);assert.equal(f.charges,1);f.revoke();
 const out=await f.coordinator.release(f.req,"token");assert.equal(out.charge.dd,2);assert.equal(f.charges,1);
 assert.equal(await p.open({...f.req,sender:f.sender.publicKey,recipient:f.recipient,policy:f.policy,release:out}),"actual private output");
});
test("restart needs retained checkpoint; sticky revocation and persistence uncertainty cannot auto-clear",async t=>{
 const f=await fixture(t),{gate,journal}=f.gates[0];gate.check();const old=p.hash(journal.get("checkpoint"));f.revoke();
 assert.throws(()=>gate.check(),/holds/);const current=p.hash(journal.get("checkpoint"));
 const cfg={policy:f.policy,trusted:f.status.trusted,journal,feed:()=>f.feed,fixture:true,now:()=>f.time};
 for(const expected_checkpoint of ["new",old])assert.throws(()=>new ReleaseGate({...cfg,expected_checkpoint}),/reconciliation/);
 const restarted=new ReleaseGate({...cfg,expected_checkpoint:current});f.feed=f.status.packet(3);
 assert.throws(()=>restarted.check(),/holds/);
 const q=await fixture(t),g=q.gates[0],set=g.journal.set.bind(g.journal);g.journal.set=()=>{throw Error("fsync");};
 assert.throws(()=>g.gate.check(),/fsync/);g.journal.set=set;assert.throws(()=>g.gate.check(),/uncertain/);
});
test("private feed FIFO and instance lock FIFO refuse in bounded processes",async t=>{
 const f=await fixture(t),fifo=path.join(f.dir,"feed");assert.equal(spawnSync("mkfifo",["-m","600",fifo]).status,0);
 const read=spawnSync(process.execPath,["-e","require('./sealed/client').readPrivate(process.argv[1])",fifo],{cwd:path.resolve(__dirname,".."),timeout:2000});
 assert.equal(read.error,undefined);assert.notEqual(read.status,0);
 assert.equal(spawnSync("mkfifo",["-m","600",path.join(f.dir,"lease.lock")]).status,0);
 const run=spawnSync("sh",[path.resolve(__dirname,"../sealed/service.sh"),f.dir],{timeout:2000});
 assert.equal(run.error,undefined);assert.equal(run.status,2);
});

test("expiry during status or share fsync cannot disclose a share",async t=>{
 for(const where of ["status","share"])await t.test(where,async t=>{
  const f=await fixture(t),j=where==="status"?f.gates[0].journal:f.guardians[0].journal,set=j.set.bind(j);
  j.set=(...args)=>{set(...args);f.time+=120001;};
  await assert.rejects(f.guardians[0].release({...f.req,approval:f.req.approvals["guardian-0"]}));
 });
});
