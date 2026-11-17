"use strict";
const fs=require("node:fs"),os=require("node:os"),path=require("node:path"),p=require("../../sealed/crypto"),
 {Guardian,Coordinator,makeGrant,approve}=require("../../sealed/guardian"),
 {Journal}=require("../../sealed/journal"),{ReleaseGate}=require("../../sealed/release-gate"),
 {statusFixture}=require("./sealed-status");
async function fixture(t) {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"release-gates-")), journals=[];
 t.after(()=>{for(const j of journals)j.close();fs.rmSync(dir,{recursive:true,force:true});});
 const journal=name=>{const j=new Journal(path.join(dir,name));journals.push(j);return j;};
 const sender=await p.identity("sender"),recipient=await p.identity("recipient"),
  ids=await Promise.all([0,1,2].map(i=>p.identity("guardian-"+i))),
  approvals=await Promise.all([0,1,2].map(i=>p.identity("approval-"+i)));
 const policy={version:1,epoch:1,threshold:2,assurance:"fixture",guardians:ids.map((id,i)=>({id:"guardian-"+i,
  publicKey:id.publicKey,approvalKey:approvals[i].publicKey.sign,
  domains:Object.fromEntries(["host","admin","credential","recovery"].map(k=>[k,k+"-"+i]))}))};
 const start=Date.now(),status=await statusFixture(policy,start), f={dir,journal,policy,sender,recipient,ids,approvals,status,time:start,feed:status.packet(),charges:0};
 const gates=[];
 const gate=name=>{const j=journal(name+"-status");const g=new ReleaseGate({policy,trusted:status.trusted,journal:j,
  feed:()=>f.feed,expected_checkpoint:"new",fixture:true,now:()=>f.time});gates.push({gate:g,journal:j});return g;};
 f.guardians=ids.map((identity,i)=>new Guardian({id:"guardian-"+i,identity,policy,sender:sender.publicKey,
  recipient:recipient.publicKey,journal:journal("guardian-"+i),fixture:true,admission:gate("guardian-"+i),now:()=>f.time}));
 const ledger=new Map();f.meter={identify:async()=>({wallet:"fixture-wallet",token_id:"fixture-token"}),
  precheck:async()=>{},lookup:async k=>ledger.get(k)||null,charge:async(w,c,k)=>{
   if(!ledger.has(k)){f.charges++;ledger.set(k,{wallet:w.wallet,action:"release",cost_dd:c,dd:c,charge_id:"charge-"+f.charges});}
   return ledger.get(k);}};
 f.coordinator=new Coordinator({policy,sender:sender.publicKey,recipient:recipient.publicKey,journal:journal("coordinator"),
  meter:f.meter,guardians:Object.fromEntries(f.guardians.map(g=>[g.id,r=>g.release({...r,approval:r.approvals[g.id]})])),
  fixture:true,admission:gate("coordinator"),now:()=>f.time});
 f.gates=gates;f.gate=gate;
 f.message=async()=>{const packet=await p.seal({sender,recipient:recipient.publicKey,plaintext:"actual private output",policy,fixture:true});
  const grant=makeGrant(packet.envelope,recipient,{now:f.time});return {...packet,grant,
   approvals:Object.fromEntries(policy.guardians.map((g,i)=>[g.id,approve(grant,g.id,approvals[i])]))};};
 f.req=await f.message();f.revoke=()=>{f.feed=status.packet(2,true,start);};return f;
}
module.exports={fixture};
