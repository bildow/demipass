'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process'),p=require('../sealed/crypto');
const {writeNew}=require('../sealed/client'),{sourceDigest}=require('../sealed/readiness');
const {loadAuthorization}=require('../sealed/runtime-authorization'),{ReleaseGate}=require('../sealed/release-gate');
const {Guardian,Coordinator,makeGrant,approve}=require('../sealed/guardian'),{Journal}=require('../sealed/journal');
const {statusFixture}=require('./helpers/sealed-status');
async function fixture(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'conduit-runtime-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const ids=await Promise.all([0,1,2].map(i=>p.identity('guardian-'+i))),approvers=await Promise.all([0,1,2].map(i=>p.identity('approver-'+i)));
 const policy={version:1,epoch:1,threshold:2,assurance:'reviewed',guardians:ids.map((g,i)=>({id:'guardian-'+i,publicKey:g.publicKey,approvalKey:approvers[i].publicKey.sign,domains:Object.fromEntries(['host','admin','credential','recovery'].map(k=>[k,k+'-test-'+i]))}))};
 const status=await statusFixture(policy);let packet=status.packet();
 const permit=(role)=>{const file=path.join(dir,role+'-permit.json');writeNew(file,{format:'conduit-runtime-permit-v1',state:'armed',role,policy_hash:p.hash(policy),source_sha256:sourceDigest(),custody_tome_commit:'a'.repeat(40),acceptance_sha256:'b'.repeat(64),expires_at:Date.now()+600000});return {file,authorization:loadAuthorization(file,policy,role)};};
 const journals=[];const journal=name=>{const j=new Journal(path.join(dir,name+'.jsonl'));journals.push(j);return j;};t.after(()=>journals.forEach(j=>{try{j.close();}catch{}}));
 return {dir,ids,approvers,policy,status,permit,journal,feed:()=>packet,revoke:()=>{packet=status.packet(2,true);}};
}
test('reviewed policy cannot self-enable; private permit binds source/role/expiry and is revoked by removal',async t=>{
 const f=await fixture(t);assert.throws(()=>p.policyForUse(f.policy),/disabled/);assert.throws(()=>p.policyForUse(f.policy,{authorization:{}}));
 const a=f.permit('endpoint');assert.equal(p.policyForUse(f.policy,{authorization:a.authorization}),f.policy);
 assert.throws(()=>loadAuthorization(a.file,f.policy,'guardian'));
 const obj=JSON.parse(fs.readFileSync(a.file));for(const change of [{state:'disabled'},{source_sha256:'0'.repeat(64)},{expires_at:Date.now()-1},{custody_tome_commit:null}]){
  fs.writeFileSync(a.file,JSON.stringify({...obj,...change}));assert.throws(()=>loadAuthorization(a.file,f.policy,'endpoint'));assert.throws(()=>p.policyForUse(f.policy,{authorization:a.authorization}));
 }
 fs.unlinkSync(a.file);assert.throws(()=>p.policyForUse(f.policy,{authorization:a.authorization}));
});
test('reviewed runtime executes crypto, independent approvals, one fee and retained paid replay; revoked new requests hold',async t=>{
 const f=await fixture(t),sender=await p.identity('sender'),recipient=await p.identity('recipient');
 const gp=f.permit('guardian'),cp=f.permit('coordinator'),ep=f.permit('endpoint');
 const gate=(name,authorization)=>new ReleaseGate({policy:f.policy,trusted:f.status.trusted,feed:f.feed,journal:f.journal(name+'-status'),expected_checkpoint:'new',authorization});
 const gs=f.ids.map((identity,i)=>new Guardian({id:'guardian-'+i,identity,policy:f.policy,sender:sender.publicKey,recipient:recipient.publicKey,journal:f.journal('g'+i),admission:gate('g'+i,gp.authorization),authorization:gp.authorization}));
 let charges=0;const paid=new Map(),meter={identify:async()=>({wallet:'fixture-payer',token_id:'t'}),precheck:async()=>{},lookup:async key=>paid.get(key),charge:async(w,c,key)=>{charges++;const v={wallet:w.wallet,action:'release',cost_dd:2,dd:2,charge_id:'fixture-charge'};paid.set(key,v);return v;}};
 const c=new Coordinator({policy:f.policy,sender:sender.publicKey,recipient:recipient.publicKey,journal:f.journal('coord'),admission:gate('coord',cp.authorization),authorization:cp.authorization,meter,guardians:Object.fromEntries(gs.map(g=>[g.id,r=>g.release({...r,approval:r.approvals[g.id]})]))});
 const packet=await p.seal({sender,recipient:recipient.publicKey,plaintext:'test-only guarded result',policy:f.policy,authorization:ep.authorization});
 const grant=makeGrant(packet.envelope,recipient);const approvals=Object.fromEntries(f.policy.guardians.map((g,i)=>[g.id,approve(grant,g.id,f.approvers[i])]));const req={...packet,grant,approvals};
 await assert.rejects(c.release({...req,approvals:{}},'fixture'));assert.equal(charges,0);
 const out=await c.release(req,'fixture');assert.equal(charges,1);assert.equal(await p.open({...packet,recipient,sender:sender.publicKey,policy:f.policy,release:out}),'test-only guarded result');
 f.revoke();assert.equal((await c.release(req,'fixture')).replayed,true);assert.equal(charges,1);
 await assert.rejects(gs[0].release({...req,approval:approvals[gs[0].id]}));
});
test('TLS listener refuses plaintext and arbitrary permits; explicit private permit permits only TLS transport',async t=>{
 const f=await fixture(t),a=f.permit('guardian'),{serve}=require('../sealed/http');
 assert.throws(()=>serve(()=>({}),{token:'x'.repeat(32)}));
 assert.throws(()=>serve(()=>({}),{token:'x'.repeat(32),authorization:{},policy:f.policy,tls:{key:'x',cert:'x'}}));
 const key=path.join(f.dir,'tls.key'),cert=path.join(f.dir,'tls.crt');
 const gen=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1','-days','1'],{stdio:'ignore'});assert.equal(gen.status,0);
 const server=await serve(()=>({ok:true}),{token:'x'.repeat(32),tls:{key:fs.readFileSync(key,'utf8'),cert:fs.readFileSync(cert,'utf8')},authorization:a.authorization,policy:f.policy});t.after(server.close);
 assert.match(server.url,/^https:/);
 const https=require('node:https');
 const call=token=>new Promise((resolve,reject)=>{const req=https.request(server.url+'/release',{method:'POST',ca:fs.readFileSync(cert),headers:{authorization:'Bearer '+token}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);req.end('{}');});
 assert.equal(await call('bad'),403);assert.equal(await call('x'.repeat(32)),200);
});
test('guarded MCP inputs cannot inject paths, tokens, permits, policy or a fixture switch',()=>{
 const {invoke}=require('../sealed/endpoint-mcp');for(const field of ['path','directory','token','authorization','policy','fixture'])assert.throws(()=>invoke('prepare',{plaintext:'x',[field]:'bad'}));
 const old=process.env.DEMIPASS_SEALED_RUNTIME_DIRECTORY;delete process.env.DEMIPASS_SEALED_RUNTIME_DIRECTORY;
 try{assert.throws(()=>invoke('prepare',{plaintext:'x'}),/not configured/);}finally{if(old!==undefined)process.env.DEMIPASS_SEALED_RUNTIME_DIRECTORY=old;}
});
test('actual MCP child -> locked endpoint -> TLS coordinator: signed fee, decrypt/ack, restart replay and dispute', {timeout:30000}, async t=>{
 const f=await fixture(t),{Client}=require('../sealed/client'),{meterFixture}=require('./helpers/sealed-meter'),{DemiPassMeter}=require('../sealed/demipass-meter');
 const directory=path.join(f.dir,'keys'),senderClient=new Client({directory,mailbox:'sender'}),recipientClient=new Client({directory,mailbox:'recipient'});
 await senderClient.initialize();await recipientClient.initialize();const sender=senderClient.key(),recipient=recipientClient.key();
 const gp=f.permit('guardian'),cp=f.permit('coordinator'),ep=f.permit('endpoint');
 const gate=(name,authorization)=>new ReleaseGate({policy:f.policy,trusted:f.status.trusted,feed:f.feed,journal:f.journal(name+'-status'),expected_checkpoint:'new',authorization});
 const guardians=f.ids.map((identity,i)=>new Guardian({id:'guardian-'+i,identity,policy:f.policy,sender:sender.publicKey,recipient:recipient.publicKey,journal:f.journal('gg'+i),admission:gate('gg'+i,gp.authorization),authorization:gp.authorization}));
 const meter=await meterFixture();t.after(meter.close);
 const coord=new Coordinator({policy:f.policy,sender:sender.publicKey,recipient:recipient.publicKey,journal:f.journal('coordinator'),admission:gate('coordinator',cp.authorization),authorization:cp.authorization,meter:new DemiPassMeter(meter.config),guardians:Object.fromEntries(guardians.map(g=>[g.id,r=>g.release({...r,approval:r.approvals[g.id]})]))});
 const key=path.join(f.dir,'tls-key'),cert=path.join(f.dir,'tls-cert');assert.equal(spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1','-days','1'],{stdio:'ignore'}).status,0);
 const transport='t'.repeat(40),server=await require('../sealed/http').serve(b=>b.operation==='dispute'?coord.dispute(b.request,b.payer_token,b.complaint):coord.release(b.request,b.payer_token),{token:transport,tls:{key:fs.readFileSync(key,'utf8'),cert:fs.readFileSync(cert,'utf8')},authorization:cp.authorization,policy:f.policy});t.after(server.close);
 const instance=path.join(f.dir,'endpoint');fs.mkdirSync(instance,{mode:0o700});
 const feed=path.join(f.dir,'feed.json'),payer=path.join(f.dir,'payer.json');writeNew(feed,f.feed());writeNew(payer,{token:'fixture-payer-token'});
 writeNew(path.join(instance,'config.json'),{format:'conduit-endpoint-runtime-v1',permit_file:ep.file,policy:f.policy,admission:{trusted:f.status.trusted,feed_file:feed,expected_checkpoint:'new'},sender:sender.publicKey,recipient:recipient.publicKey,coordinator:{url:server.url,token:transport},payer_token_file:payer,payer_wallet:'fixture-wallet',meter_issuer:meter.config.issuer,client_directory:directory});
 const call=(name,args)=>new Promise((resolve,reject)=>{
  const child=require('node:child_process').spawn(process.execPath,[path.resolve(__dirname,'../mcp-server.js')],{env:{PATH:process.env.PATH,HOME:f.dir,NODE_EXTRA_CA_CERTS:cert,DEMIPASS_SEALED_RUNTIME_DIRECTORY:instance},stdio:['pipe','pipe','pipe']});const chunks=[];let err='';
  const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('test MCP deadline'));},10000);child.stdout.on('data',b=>chunks.push(b));child.stderr.on('data',b=>err+=b);
  child.on('close',code=>{clearTimeout(timer);try{assert.equal(code,0,err);const out=Buffer.concat(chunks).toString('utf8'),r=JSON.parse(out);if(r.error||r.result.isError)throw Error(out);resolve(JSON.parse(r.result.content[0].text));}catch(e){reject(e);}});
  child.stdin.end(JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'conduit_guarded_'+name,arguments:args}})+'\n');
 });
 const plaintext='MCP actual return — 雪 🪿 '.repeat(700);
 const prepared=await call('prepare',{plaintext,padding:'none'});const packet=JSON.parse(senderClient.transport(prepared.id).body);packet.capsule=senderClient.capsule(prepared.id);
 const grant=await call('grant',packet);const approvals=Object.fromEntries(f.policy.guardians.slice(0,2).map((g,i)=>[g.id,approve(grant.grant,g.id,f.approvers[i])]));
 await assert.rejects(call('release',{request_id:grant.request_id,approvals:{}}));assert.equal(meter.state.charges,0);
 const result=await call('release',{request_id:grant.request_id,approvals});assert.equal(result.plaintext,plaintext);assert.equal(result.charge.dd,2);assert.equal(result.ack.body.event,'decrypted');assert.equal(meter.state.charges,1);
 const replay=await call('release',{request_id:grant.request_id,approvals});assert.equal(replay.replayed,true);assert.equal(meter.state.charges,1);assert.equal(replay.charge.charge_id,result.charge.charge_id);
 const body={version:1,type:'conduit-release-dispute',envelope_hash:grant.request_id,grant_hash:p.hash(grant.grant.body),reason:'billing_mismatch'};
 const dispute=await call('dispute',{request_id:grant.request_id,complaint:{body,signature:p.sign(body,recipient.signPrivate)}});assert.equal(dispute.status,'manual_review_required');assert.equal(dispute.refund,'not_issued');assert.equal(meter.state.charges,1);
 const checkpoint=JSON.parse(fs.readFileSync(path.join(instance,'checkpoint-pin.json')));assert.match(checkpoint.checkpoint,/^[a-f0-9]{64}$/);
 fs.unlinkSync(path.join(instance,'checkpoint-pin.json'));await assert.rejects(call('grant',packet));assert.equal(meter.state.charges,1);
});
test('installation plan never arms or creates state; custodian signing verifies recipient and rejects another key',async t=>{
 const f=await fixture(t),{plan}=require('../sealed/installation-plan'),before=fs.readdirSync(f.dir);
 assert.equal(plan(path.join(f.dir,'not-created'),'guardian').live_guardian_release,false);assert.deepEqual(fs.readdirSync(f.dir),before);assert.throws(()=>plan('relative','guardian'));
 const sender=await p.identity('sender'),recipient=await p.identity('recipient'),auth=f.permit('endpoint');
 const packet=await p.seal({sender,recipient:recipient.publicKey,plaintext:'approval test',policy:f.policy,authorization:auth.authorization});
 const grant=makeGrant(packet.envelope,recipient),cf=path.join(f.dir,'approval.json'),rf=path.join(f.dir,'request.json');
 const cfg={guardian_id:f.policy.guardians[0].id,approval_identity:f.approvers[0],policy:f.policy,sender:sender.publicKey,recipient:recipient.publicKey};writeNew(cf,cfg);writeNew(rf,{...packet,grant});
 const got=require('../sealed/guardian-approve-cli').approval(cf,rf);require('../sealed/guardian').checkApproval(got,f.policy.guardians[0],grant,p.hash(grant.body));
 fs.writeFileSync(cf,JSON.stringify({...cfg,approval_identity:f.approvers[1]}));assert.throws(()=>require('../sealed/guardian-approve-cli').approval(cf,rf));
});
