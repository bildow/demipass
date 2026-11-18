"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {spawnSync}=require("node:child_process"),p=require("../sealed/crypto");
const r=require("../sealed/readiness"),{evaluate}=require("../sealed/revocation");
const {statusFixture}=require("./helpers/sealed-status");
const copy=x=>JSON.parse(JSON.stringify(x));
function directory(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),"readiness-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));return dir;}
async function sample(){
 const ids=await Promise.all([0,1,2].map(i=>p.identity("guardian-"+i)));
 const approvals=await Promise.all([0,1,2].map(i=>p.identity("approver-"+i)));
 const peers=await Promise.all(r.ROLES.map(role=>p.identity(role)));
 const policy={version:1,epoch:1,threshold:2,assurance:"fixture",guardians:ids.map((id,i)=>({id:"guardian-"+i,publicKey:id.publicKey,approvalKey:approvals[i].publicKey.sign,domains:Object.fromEntries(["host","admin","credential","recovery"].map(k=>[k,k+"-"+i]))}))};
 const now=Date.now(),status=await statusFixture(policy,now),source=r.sourceDigest();
 return {now,status,actual_source_sha256:source,evidence:status.packet(),config:{format:r.FORMAT,participants:r.ROLES.map((role,i)=>({role,mailbox:role,public_key:peers[i].publicKey})),source_sha256:source,policy,trusted:status.trusted,previous:null}};
}
test("pinned Brain/Claude/Codex and current signed evidence produce inspection only, with no mutation",async()=>{
 const f=await sample(),before=JSON.stringify(f.config),got=r.inspect(f);
 assert.equal(got.status,"fixture_evidence_current_live_disabled");assert.equal(got.live_guardian_release,false);
 assert.deepEqual(got.participants.map(x=>x.role),r.ROLES);assert(got.deployment_blockers.includes("live_mcp_release_integration"));
 assert.equal(JSON.stringify(f.config),before);assert.equal(f.config.previous,null);
});
test("missing setup lists missing custody without creating identity or adopting applicants' pins",()=>{
 const got=r.inspect({config:null,evidence:null,now:10});assert.equal(got.status,"hold");assert.equal(got.live_guardian_release,false);
 const cfg={format:r.FORMAT,participants:r.ROLES.map(role=>({role,mailbox:role,public_key:null})),source_sha256:null,policy:null,trusted:[],previous:null};
 const out=r.inspect({config:cfg,evidence:{trusted:"untrusted"},now:10});assert.equal(out.status,"hold");assert(out.checks.some(x=>x.id==="guardian_evidence"&&x.state==="missing"));
});
test("malformed source, peer, key, shared control and authority inputs hold",async t=>{
 const original=await sample();
 const cases={missing_brain:f=>f.config.participants.pop(),duplicate_role:f=>f.config.participants[1].role="brain",shared_mailbox:f=>f.config.participants[1].mailbox="brain",wrong_mailbox_key:f=>f.config.participants[0].public_key.mailbox="wrong",shared_signing_key:f=>f.config.participants[1].public_key.sign=f.config.participants[0].public_key.sign,unknown_field:f=>f.config.enable_live=true,missing_source:f=>f.config.source_sha256=null,moved_source:f=>f.actual_source_sha256="0".repeat(64),missing_peer_pin:f=>f.config.participants[2].public_key=null,shared_admin:f=>f.config.policy.guardians[1].domains.admin=f.config.policy.guardians[0].domains.admin,shared_issuer:f=>f.config.trusted[1].issuer_key=f.config.trusted[0].issuer_key,forged_signature:f=>f.evidence.snapshots[0].signature="forged",expired:f=>f.now+=600001,unreadable_shape:f=>f.evidence=[],nonobject:f=>f.config=null};
 for(const [name,mutate]of Object.entries(cases))await t.test(name,()=>{const f=copy(original);mutate(f);const got=r.inspect(f);assert.equal(got.status,"hold");assert.equal(got.live_guardian_release,false);});
});
test("revoked, stale and same-serial fork refuse; retained checkpoint remains untouched",async()=>{
 const f=await sample();f.config.previous=evaluate({policy:f.config.policy,trusted:f.config.trusted,...f.evidence,now:f.now}).checkpoint;
 const before=copy(f.config.previous);f.evidence=f.status.packet(2,true,f.now);assert.equal(r.inspect(f).status,"hold");assert.deepEqual(f.config.previous,before);
 f.evidence=f.status.packet(1,false,f.now+1);assert.equal(r.inspect({...f,now:f.now+1}).status,"hold");
 f.config.previous=evaluate({policy:f.config.policy,trusted:f.config.trusted,...f.status.packet(2,false),now:f.now}).checkpoint;
 f.evidence=f.status.packet(1,false);assert.equal(r.inspect(f).status,"hold");
});
test("participant signing keys cannot be reused as guardian or enrollment authorities",async()=>{
 const f=await sample();const guardian=copy(f),issuer=copy(f);
 guardian.config.policy.guardians[0].approvalKey=guardian.config.participants[0].public_key.sign;
 issuer.config.trusted[0].issuer_key=issuer.config.participants[0].public_key.sign;
 assert.equal(r.inspect(guardian).status,"hold");assert.equal(r.inspect(issuer).status,"hold");
});
function mcp(home,name,args={},extra={}){
 const request={jsonrpc:"2.0",id:1,method:"tools/call",params:{name,arguments:args}};
 const run=spawnSync(process.execPath,[path.resolve(__dirname,"../mcp-server.js")],{input:JSON.stringify(request)+"\n",encoding:"utf8",timeout:10000,env:{PATH:process.env.PATH,HOME:home,...extra}});
 assert.equal(run.status,0,run.stderr);const reply=JSON.parse(run.stdout.trim());return {reply,raw:run.stdout,value:reply.result&&!reply.result.isError?JSON.parse(reply.result.content[0].text):null};
}
test("actual MCP readiness is no-argument, read-only, offline and sanitizes malformed private contents",async t=>{
 const root=directory(t),before=fs.readdirSync(root);const empty=mcp(root,"conduit_sealed_readiness");assert.equal(empty.value.status,"hold");assert.deepEqual(fs.readdirSync(root),before);
 const attack=mcp(root,"conduit_sealed_readiness",{config:"/etc/passwd",now:1,enable_live:true});assert(attack.reply.error||attack.reply.result.isError);
 const f=await sample(),config=path.join(root,"config.json"),evidence=path.join(root,"evidence.json");
 fs.writeFileSync(config,JSON.stringify(f.config),{mode:0o600});fs.writeFileSync(evidence,JSON.stringify(f.evidence),{mode:0o600});
 const env={DEMIPASS_SEALED_READINESS_CONFIG:config,DEMIPASS_SEALED_READINESS_EVIDENCE:evidence};
 const cfgBytes=fs.readFileSync(config),evidenceBytes=fs.readFileSync(evidence);
 assert.equal(mcp(root,"conduit_sealed_readiness",{},env).value.status,"fixture_evidence_current_live_disabled");
 assert.deepEqual(fs.readFileSync(config),cfgBytes);assert.deepEqual(fs.readFileSync(evidence),evidenceBytes);
 fs.writeFileSync(config,'{"private_key":"DO_NOT_ECHO_SECRET", broken');
 const bad=mcp(root,"conduit_sealed_readiness",{},env);assert.equal(bad.value.status,"hold");assert(!bad.raw.includes("DO_NOT_ECHO_SECRET"));
});
test("unsafe private input, FIFO, symlink and missing configured files hold within a bounded CLI",async t=>{
 const root=directory(t),config=path.join(root,"config.json"),f=await sample();
 const run=()=>spawnSync(process.execPath,[path.resolve(__dirname,"../sealed/readiness-cli.js")],{encoding:"utf8",timeout:3000,env:{PATH:process.env.PATH,HOME:root,DEMIPASS_SEALED_READINESS_CONFIG:config}});
 for(const kind of ["missing","shared","symlink","fifo"]){
  if(kind==="shared"){fs.writeFileSync(config,JSON.stringify(f.config));fs.chmodSync(config,0o644);}
  if(kind==="symlink"){fs.writeFileSync(config+"-target",JSON.stringify(f.config),{mode:0o600});fs.symlinkSync(config+"-target",config);}
  if(kind==="fifo")assert.equal(spawnSync("mkfifo",["-m","600",config]).status,0);
  const x=run();assert.equal(x.status,2,kind+":"+x.stderr);assert.equal(JSON.parse(x.stdout).status,"hold");if(fs.existsSync(config))fs.unlinkSync(config);
 }
});
test("source inventory changes when an implementation or launcher changes; symlink refuses",t=>{
 const root=directory(t);fs.mkdirSync(path.join(root,"sealed"));
 for(const name of ["index.js","mcp-server.js","http-json.js","services.js","package.json","sealed/runner.sh"])fs.writeFileSync(path.join(root,name),"original");
 const first=r.sourceDigest(root);
 fs.writeFileSync(path.join(root,"package-lock.json"),"not shipped by npm");assert.equal(r.sourceDigest(root),first);fs.unlinkSync(path.join(root,"package-lock.json"));assert.equal(r.sourceDigest(root),first);
 fs.writeFileSync(path.join(root,"sealed/runner.sh"),"changed");assert.notEqual(r.sourceDigest(root),first);
 fs.unlinkSync(path.join(root,"sealed/runner.sh"));fs.symlinkSync(path.join(root,"index.js"),path.join(root,"sealed/runner.sh"));assert.throws(()=>r.sourceDigest(root));
});
test("Brain, Claude and Codex actual MCP endpoints exchange all six direct encrypted fixture paths and acknowledgments",async t=>{
 const root=directory(t),peers={};
 for(const role of r.ROLES){const home=path.join(root,role);fs.mkdirSync(home,{mode:0o700});const config=path.join(home,"conduit.json");fs.writeFileSync(config,JSON.stringify({name:role}),{mode:0o600});
  const env={CONDUIT_CONFIG:config,DEMIPASS_SEALED_ENABLE:"1",DEMIPASS_SEALED_DIRECTORY:path.join(home,"sealed")};
  peers[role]={home,env,key:mcp(home,"conduit_sealed_identity",{},env).value.public_key};
 }
 for(const from of r.ROLES)for(const to of r.ROLES){if(from===to)continue;const a=peers[from],b=peers[to],plaintext=from+" private fixture for "+to;
  const prepared=mcp(a.home,"conduit_sealed_prepare",{recipient:b.key,plaintext,padding:"1k",defer_capsule:true},a.env).value;
  const saved=JSON.parse(fs.readFileSync(path.join(a.env.DEMIPASS_SEALED_DIRECTORY,"outbox",prepared.id+".json")));
  assert(!JSON.stringify(saved).includes(plaintext));
  const capsule=mcp(a.home,"conduit_sealed_capsule",{id:prepared.id},a.env).value.capsule;
  assert(mcp(b.home,"conduit_sealed_open",{envelope:saved.envelope,sender:a.key},b.env).reply.result.isError);
  const opened=mcp(b.home,"conduit_sealed_open",{envelope:saved.envelope,capsule,sender:a.key,padding:"1k",acknowledge:true},b.env).value;
  assert.equal(opened.plaintext,plaintext);assert.equal(opened.ack.body.event,"decrypted");
  assert(require("../sealed/endpoint-lifecycle").verifyAcknowledgment({envelope:saved.envelope,capsule,sender:a.key,recipient:b.key,padding:"1k",ack:opened.ack}));
  const other=peers[r.ROLES.find(x=>x!==from&&x!==to)];
  assert(mcp(other.home,"conduit_sealed_open",{envelope:saved.envelope,capsule,sender:a.key,padding:"1k"},other.env).reply.result.isError);
 }
});
