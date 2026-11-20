'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),os=require('os'),path=require('path');
const {execFileSync}=require('child_process');
const root=path.resolve(__dirname,'..'),SID='11111111-1111-4111-8111-111111111111',NEXT='22222222-2222-4222-8222-222222222222';
function run(t,body){
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'conduit-session-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const fake=path.join(home,'claude');fs.symlinkSync(process.execPath,fake);
 const script=path.join(home,'run.js');fs.writeFileSync(script,`const fs=require('fs'),path=require('path'),assert=require('node:assert/strict'),http=require('http');
 const ctx=require(${JSON.stringify(root+'/conduit-session-context')}),sdk=require(${JSON.stringify(root+'/index')}),profiles=require(${JSON.stringify(root+'/conduit-receiver-profile')});
 const runtime=ctx.processInfo(process.pid); const originalRecord=ctx.record;let eventTick=Number(runtime.start_ticks);ctx.record=(input,runtime,home=process.env.HOME)=>originalRecord(input,runtime,home,++eventTick);process.env.CONDUIT_RUNTIME_PID=String(runtime.pid);process.env.CONDUIT_RUNTIME_START=runtime.start_ticks;
 const SID=${JSON.stringify(SID)},NEXT=${JSON.stringify(NEXT)};
 const input=(sid,title='dustforge-demipass')=>({hook_event_name:'SessionStart',source:'resume',session_id:sid,session_title:title,model:'claude-fable-5-1'});
 (async()=>{${body}})().then(()=>console.log('PASS'),e=>{console.error(e);process.exitCode=1});`);
 const out=execFileSync(fake,[script],{env:{HOME:home,PATH:process.env.PATH,CONDUIT_REQUIRE_PANE:'1'},encoding:'utf8',timeout:15000});assert.match(out,/PASS/);
}
test('same Claude process follows resume, ignores stale static binding and rejects caller rebinding',t=>run(t,`
 process.env.CONDUIT_MODEL_FAMILY='opus';process.env.CONDUIT_SESSION_ID=NEXT;process.env.CONDUIT_SESSION_NAME='brain | flimflam';process.env.CONDUIT_SESSION_NAME_SOURCE='binding';
 ctx.record(input(SID),runtime);assert.equal(sdk.conduitConfig().pane_address,'fable-'+SID);
 await assert.rejects(sdk.conduitOnboard({model_family:'opus',session_id:NEXT}),/bound to another pane/);
 ctx.record(input(NEXT,'kodiak'),runtime);assert.equal(sdk.conduitConfig().pane_address,'fable-'+NEXT);
 await assert.rejects(sdk.conduitOnboard({session_name:'brain | flimflam'}),/current Claude session title/);
`));
test('rename changes generation; same identity events are idempotent and model change does not rename family',t=>run(t,`
 const first=ctx.record(input(SID),runtime);const same=ctx.record({...input(SID),model:'claude-opus-5-5'},runtime);
 assert.equal(same.changed,false);assert.equal(same.value.model_family,'fable');
 const renamed=ctx.record(input(SID,'new name'),runtime);assert.notEqual(first.value.generation,renamed.value.generation);
 assert.equal(ctx.load(runtime).session_name,'new name');
`));
test('new session without model evidence holds instead of retaining previous address',t=>run(t,`
 ctx.record(input(SID),runtime);assert.throws(()=>ctx.record({...input(NEXT),model:undefined},runtime),/model_unknown/);
 assert.throws(()=>sdk.conduitConfig(),/identity is held/);
`));
test('missing, corrupt, world-readable and wrong process-start evidence all hold',t=>run(t,`
 assert.throws(()=>sdk.conduitConfig(),/identity is held/);
 ctx.record(input(SID),runtime);const f=ctx.fileFor(runtime);fs.chmodSync(f,0o644);assert.throws(()=>sdk.conduitConfig());fs.chmodSync(f,0o600);
 const r=JSON.parse(fs.readFileSync(f));r.start_ticks='0';profiles.writePrivate(f,r);assert.throws(()=>sdk.conduitConfig());
 fs.writeFileSync(f,'not JSON');assert.throws(()=>sdk.conduitConfig());
`));
test('in-flight inbox response after resume is refused and new requests use only new address',t=>run(t,`
 let entered,release;const reached=new Promise(r=>entered=r),wait=new Promise(r=>release=r);let requests=[];
 const server=http.createServer(async(req,res)=>{requests.push(req.headers['x-conduit-address']);if(requests.length===1){entered();await wait;}res.end(JSON.stringify({agent:req.headers['x-conduit-address'],messages:[],next_since:0}));});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const configure=sid=>{ctx.record(input(sid),runtime);const c=sdk.conduitConfig();fs.mkdirSync(path.dirname(c.file),{recursive:true,mode:0o700});profiles.writePrivate(c.file,{name:'fable-'+sid,wallet:'w',token:'fixture',expires_at:'2099-01-01T00:00:00Z',url:'http://127.0.0.1:'+server.address().port,stable_address:'dustforge-demipass',session_name:'dustforge-demipass'});};
 try{configure(SID);const old=sdk.conduitInbox({});await reached;configure(NEXT);release();await assert.rejects(old,/session changed/);const current=await sdk.conduitInbox({});assert.equal(current.agent,'fable-'+NEXT);assert.deepEqual(requests,['fable-'+SID,'fable-'+NEXT]);}finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
`));
test('rename mismatch blocks use before relay access until route reconciled',t=>run(t,`
 ctx.record(input(SID),runtime);const c=sdk.conduitConfig();fs.mkdirSync(path.dirname(c.file),{recursive:true,mode:0o700});profiles.writePrivate(c.file,{name:'fable-'+SID,wallet:'w',token:'x',stable_address:'old-name',url:'http://127.0.0.1:1'});
 await assert.rejects(sdk.conduitInbox({}),/route reconciliation required/);
`));
test('existing canonical UUID address survives model-family change on process restart',t=>run(t,`
 const dir=path.join(process.env.HOME,'.config/demipass/conduit-panes');fs.mkdirSync(dir,{recursive:true,mode:0o700});profiles.writePrivate(path.join(dir,'opus-'+SID+'.json'),{name:'opus-'+SID});
 const r=ctx.record(input(SID),runtime);assert.equal(r.value.model_family,'opus');assert.equal(sdk.conduitConfig().pane_address,'opus-'+SID);
`));
test('conflicting canonical addresses for one UUID hold rather than guessing',t=>run(t,`
 const dir=path.join(process.env.HOME,'.config/demipass/conduit-panes');fs.mkdirSync(dir,{recursive:true,mode:0o700});for(const family of ['opus','fable'])profiles.writePrivate(path.join(dir,family+'-'+SID+'.json'),{name:family+'-'+SID});
 assert.throws(()=>ctx.record(input(SID),runtime),/multiple_identities/);assert.throws(()=>sdk.conduitConfig(),/identity is held/);
`));
test('occupied current title refuses automatic takeover before any mutation',t=>run(t,`
 let writes=0;const server=http.createServer((req,res)=>{if(req.method!=='GET')writes++;res.end(JSON.stringify({agents:[{name:'fable-'+NEXT,route:{alias:'dustforge-demipass',current:'fable-'+NEXT,generation:1}}]}));});await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{ctx.record(input(SID),runtime);const c=sdk.conduitConfig();fs.mkdirSync(path.dirname(c.file),{recursive:true,mode:0o700});profiles.writePrivate(c.file,{name:'fable-'+SID,wallet:'w',token:'fixture',expires_at:'2099-01-01T00:00:00Z',url:'http://127.0.0.1:'+server.address().port});await assert.rejects(sdk.conduitReconcileSession(),/another session/);assert.equal(writes,0);}finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
`));
test('rename on old relay holds without deleting the old route',t=>run(t,`
 let writes=0;const server=http.createServer((req,res)=>{if(req.method!=='GET')writes++;res.end(JSON.stringify(req.url.startsWith('/readme')?{}:{agents:[{name:'fable-'+SID,route:{alias:'old-name',current:'fable-'+SID,generation:1}}]}));});await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{ctx.record(input(SID),runtime);const c=sdk.conduitConfig();fs.mkdirSync(path.dirname(c.file),{recursive:true,mode:0o700});profiles.writePrivate(c.file,{name:'fable-'+SID,wallet:'w',token:'fixture',expires_at:'2099-01-01T00:00:00Z',url:'http://127.0.0.1:'+server.address().port,stable_address:'old-name'});await assert.rejects(sdk.conduitReconcileSession(),/conditional rename gate/);assert.equal(writes,0);assert.equal(sdk.conduitConfig().stable_address,'old-name');}finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
`));

test('delayed older hook cannot restore a previous session',t=>run(t,`
 ctx.record(input(SID),runtime);ctx.record(input(NEXT,'new role'),runtime);
 assert.throws(()=>originalRecord(input(SID),runtime,process.env.HOME,Number(runtime.start_ticks)+1),/stale_lifecycle/);
 assert.equal(sdk.conduitConfig().pane_address,'fable-'+NEXT);
`));

test('invalid current rename holds the old route for background readers too',t=>run(t,`
 ctx.record(input(SID),runtime);
 assert.throws(()=>ctx.record(input(SID,'!!!'),runtime));
 assert.throws(()=>sdk.conduitConfig(),/identity is held/);
 ctx.record(input(SID,'corrected name'),runtime);
 assert.equal(ctx.load(runtime).session_name,'corrected name');
`));

test('malformed current lifecycle event cannot leave the old mailbox usable',t=>run(t,`
 ctx.record(input(SID),runtime);
 assert.throws(()=>ctx.record({...input(SID),session_id:'invalid'},runtime),/lifecycle_input_invalid/);
 assert.throws(()=>sdk.conduitConfig(),/identity is held/);
 ctx.record(input(SID),runtime);
 assert.equal(sdk.conduitConfig().pane_address,'fable-'+SID);
`));

test('a prior boot cannot supply identity or defeat current-boot lifecycle ordering',t=>run(t,`
 ctx.record(input(SID),runtime);const file=ctx.fileFor(runtime),old=profiles.readPrivate(file);
 old.boot_id='00000000-0000-4000-8000-000000000000';old.event_tick=Number.MAX_SAFE_INTEGER;profiles.writePrivate(file,old);
 assert.throws(()=>ctx.load(runtime),/wrong_boot/);
 ctx.record(input(NEXT,'new boot'),runtime);assert.equal(ctx.load(runtime).session_id,NEXT);
`));
