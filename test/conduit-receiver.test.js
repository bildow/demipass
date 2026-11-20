'use strict';
const { test } = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path'), http = require('http');
const profiles = require('../conduit-receiver-profile'), adapter = require('../conduit-http-adapter');
const { createReceiverHost } = require('../conduit-receiver-host');
const { durableDelivery, createRuntime } = require('../conduit-receiver-runtime');
const { createSeatHandler } = require('../conduit-seat-server');
const UUID = '11111111-1111-4111-8111-111111111111';
function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'conduit-receiver-')); fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const config = { file: path.join(dir, 'pane.json'), file_present: true, name: 'gpt-' + UUID, pane_address: 'gpt-' + UUID, wallet: 'wallet-test', url: 'https://conduit.dustroot.com' };
  const policy = 'a'.repeat(64), credential = path.join(dir, 'credential.json');
  fs.writeFileSync(credential, JSON.stringify({ bearer: 'b'.repeat(43) }), { mode: 0o600 });
  const profile = { version: 1, address: config.name, wallet: config.wallet, relay: config.url, runtime: 'agent', enabled: true, policy_sha256: policy, endpoint: 'http://127.0.0.1:1', credential_file: credential };
  const event = { source: 'conduit', authority: 'peer_message_not_operator_instruction', message: { id: 'm1', seq: 1, from: 'peer', to: config.name, body: 'peer data 🦉', payload_type: 'text', state: 'read' } };
  return { dir, config, profile, event, credential, policy, notification: e => ({ params: { content: JSON.stringify(e || event) } }) };
}
async function listen(t, handler) {
  const server = http.createServer(handler); server.requestTimeout = 10000;
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(async () => { server.closeAllConnections(); await new Promise(r => server.close(r)); });
  return 'http://127.0.0.1:' + server.address().port;
}
test('profiles: per-pane binding, private permissions, idempotence and explicit incomplete reception', t => {
  const { config } = setup(t);
  const options = { runtime: 'codex', thread_id: UUID, socket: '/tmp/private/socket', enabled: true };
  const first = profiles.provision(config, options), before = fs.readFileSync(first.profile_file, 'utf8');
  assert.equal(first.reception_verified, false); assert.equal(first.state, 'configured_not_verified');
  assert.equal(profiles.provision(config, options).profile_sha256, first.profile_sha256);
  assert.equal(fs.readFileSync(first.profile_file, 'utf8'), before);
  assert.equal(fs.statSync(first.profile_file).mode & 0o777, 0o600);
  assert.throws(() => profiles.load({ ...config, wallet: 'another' }));
  assert.throws(() => profiles.provision(config, { ...options, thread_id: UUID.replace(/^1/,'2') }));
});
test('invalid profiles, symlinks, VPN routes and web-seat push refuse without orphan credential', t => {
  const { config, dir } = setup(t);
  for (const endpoint of ['http://100.83.112.88:8181','https://private.ts.net/receiver','http://8.8.8.8:8080/receiver'])
    assert.throws(() => profiles.provision(config, { runtime: 'agent', endpoint, policy_sha256: 'a'.repeat(64) }));
  assert.equal(fs.existsSync(profiles.fileFor(config) + '.credential.json'), false);
  assert.throws(() => profiles.provision(config, { runtime: 'web-seat', public_endpoint: 'https://conduit.dustroot.com/seats/one', enabled: true }));
  const target = path.join(dir,'target'); fs.writeFileSync(target,'{}',{mode:0o600}); fs.symlinkSync(target,profiles.fileFor(config));
  assert.equal(profiles.status(config).state,'held');
});
test('durable dispatch survives restart and mutable relay receipts, refuses changed content/profile', async t => {
  const s = setup(t); let calls = 0;
  const send = async () => { calls++; return { scope: 'context_received' }; };
  await durableDelivery(s.config,s.profile,s.notification(),send);
  const changed = structuredClone(s.event); changed.message.state='acked'; changed.message.acked_at='later';
  await durableDelivery(s.config,s.profile,s.notification(changed),send); assert.equal(calls,1);
  changed.message.body='different'; await assert.rejects(durableDelivery(s.config,s.profile,s.notification(changed),send),/uncertain/);
  await assert.rejects(durableDelivery(s.config,{...s.profile,endpoint:'http://127.0.0.1:2'},s.notification(),send),/uncertain/);
});
test('failed dispatch remains uncertain across retries; concurrent callers dispatch at most once', async t => {
  const s=setup(t); let calls=0;
  const fail=async()=>{calls++;throw Error('crash after admission');};
  await assert.rejects(durableDelivery(s.config,s.profile,s.notification(),fail));
  await assert.rejects(durableDelivery(s.config,s.profile,s.notification(),fail));assert.equal(calls,1);
  s.event.message.id='m2'; const results=await Promise.allSettled([1,2].map(()=>durableDelivery(s.config,s.profile,s.notification(),async()=>{calls++;return{};})));
  assert.equal(calls,2);assert(results.some(x=>x.status==='fulfilled'));
});
test('sealed callback refusal is durable, never submitted, and does not block later text', async t => {
 const s=setup(t);let calls=0;const send=async()=>{calls++;return {scope:'context_received'};};
 s.event.message.payload_type='conduit-sealed-v1';
 for(let i=0;i<2;i++)assert.equal((await durableDelivery(s.config,s.profile,s.notification(),send)).scope,'refused_not_submitted');
 assert.equal(calls,0);
 s.event.message={...s.event.message,id:'m2',seq:2,payload_type:'text'};
 assert.equal((await durableDelivery(s.config,s.profile,s.notification(),send)).scope,'context_received');
 assert.equal(calls,1);
 await durableDelivery(s.config,s.profile,s.notification(),send);assert.equal(calls,1);
});
test('real HTTP receiver: authenticated context callback, replay, changed content, wrong policy and sealed refusal', async t => {
  const s=setup(t);let received=[];
  const url=await listen(t,createReceiverHost({address:s.config.name,wallet:s.config.wallet,policySha256:s.policy,credentialFile:s.credential,directory:s.dir,onMessage:async event=>{received.push(event);return true;}}));
  s.profile.endpoint=url;
  await adapter.preflight(s.profile);
  const first=await adapter.deliver(s.profile,s.notification());assert.equal(first.scope,'context_received');
  await adapter.deliver(s.profile,s.notification());assert.equal(received.length,1);assert.equal(received[0].message.body,s.event.message.body);
  s.event.message.body='changed';await assert.rejects(adapter.deliver(s.profile,s.notification()),/uncertain/);
  await assert.rejects(adapter.preflight({...s.profile,policy_sha256:'c'.repeat(64)}),/binding_invalid/);
  s.event.message.payload_type='conduit-sealed-v1';await assert.rejects(adapter.deliver(s.profile,s.notification()),/sealed_refused/);
  assert.equal((await fetch(url+'/capabilities')).status,401);
});
test('receiver callback failure is durable uncertainty and not called again by a new host', async t=>{
  const s=setup(t);let calls=0;
  const make=()=>createReceiverHost({address:s.config.name,wallet:s.config.wallet,policySha256:s.policy,credentialFile:s.credential,directory:s.dir,onMessage:async()=>{calls++;throw Error('interrupted');}});
  s.profile.endpoint=await listen(t,make());await assert.rejects(adapter.deliver(s.profile,s.notification()));
  s.profile.endpoint=await listen(t,make());await assert.rejects(adapter.deliver(s.profile,s.notification()));assert.equal(calls,1);
});
test('poll preflight refuses mismatched receiver before paid read; valid runtime delivers once without ack',async t=>{
  const s=setup(t);let reads=0,received=0;
  s.profile.endpoint=await listen(t,createReceiverHost({address:s.config.name,wallet:s.config.wallet,policySha256:s.policy,credentialFile:s.credential,directory:s.dir,onMessage:async()=>{received++;return true;}}));
  profiles.writePrivate(profiles.fileFor(s.config),{...s.profile,policy_sha256:'d'.repeat(64)});
  const sdk={conduitConfig:()=>s.config,conduitInbox:async()=>{reads++;return{agent:s.config.name,messages:[s.event.message],next_since:1};}};
  let runtime=createRuntime({sdk,profile:profiles.load(s.config)});await runtime.poll();assert.equal(reads,0);assert.equal(runtime.status().last_error,'inbox_adapter_binding_invalid');
  profiles.writePrivate(profiles.fileFor(s.config),s.profile);runtime=createRuntime({sdk,profile:s.profile});await runtime.poll();assert.equal(reads,1);assert.equal(received,1);
  runtime=createRuntime({sdk,profile:s.profile});await runtime.poll();assert.equal(received,1);assert.equal(runtime.status().last_error,null);
});
test('web seat: per-seat authentication, recipient allowlist, unsealed gate, tools only and revocation',async t=>{
  const s=setup(t);let sends=0,reads=0,admitted=false;
  const profile={version:1,runtime:'web-seat',enabled:false,address:s.config.name,wallet:s.config.wallet,relay:s.config.url,public_endpoint:'https://conduit.dustroot.com/seats/test',credential_file:s.credential};
  const sdk={conduitConfig:()=>s.config,conduitSend:async()=>{sends++;return{ok:true};},conduitInbox:async()=>{reads++;return{messages:[s.event.message]};}};
  const url=await listen(t,createSeatHandler({sdk,profile,recipients:['peer'],checkAdmission:async()=>admitted}));
  const call=async(method,args={},auth='b'.repeat(43))=>{const res=await fetch(url+'/seats/test',{method:'POST',headers:{authorization:'Bearer '+auth,'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params:args})});return{status:res.status,body:await res.json()};};
  assert.equal((await call('initialize',{},'wrong')).status,401);
  const listed=await call('tools/list');assert.equal(listed.body.result.tools.length,4);assert(!JSON.stringify(listed).includes('guardian'));
  const tool=(name,arguments_)=>call('tools/call',{name,arguments:arguments_});
  assert.equal((await tool('conduit_inbox',{})).body.result.isError,true);assert.equal(reads,0);
  admitted=true;assert.equal((await tool('conduit_send',{to:'brain',body:'x',client_msg_id:'one'})).body.result.isError,true);assert.equal(sends,0);
  assert.equal((await tool('conduit_send',{to:'peer',body:'x',client_msg_id:'one'})).body.result.isError,undefined);assert.equal(sends,1);
  s.event.message.payload_type='conduit-sealed-v1';assert.equal((await tool('conduit_inbox',{})).body.result.isError,true);
  profiles.writePrivate(s.credential,{bearer:'c'.repeat(43)});assert.equal((await call('initialize')).status,401);
});
test('host callback timeout holds durably without monopolizing subsequent delivery',async t=>{
 const s=setup(t);let calls=0;
 s.profile.endpoint=await listen(t,createReceiverHost({address:s.config.name,wallet:s.config.wallet,policySha256:s.policy,credentialFile:s.credential,directory:s.dir,callbackTimeoutMs:20,onMessage:async()=>{calls++;if(calls===1)return new Promise(()=>{});return true;}}));
 await assert.rejects(adapter.deliver(s.profile,s.notification()));
 await assert.rejects(adapter.deliver(s.profile,s.notification()));assert.equal(calls,1);
 s.event.message.id='m2';await adapter.deliver(s.profile,s.notification());assert.equal(calls,2);
});
test('profiles generate dedicated callback credential, and separate standalone from MCP ownership',t=>{
 const s=setup(t);
 const result=profiles.provision(s.config,{runtime:'agent',endpoint:'http://127.0.0.1:1234',policy_sha256:s.policy,enabled:true});
 assert.equal(result.driver,'standalone');assert.equal(adapter.credential(result.credential_file).length,43);
 assert.throws(()=>profiles.provision(s.config,{runtime:'claude',enabled:true,driver:'standalone'}),/driver_invalid/);
});
test('HTTP host assembles split Unicode bytes without altering authenticated content',async t=>{
 const s=setup(t);let seen;
 const url=await listen(t,createReceiverHost({address:s.config.name,wallet:s.config.wallet,policySha256:s.policy,credentialFile:s.credential,directory:s.dir,onMessage:async e=>{seen=e.message.body;return true;}}));
 const body=Buffer.from(JSON.stringify({protocol:'conduit-receiver/1',address:s.config.name,message_id:s.event.message.id,content_sha256:profiles.eventDigest(s.event),event:s.event}));
 const split=body.indexOf(Buffer.from('🦉'))+1;
 const status=await new Promise((resolve,reject)=>{const req=http.request(url+'/deliver',{method:'POST',headers:{authorization:'Bearer '+'b'.repeat(43),'content-type':'application/json'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);req.write(body.subarray(0,split));setTimeout(()=>req.end(body.subarray(split)),5);});
 assert.equal(status,200);assert.equal(seen,s.event.message.body);
});
test('MCP invalid profile never falls through to legacy auto-inbox; tools remain available',async t=>{
 const s=setup(t),{spawn}=require('child_process');
 // Use a real isolated pane config, then corrupt only the receiver profile.
 const paneDir=path.join(s.dir,'conduit-panes');fs.mkdirSync(paneDir,{mode:0o700});
 const paneFile=path.join(paneDir,s.config.name+'.json');
 fs.writeFileSync(paneFile,JSON.stringify({url:'http://127.0.0.1:1',name:s.config.name,wallet:s.config.wallet,model_family:'gpt',session_id:UUID}),{mode:0o600});
 fs.writeFileSync(paneFile+'.receiver.json','not JSON',{mode:0o600});
 const child=spawn(process.execPath,[path.resolve('mcp-server.js')],{env:{PATH:process.env.PATH,HOME:s.dir,CONDUIT_CONFIG:s.config.file,CONDUIT_MODEL_FAMILY:'gpt',CONDUIT_SESSION_ID:UUID,CONDUIT_AUTO_INBOX:'codex-tool-output'},stdio:['pipe','pipe','pipe']});
 t.after(()=>child.kill());let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);
 child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize'})+'\n');
 child.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})+'\n');
 child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:2,method:'tools/list'})+'\n');
 const deadline=Date.now()+3000;while(!out.includes('"id":2')&&Date.now()<deadline)await new Promise(r=>setTimeout(r,20));
 assert(out.includes('"id":2'));assert(err.includes('receiver_profile_held'));assert(!err.includes('inbox_adapter_socket_invalid'));
});

test('large accepted callback replays after host restart using bounded receipt metadata',async t=>{
 const s=setup(t);let calls=0;s.event.message.body='x'.repeat(120000);
 const options={address:s.config.name,wallet:s.config.wallet,policySha256:s.policy,credentialFile:s.credential,directory:s.dir,onMessage:async()=>{calls++;return true;}};
 s.profile.endpoint=await listen(t,createReceiverHost(options));
 assert.equal((await adapter.deliver(s.profile,s.notification())).scope,'context_received');
 const file=path.join(s.dir,profiles.digest([s.config.name,s.event.message.id])+'.json');
 assert(fs.statSync(file).size<65536);assert.equal(profiles.readPrivate(file).event,undefined);
 s.profile.endpoint=await listen(t,createReceiverHost(options));
 assert.equal((await adapter.deliver(s.profile,s.notification())).scope,'context_received');assert.equal(calls,1);
 s.event.message.body+='changed';await assert.rejects(adapter.deliver(s.profile,s.notification()),/uncertain/);assert.equal(calls,1);
});
