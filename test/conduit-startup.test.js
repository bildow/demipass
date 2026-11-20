'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), path = require('path'), os = require('os');
const {execFileSync} = require('child_process');
const startup = require('../conduit-startup'), profiles = require('../conduit-receiver-profile');
const {ReceiverManager, acquire} = require('../conduit-receiver-manager');
function home(t) { const h = fs.mkdtempSync(path.join(os.tmpdir(),'conduit-startup-')); t.after(()=>fs.rmSync(h,{recursive:true,force:true})); fs.mkdirSync(path.join(h,'.config/demipass'),{recursive:true,mode:0o700}); return h; }
test('startup requires private explicit owner opt-in; disabled/corrupt/symlink policy cannot grant it', t => {
  const h=home(t), f=path.join(h,'.config/demipass/conduit-startup.json');
  assert.equal(startup.policy(h).claude_channels,false);
  profiles.writePrivate(f,{version:1,claude_channels:true}); assert.equal(startup.policy(h).claude_channels,true);
  fs.chmodSync(f,0o644);assert.throws(()=>startup.policy(h)); fs.chmodSync(f,0o600);
  profiles.writePrivate(f,{version:1,claude_channels:true,approve_permissions:true});assert.throws(()=>startup.policy(h));
  fs.unlinkSync(f);fs.symlinkSync('/dev/null',f);assert.throws(()=>startup.policy(h));
});
test('real launcher preserves resume/name/model/permissions and does not auto-answer host prompts', t => {
  const h=home(t), f=path.join(h,'.config/demipass/conduit-startup.json'), fake=path.join(h,'fake-claude');
  fs.writeFileSync(fake,'#!/usr/bin/env node\nconsole.log(JSON.stringify(process.argv.slice(2)));',{mode:0o700});
  const args=['--resume','11111111-1111-4111-8111-111111111111','--name','same pane','--model','existing-model'];
  const run=a=>JSON.parse(execFileSync(process.execPath,[path.resolve('bin/conduit-claude-start.js'),fake,...a],{env:{HOME:h,PATH:process.env.PATH},encoding:'utf8'}));
  assert.deepEqual(run(args),args);
  profiles.writePrivate(f,{version:1,claude_channels:true});
  assert.deepEqual(run(args),['--dangerously-load-development-channels','server:demipass',...args]);
  assert.deepEqual(run(['--help']),['--help']);assert.deepEqual(run(['mcp','list']),['mcp','list']);
  assert.deepEqual(run(['-p','a prompt']),['-p','a prompt']);
  assert.deepEqual(run(run(args)),run(args));
});
test('automatic provisioning only creates a missing Claude profile; explicit disable and other runtimes survive',t=>{
  const h=home(t), config={file:path.join(h,'pane.json'),file_present:true,pane_address:'opus-test',name:'opus-test',wallet:'w',url:'https://conduit.dustroot.com'};
  assert.equal(startup.provisionClaude(config,h),false);
  profiles.writePrivate(path.join(h,'.config/demipass/conduit-startup.json'),{version:1,claude_channels:true});
  assert.equal(startup.provisionClaude(config,h),true);assert.equal(profiles.load(config).runtime,'claude');
  profiles.provision(config,{runtime:'claude',enabled:false,driver:'mcp'});
  assert.equal(startup.provisionClaude(config,h),false);assert.equal(profiles.load(config).enabled,false);
});
test('lifecycle manager drains old in-flight poll before rearming and never retries uncertainty',()=>{
  let snap={generation:'one'}, made=[];
  const manager=new ReceiverManager({snapshot:()=>snap,create:()=>{const state={stopped:false,poll_in_flight:true,last_error:null};const l={start(){},stop(){state.stopped=true;},status:()=>state};made.push(l);return l;}});
  manager.tick();snap={generation:'two'};manager.tick();assert.equal(made.length,1);assert.equal(made[0].status().stopped,true);
  made[0].status().poll_in_flight=false;manager.tick();assert.equal(made.length,2);
  Object.assign(made[1].status(),{stopped:true,poll_in_flight:false,last_error:'inbox_delivery_uncertain'});snap={generation:'three'};manager.tick();assert.equal(made.length,2);
});
test('missing lifecycle evidence stops reception; repaired evidence can rearm after drain',()=>{
  let broken=false,made=0;const state={stopped:false,poll_in_flight:false,last_error:null};
  const manager=new ReceiverManager({snapshot:()=>{if(broken)throw Error('held');return{generation:'same'};},create:()=>{made++;state.stopped=false;return{start(){},stop(){state.stopped=true;},status:()=>state};}});
  manager.tick();broken=true;assert.throws(()=>manager.tick());assert.equal(state.stopped,true);
  broken=false;manager.tick();assert.equal(made,2);
});
test('process-held mailbox lease excludes another receiver and releases without deleting its lock file',t=>{
  const h=home(t), c={file:path.join(h,'pane.json'),file_present:true,pane_address:'x',name:'x',wallet:'w'};
  const release=acquire(c);try{assert.throws(()=>acquire(c),/already_owned/);}finally{release();}
  acquire(c)();assert(fs.existsSync(profiles.fileFor(c)+'.owner.lock'));
});
