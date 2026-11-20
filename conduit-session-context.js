'use strict';
// Runtime identity is supplied by a local lifecycle hook, never tool arguments or
// pane titles. PID + kernel start time prevents reuse of an old process binding.
const fs = require('fs'), path = require('path'), os = require('os');
const { readPrivate, writePrivate, digest } = require('./conduit-receiver-profile');
const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function bootId() { const id=fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim();if(!UUID.test(id))throw Error('conduit_boot_evidence_invalid');return id; }
function processInfo(pid) {
 const raw=fs.readFileSync(`/proc/${pid}/stat`,'utf8'), f=raw.slice(raw.lastIndexOf(') ')+2).trim().split(/\s+/);
 const argv=fs.readFileSync(`/proc/${pid}/cmdline`,'utf8').split('\0');
 const claude=argv.some(a=>/(^|\/)claude(?:\.js)?$/.test(a)||/\/@anthropic-ai\/claude-code\/cli\.js$/.test(a));
 return {pid:Number(pid),parent:Number(f[1]),start_ticks:f[19],claude};
}
function nearestClaude(pid=process.ppid) {
 for(let i=0;pid>1&&i<24;i++){const p=processInfo(pid);if(p.claude)return p;pid=p.parent;}
 throw Error('conduit_runtime_not_found');
}
function fileFor(runtime,home=os.homedir()) {
 if(!Number.isSafeInteger(runtime.pid)||runtime.pid<2||!/^\d+$/.test(String(runtime.start_ticks)))throw Error('conduit_runtime_invalid');
 return path.join(home,'.config/demipass/session-context',`${runtime.pid}-${runtime.start_ticks}.json`);
}
function load(runtime,home=os.homedir()) {
 const live=processInfo(runtime.pid);
 if(!live.claude||live.start_ticks!==runtime.start_ticks)throw Error('conduit_runtime_changed');
 const r=readPrivate(fileFor(runtime,home));
 if(r.boot_id!==bootId())throw Error('conduit_session_context_wrong_boot');
 if(r.version!==1||r.pid!==runtime.pid||r.start_ticks!==runtime.start_ticks||!UUID.test(r.session_id||'')||!/^claude-lifecycle$/.test(r.source||'')||!/^([a-z][a-z0-9]{0,14})$/.test(r.model_family||'')||r.state!=='ready')throw Error('conduit_session_context_held');
 if(r.session_name!==null&&(typeof r.session_name!=='string'||!r.session_name.trim()||r.session_name.length>160))throw Error('conduit_session_context_held');
 const identity={model_family:r.model_family,session_id:r.session_id,session_name:r.session_name};
 if(r.generation!==digest(identity))throw Error('conduit_session_context_held');
 return r;
}
function fromEnvironment() {
 const pid=process.env.CONDUIT_RUNTIME_PID,start_ticks=process.env.CONDUIT_RUNTIME_START;
 if(!pid&&!start_ticks)return null;
 try{return load({pid:Number(pid),start_ticks});}catch{throw Error('Conduit session identity is held: lifecycle evidence missing, invalid or changed; reconnect the reviewed MCP launcher');}
}
function transcriptTitle(file,sid) {
 // Only Claude's own session transcript, never arbitrary paths from tool input.
 const root=path.join(os.homedir(),'.claude/projects')+path.sep;
 if(typeof file!=='string'||!file.startsWith(root)||path.basename(file)!==sid+'.jsonl')return null;
 const real=fs.realpathSync(file);if(real!==file)throw Error('conduit_transcript_symlink');
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{
  const st=fs.fstatSync(fd);if(!st.isFile()||st.uid!==process.getuid())throw Error('conduit_transcript_invalid');
  const size=Math.min(st.size,4*1024*1024),b=Buffer.alloc(size);fs.readSync(fd,b,0,size,st.size-size);
  const lines=b.toString('utf8').split('\n');if(st.size>size)lines.shift();
  for(let i=lines.length-1;i>=0;i--){let r;try{r=JSON.parse(lines[i]);}catch{continue;}
   if(r.type==='custom-title'&&r.sessionId===sid&&typeof r.customTitle==='string')return r.customTitle;
  }
  return null;
 }finally{fs.closeSync(fd);}
}
function record(input,runtime=nearestClaude(),home=os.homedir(),eventTick=Number(processInfo(process.pid).start_ticks)) {
 const file=fileFor(runtime,home),dir=path.dirname(file);fs.mkdirSync(dir,{recursive:true,mode:0o700});
 const fd=fs.openSync(file+'.lock',fs.constants.O_CREAT|fs.constants.O_RDWR|fs.constants.O_NOFOLLOW,0o600);
 try {
  const st=fs.fstatSync(fd);if(!st.isFile()||st.uid!==process.getuid()||(st.mode&0o077))throw Error('conduit_context_lock_invalid');
  // flock owns this shared open-file description; closing fd releases it, even
  // after process death. Slow old hooks may not overwrite a newer lifecycle event.
  const r=require('child_process').spawnSync('flock',['-x','-w','3','3'],{stdio:['ignore','ignore','pipe',fd],timeout:4000});
  if(r.status!==0)throw Error('conduit_context_lock_held');
  return recordLocked(input,runtime,home,eventTick);
 } finally {fs.closeSync(fd);}
}
function recordLocked(input,runtime,home,eventTick) {
 const file=fileFor(runtime,home),dir=path.dirname(file);fs.mkdirSync(dir,{recursive:true,mode:0o700});
 const st=fs.lstatSync(dir);if(!st.isDirectory()||st.uid!==process.getuid()||(st.mode&0o077))throw Error('conduit_context_directory_invalid');
 let prior;try{prior=readPrivate(file);}catch(e){if(e.code!=='ENOENT')throw e;}
 const boot=bootId();if(prior?.boot_id!==boot)prior=null;
 if(!Number.isSafeInteger(eventTick)||eventTick<1)throw Error('conduit_event_clock_invalid');
 if(prior?.event_tick>eventTick)throw Error('conduit_stale_lifecycle_event');
 // Invalidate on every current event, including same-session renames. A bad title,
 // malformed event or hook crash must not leave background readers on the old role.
 // Stale events were refused above and therefore cannot hold a newer session.
 writePrivate(file,{version:1,boot_id:boot,pid:runtime.pid,start_ticks:runtime.start_ticks,state:'held',event_tick:eventTick,source:'claude-lifecycle'});
 if(!input||!['SessionStart','UserPromptSubmit','PreToolUse'].includes(input.hook_event_name)||!UUID.test(input.session_id||''))throw Error('conduit_lifecycle_input_invalid');
 const same=prior?.session_id===input.session_id&&prior?.state==='ready';
 let family=same?prior.model_family:null;
 if(!family){
  const paneDir=path.join(home,'.config/demipass/conduit-panes');let files=[];
  try{files=fs.readdirSync(paneDir).filter(n=>n.endsWith('-'+input.session_id+'.json'));}catch(e){if(e.code!=='ENOENT')throw e;}
  const families=new Set();
  for(const name of files){const cfg=readPrivate(path.join(paneDir,name));const m=/^([a-z][a-z0-9]{0,14})-/.exec(name);if(m&&cfg.name===name.slice(0,-5))families.add(m[1]);}
  if(families.size>1)throw Error('conduit_session_has_multiple_identities');
  family=[...families][0]||null;
 }

 if(!family){const m=/^claude-([a-z][a-z0-9]{0,14})(?:-|$)/.exec(input.model||'');family=m?.[1]||require('./index')._conduitClaudeFamily(input.session_id,{home}).family;}
 if(!family)throw Error('conduit_current_model_unknown');
 let title=typeof input.session_title==='string'?input.session_title:transcriptTitle(input.transcript_path,input.session_id);
 if(title===null&&same)title=prior.session_name;
 if(title!==null){title=title.trim();require('./index').conduitSessionAlias(title);}
 const identity={model_family:family,session_id:input.session_id,session_name:title};
 const value={version:1,boot_id:boot,pid:runtime.pid,start_ticks:runtime.start_ticks,source:'claude-lifecycle',state:'ready',event_tick:eventTick,...identity,generation:digest(identity),at:new Date().toISOString()};
 if(prior?.event_tick===eventTick&&prior?.generation&&prior.generation!==value.generation)throw Error('conduit_ambiguous_lifecycle_order');
 writePrivate(file,value);return{value,prior,changed:prior?.generation!==value.generation};
}
module.exports={processInfo,nearestClaude,fileFor,load,fromEnvironment,record};
