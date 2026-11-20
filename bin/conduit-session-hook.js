#!/usr/bin/env node
'use strict';
// Installed as SessionStart + UserPromptSubmit + Conduit PreToolUse. No credentials
// or transcript text leave the machine. Only the runtime's verified current ID/name
// is recorded. Old MCP children are refused, not killed or silently rebound.
const fs=require('fs'),path=require('path'),os=require('os');
const context=require('../conduit-session-context');
async function main(input) {
 const runtime=context.nearestClaude();
 const {value,changed}=context.record(input,runtime);
 process.env.CONDUIT_RUNTIME_PID=String(runtime.pid);process.env.CONDUIT_RUNTIME_START=runtime.start_ticks;
 for(const k of ['CONDUIT_MODEL_FAMILY','CONDUIT_SESSION_ID','CONDUIT_SESSION_NAME','CONDUIT_SESSION_NAME_SOURCE','CONDUIT_AUTOBIND'])delete process.env[k];
 process.env.CONDUIT_REQUIRE_PANE='1';
 const sdk=require('../index');sdk.configure({baseUrl:'https://api.dustforge.com',bearerToken:require('../onboard').sessionToken()});
 let reconciled;
 try{reconciled=await sdk.conduitReconcileSession();}catch{reconciled={ok:false,reason:'session_route_held'};}
 let modern=false;
 const dir=path.join(os.homedir(),'.config/demipass/runtime');
 try{for(const name of fs.readdirSync(dir)){
  if(!/^pid-\d+\.json$/.test(name))continue;
  let r;try{r=JSON.parse(fs.readFileSync(path.join(dir,name),'utf8'));}catch{continue;}
  if(r.role!=='demipass'||r.runtime_pid!==runtime.pid||r.runtime_start!==runtime.start_ticks||r.source!=='claude-lifecycle')continue;
  try{const p=context.processInfo(r.pid);if(p.start_ticks===r.child_start_ticks)modern=true;}catch{}
 }}catch{}
 if(input.hook_event_name==='PreToolUse'&&/conduit_/.test(input.tool_name||'')&&(!modern||!reconciled.ok))return{hookSpecificOutput:{hookEventName:'PreToolUse',permissionDecision:'deny',permissionDecisionReason:'Conduit current-session binding is not ready. Reconnect DemiPass with /mcp to load the lifecycle-aware launcher; do not use an old pane address. No message sent by this check.'}};
 if(changed||!modern||!reconciled.ok)return{hookSpecificOutput:{hookEventName:input.hook_event_name,additionalContext:`Conduit identity: ${value.model_family}-${value.session_id}; current session name: ${value.session_name||'(unnamed)'}. Route ${reconciled.ok?'reconciled':'held'}. ${modern?'Lifecycle-aware MCP present.':'Reconnect DemiPass via /mcp once; the previous MCP must not send/read under an old identity.'} This does not prove automatic reception.`}};
 return null;
}
if(require.main===module){let raw='';process.stdin.on('data',b=>{raw+=b;if(raw.length>1048576)process.exit(2);});process.stdin.on('end',async()=>{
 let input;try{input=JSON.parse(raw);const out=await main(input);if(out)console.log(JSON.stringify(out));}catch{console.error('Conduit lifecycle identity could not be verified; old address must not be used.');process.exitCode=input?.hook_event_name==='PreToolUse'?2:0;}
});}
module.exports={main};
