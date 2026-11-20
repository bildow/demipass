#!/usr/bin/env node
'use strict';
// Read-only recovery identity. Never choose --continue or infer a UUID from tmux.
const fs=require('fs'),path=require('path'),os=require('os');
const {processInfo}=require('../conduit-session-context');
function recovery(pid,home=os.homedir()) {
  const live=processInfo(pid);if(!live.claude)throw Error('not_claude');
  const dir=path.join(home,'.claude/sessions'),st=fs.lstatSync(dir);
  if(!st.isDirectory()||st.uid!==process.getuid()||(st.mode&0o077))throw Error('session_directory_untrusted');
  const read=p=>{const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{
    const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid()||s.size>65536)throw Error('session_evidence_invalid');
    return JSON.parse(fs.readFileSync(fd,'utf8'));
  }finally{fs.closeSync(fd);}};
  const record=read(path.join(dir,pid+'.json'));
  if(record.pid!==pid||String(record.procStart)!==live.start_ticks||!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(record.sessionId||''))throw Error('session_identity_unconfirmed');
  if(record.name!==undefined&&(typeof record.name!=='string'||!record.name.trim()||record.name.length>160||/[\x00-\x1f\x7f]/.test(record.name)))throw Error('session_title_invalid');
  for(const file of fs.readdirSync(dir)){
    if(!/^\d+\.json$/.test(file)||file===pid+'.json')continue;
    const otherPid=Number(file.slice(0,-5));let other;
    try{other=processInfo(otherPid);}catch(e){if(e.code==='ENOENT'||e.code==='ESRCH')continue;throw e;}
    if(!other.claude)continue;
    const r=read(path.join(dir,file));
    if(String(r.procStart)===other.start_ticks&&r.sessionId===record.sessionId)throw Error('duplicate_live_conversation');
  }
  return {pid,start_ticks:live.start_ticks,session_id:record.sessionId,name:record.name||null,args:['--resume',record.sessionId,...(record.name?['--name',record.name]:[])]};
}
if(require.main===module){try{console.log(JSON.stringify(recovery(Number(process.argv[2]))));}catch{console.error('Exact Claude recovery identity unavailable or duplicated; no restart authorized by this helper.');process.exitCode=1;}}
module.exports={recovery};
