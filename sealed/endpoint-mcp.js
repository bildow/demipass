"use strict";
const path=require('node:path'),{spawn}=require('node:child_process');
// Paths/credentials/activation are only read by the child from private local files.
function invoke(operation,args={}){
 const fields={prepare:['plaintext','public_text','padding'],grant:['envelope','capsule'],release:['request_id','approvals','padding'],dispute:['request_id','complaint']};
 if(!Object.hasOwn(fields,operation))throw Error('unknown operation');require('./runtime-fields').fields(args,fields[operation],{prepare:['plaintext'],grant:['envelope','capsule'],release:['request_id','approvals'],dispute:['request_id','complaint']}[operation]);
 const dir=process.env.DEMIPASS_SEALED_RUNTIME_DIRECTORY;
 if(typeof dir!=='string'||!path.isAbsolute(dir))throw Error('guarded endpoint not configured; live release remains disabled');
 const raw=JSON.stringify({...args,operation});if(Buffer.byteLength(raw)>98304)throw Error('request too large');
 return new Promise((resolve,reject)=>{
  const c=spawn('/bin/sh',[path.join(__dirname,'endpoint.sh'),dir],{stdio:['pipe','pipe','pipe']});
  const output=[];let size=0,failed=false;
  const fail=()=>{failed=true;c.kill('SIGKILL');};
  const timer=setTimeout(fail,45000);
  c.stdout.on('data',b=>{size+=b.length;if(size>131072)fail();else output.push(b);});
  c.stderr.on('data',()=>{});c.stdin.on('error',()=>{});
  c.on('error',()=>{clearTimeout(timer);reject(Error('guarded endpoint could not start'));});
  c.on('close',code=>{clearTimeout(timer);if(code!==0||failed)return reject(Error('guarded operation held or uncertain; preserve original request id and reconcile payment before retry'));
   try{resolve(JSON.parse(Buffer.concat(output).toString('utf8')));}catch{reject(Error('invalid endpoint response; reconcile original request'));}});
  c.stdin.end(raw);
 });
}
module.exports={invoke};
