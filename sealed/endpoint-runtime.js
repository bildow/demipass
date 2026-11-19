"use strict";
// One bounded child per MCP call, under the endpoint's OS lock. Configuration and
// trust are launcher-owned; requests cannot provide paths, tokens or authorities.
const fs=require('node:fs'),path=require('node:path'),p=require('./crypto');
const {Client,readPrivate,privateDirectory,writeNew}=require('./client');
const {loadAuthorization,assertAuthorization}=require('./runtime-authorization');
const {Journal}=require('./journal'),{ReleaseGate}=require('./release-gate');
const {makeGrant,validateGrant,checkApproval}=require('./guardian');
const {fields}=require('./runtime-fields');
const {request}=require('./http'),{DemiPassMeter}=require('./demipass-meter');
function syncSaved(file){
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{if(!fs.fstatSync(fd).isFile())throw Error('unsafe saved request');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 const d=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(d);}finally{fs.closeSync(d);}
}
async function operation(dir,args){
 fields(args,['operation','plaintext','public_text','padding','envelope','capsule','request_id','approvals','complaint']);
 if(!['prepare','grant','release','dispute'].includes(args.operation))throw Error('unknown operation');
 privateDirectory(dir);
 const cfg=readPrivate(path.join(dir,'config.json'));
 p.fields(cfg,['format','permit_file','policy','admission','sender','recipient','coordinator','payer_token_file','payer_wallet','meter_issuer','client_directory']);
 if(cfg.format!=='conduit-endpoint-runtime-v1')throw Error('endpoint config required');
 const authorization=loadAuthorization(cfg.permit_file,cfg.policy,'endpoint');
 const a=fs.fstatSync(9),b=fs.lstatSync(path.join(dir,'lease.lock'));
 if(!a.isFile()||a.ino!==b.ino||a.dev!==b.dev||b.isSymbolicLink())throw Error('endpoint lock required');
 p.validatePublic(cfg.sender);p.validatePublic(cfg.recipient);
 if(cfg.recipient.mailbox==='brain'||p.keyId(cfg.sender)===p.keyId(cfg.recipient))throw Error('recipient held');
 const keys=new Set([cfg.sender.kem,cfg.sender.sign.x,cfg.recipient.kem,cfg.recipient.sign.x]);
 if(keys.size!==4)throw Error('shared endpoint key');
 for(const g of cfg.policy.guardians)if([g.publicKey.kem,g.publicKey.sign.x,g.approvalKey.x].some(k=>keys.has(k)))throw Error('shared participant guardian key');
 p.fields(cfg.admission,['trusted','feed_file','expected_checkpoint']);
 for(const pin of cfg.admission.trusted)if(keys.has(pin.issuer_key.x))throw Error('shared participant issuer key');
 const statusFile=path.join(dir,'status.jsonl');
 if(!fs.existsSync(statusFile)&&cfg.admission.expected_checkpoint!=='new')throw Error('checkpoint missing');
 const anchorFile=path.join(dir,'checkpoint-pin.json');
 if(!fs.existsSync(anchorFile)){
  if(fs.existsSync(statusFile))throw Error('checkpoint pin missing; reconcile');
  writeNew(anchorFile,{checkpoint:cfg.admission.expected_checkpoint});
 }
 const anchor=readPrivate(anchorFile);p.fields(anchor,['checkpoint']);
 const journal=new Journal(statusFile);
 const actual=journal.get('checkpoint')===undefined?'new':p.hash(journal.get('checkpoint'));
 if(anchor.checkpoint!==actual){journal.close();throw Error('checkpoint anchor mismatch; reconcile');}
 const saveAnchor=()=>{
  const checkpoint=journal.get('checkpoint')===undefined?'new':p.hash(journal.get('checkpoint'));
  if(checkpoint===anchor.checkpoint)return;
  const tmp=anchorFile+'.'+require('node:crypto').randomUUID();writeNew(tmp,{checkpoint});
  fs.renameSync(tmp,anchorFile);const fd=fs.openSync(dir,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 };
 try{
  const admission=new ReleaseGate({policy:cfg.policy,trusted:cfg.admission.trusted,journal,authorization,
   feed:()=>readPrivate(cfg.admission.feed_file),expected_checkpoint:anchor.checkpoint});
  const local=args.operation==='prepare'?cfg.sender:cfg.recipient;
  const client=new Client({directory:cfg.client_directory,mailbox:local.mailbox});
  if(p.keyId(client.key().publicKey)!==p.keyId(local))throw Error('local endpoint key mismatch');
  if(args.operation==='prepare'){
   fields(args,['operation','plaintext','public_text','padding']);admission.check();
   return client.prepare({plaintext:args.plaintext,public_text:args.public_text||'',padding:args.padding||'none',
    recipient:cfg.recipient,policy:cfg.policy,authorization,defer_capsule:true});
  }
  const requests=path.join(dir,'requests');privateDirectory(requests);
  if(args.operation==='grant'){
   fields(args,['operation','envelope','capsule']);admission.check();
   const h=p.validateEnvelope(args.envelope,cfg.sender,cfg.recipient);p.validateCapsule(args.envelope,args.capsule);
   if(h.mode!=='guarded'||h.policy_hash!==p.hash(cfg.policy))throw Error('wrong guarded policy');
   const id=p.hash(args.envelope),file=path.join(requests,id+'.json');
   let saved;
   if(fs.existsSync(file))saved=readPrivate(file);
   else{saved={envelope:args.envelope,capsule:args.capsule,grant:makeGrant(args.envelope,client.key())};writeNew(file,saved);}
   syncSaved(file);
   validateGrant(saved.grant,args.envelope,cfg.recipient);
   return {request_id:id,grant:saved.grant,note:'Separate signed guardian approvals are required; no charge or share requested.'};
  }
  fields(args,args.operation==='dispute'?['operation','request_id','complaint']:['operation','request_id','approvals','padding']);
  if(typeof args.request_id!=='string'||!/^[a-f0-9]{64}$/.test(args.request_id))throw Error('invalid request id');
  const saved=readPrivate(path.join(requests,args.request_id+'.json'));
  p.validateEnvelope(saved.envelope,cfg.sender,cfg.recipient);p.validateCapsule(saved.envelope,saved.capsule);
  if(p.hash(saved.envelope)!==args.request_id||saved.envelope.header.policy_hash!==p.hash(cfg.policy))throw Error('saved request mismatch');
  // Expired original grants may recover an already paid package; the coordinator
  // alone decides that. Never silently mint a replacement or change its fee key.
  validateGrant(saved.grant,saved.envelope,cfg.recipient,Date.now(),true);
  p.fields(cfg.coordinator,['url','token']);
  const u=new URL(cfg.coordinator.url);if(u.protocol!=='https:'||u.username||u.password||u.hash||u.search)throw Error('HTTPS coordinator required');
  const payer=readPrivate(cfg.payer_token_file);p.fields(payer,['token']);
  if(typeof payer.token!=='string'||!payer.token||typeof cfg.payer_wallet!=='string'||!cfg.payer_wallet)throw Error('payer binding required');
  assertAuthorization(authorization,cfg.policy,'endpoint');
  if(args.operation==='dispute')return request(cfg.coordinator.url+'/release',{operation:'dispute',request:saved,payer_token:payer.token,complaint:args.complaint},{token:cfg.coordinator.token,timeout:30000});
  if(!args.approvals||typeof args.approvals!=='object'||Array.isArray(args.approvals))throw Error('approvals required');
  fields(args.approvals,cfg.policy.guardians.map(g=>g.id));
  let count=0;for(const g of cfg.policy.guardians)if(args.approvals[g.id]){checkApproval(args.approvals[g.id],g,saved.grant,p.hash(saved.grant.body));count++;}
  if(count<cfg.policy.threshold)throw Error('independent approval quorum missing');
  // Gate is rechecked by each guardian/coordinator. Recovery of already-paid
  // packages intentionally remains possible after a guardian revocation.
  const release=await request(cfg.coordinator.url+'/release',{request:{...saved,approvals:args.approvals},payer_token:payer.token},{token:cfg.coordinator.token,timeout:30000});
  const feeKey='release:'+p.hash({envelope:args.request_id,recipient:saved.envelope.header.recipient_key,policy:saved.envelope.header.policy_hash});
  const meter=new DemiPassMeter({url:'https://api.dustforge.com',token:'unused-verifier-only',issuer:cfg.meter_issuer});
  const charge=meter.receipt(release.charge,feeKey);if(charge.wallet!==cfg.payer_wallet)throw Error('wrong signed payer');
  const paid=path.join(dir,'paid');privateDirectory(paid);
  const file=path.join(paid,args.request_id+'.json');
  if(!fs.existsSync(file))writeNew(file,{release,charge});
  else {const old=readPrivate(file);if(p.hash(old.release.responses)!==p.hash(release.responses)||old.charge.charge_id!==charge.charge_id)throw Error('conflicting paid replay');}
  syncSaved(file);
  const opened=await client.openAcknowledged({...saved,sender:cfg.sender,policy:cfg.policy,release,padding:args.padding||'none'});
  return {...opened,charge,request_id:args.request_id,replayed:release.replayed===true};
 }finally{try { if (!journal.failed) saveAnchor(); } finally { journal.close(); }}
}
async function main(){
 const dir=path.resolve(process.argv[2]||'');let size=0,parts=[];
 for await(const b of process.stdin){size+=b.length;if(size>98304)throw Error('request too large');parts.push(b);}
 const args=JSON.parse(Buffer.concat(parts).toString('utf8'));
 const result=await operation(dir,args);process.stdout.write(JSON.stringify(result)+'\n');
}
if(require.main===module)main().catch(()=>{process.stderr.write('guarded endpoint held; preserve request and reconcile any uncertain charge\n');process.exitCode=1;});
module.exports={operation};
