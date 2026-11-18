"use strict";
const test=require('node:test'), assert=require('node:assert/strict'), fs=require('node:fs');
const {DemiPassMeter}=require('../sealed/demipass-meter');
const {meterFixture}=require('./helpers/sealed-meter');
const {fixture}=require('./helpers/sealed-release-fixture');
const {Journal}=require('../sealed/journal');
const p=require('../sealed/crypto');
async function httpFixture(t) {
 const f=await fixture(t), server=await meterFixture();t.after(server.close);
 f.server=server;f.coordinator.meter=new DemiPassMeter(server.config);return f;
}
const token='fixture-payer-token';
function complaint(f,reason='decryption_failed') {
 const body={version:1,type:'conduit-release-dispute',envelope_hash:p.hash(f.req.envelope),grant_hash:p.hash(f.req.grant.body),reason};
 return {body,signature:p.sign(body,f.recipient.signPrivate)};
}
test('old gateway contract refuses before verification, charging or guardian RPC',async t=>{
 const f=await httpFixture(t);f.server.state.contract=false;
 await assert.rejects(f.coordinator.release(f.req,token),/atomic charge contract/);
 assert.equal(f.server.state.charges,0);assert.equal(f.server.state.requests.length,1);
});
test('price rise after preflight cannot debit beyond 2 DD',async t=>{
 const f=await httpFixture(t),m=f.coordinator.meter,pre=m.precheck.bind(m);
 m.precheck=async(...args)=>{await pre(...args);f.server.state.margin=20;};
 await assert.rejects(f.coordinator.release(f.req,token));assert.equal(f.server.state.charges,0);
});
test('24 concurrent releases debit once and return only the identical paid package',async t=>{
 const f=await httpFixture(t);
 const outputs=await Promise.all(Array.from({length:24},()=>f.coordinator.release(f.req,token)));
 assert.equal(f.server.state.charges,1);assert.equal(outputs.filter(x=>!x.replayed).length,1);
 for(const out of outputs){assert.deepEqual(out.responses,outputs[0].responses);assert.equal(out.charge.dd,2);}
 assert.equal(f.coordinator.locks.size,0);
 for(const r of f.server.state.requests.filter(x=>x.path.endsWith('/charge')))assert.equal(r.body.max_total_dd,2);
});
test('lost successful charge response holds first caller; restart recovers signed receipt without charge',async t=>{
 const f=await httpFixture(t),m=f.coordinator.meter,charge=m.charge.bind(m);
 m.charge=async(...args)=>{await charge(...args);throw Error('lost response');};
 await assert.rejects(f.coordinator.release(f.req,token),/lost response/);
 assert.equal(f.server.state.charges,1);
 const file=f.coordinator.journal.file;f.coordinator.journal.close();
 const restored=new Journal(file);t.after(()=>restored.close());f.coordinator.journal=restored;
 m.charge=async()=>{throw Error('must not retry debit');};
 f.revoke(); // Paid recovery returns the original fulfillment, no new authority.
 const out=await f.coordinator.release(f.req,token);assert.equal(out.charge.dd,2);
 assert.equal(f.server.state.charges,1);assert.equal(out.charge.max_total_dd,2);
});
test('tampered, unsigned or wrong-key recovery cannot authorize disclosure',async t=>{
 for(const mode of ['signature','unsigned','key','payer','amount','ceiling','missing_ceiling'])await t.test(mode,async t=>{
  const f=await httpFixture(t),m=f.coordinator.meter,charge=m.charge.bind(m);
  m.charge=async(...args)=>{await charge(...args);throw Error('lost response');};
  await assert.rejects(f.coordinator.release(f.req,token));
  const [key,row]=[...f.server.state.ledger][0];
  if(mode==='signature')f.server.state.badReceipt=true;
  if(mode==='key')row.idempotency_key='another-charge-key';
  if(mode==='payer')row.payer='another-wallet';
  if(mode==='amount')row.dd=3;
  if(mode==='ceiling')row.max_total_dd=3;
  if(mode==='missing_ceiling')delete row.max_total_dd;
  if(mode==='unsigned') {const call=m.call.bind(m);m.call=async(...args)=>{const r=await call(...args);if(args[0].includes('/charges?'))delete r.received[0].sig;return r;};}
  const before=fs.readFileSync(f.coordinator.journal.file);
  await assert.rejects(f.coordinator.release(f.req,token));
  assert.deepEqual(fs.readFileSync(f.coordinator.journal.file),before);assert.equal(f.server.state.charges,1);
 });
});
test('signed complaints are durable, idempotent, contain no plaintext, and never pretend a refund',async t=>{
 const f=await httpFixture(t),c=complaint(f);
 await assert.rejects(f.coordinator.dispute(f.req,token,c),/paid original/);
 await f.coordinator.release(f.req,token);
 const first=await f.coordinator.dispute(f.req,token,c), replay=await f.coordinator.dispute(f.req,token,c);
 assert.equal(first.status,'manual_review_required');assert.equal(first.refund,'not_issued');
 assert.equal(replay.dispute_id,first.dispute_id);assert.equal(replay.replayed,true);assert.equal(f.server.state.charges,1);
 assert(!JSON.stringify(first).includes('actual private output'));assert(!('responses' in first));
 const file=f.coordinator.journal.file;f.coordinator.journal.close();
 const journal=new Journal(file);t.after(()=>journal.close());f.coordinator.journal=journal;
 assert.equal((await f.coordinator.dispute(f.req,token,c)).replayed,true);
 await assert.rejects(f.coordinator.dispute(f.req,token,complaint(f,'refund_granted')),/invalid signed/);
 await assert.rejects(f.coordinator.dispute(f.req,token,{...c,signature:'forged'}));
});
test('dispute persistence failure reports no success and does not alter the paid package',async t=>{
 const f=await httpFixture(t);const paid=await f.coordinator.release(f.req,token);
 const set=f.coordinator.journal.set.bind(f.coordinator.journal);
 f.coordinator.journal.set=(key,value)=>{if(key.startsWith('dispute:'))throw Error('dispute fsync failed');return set(key,value);};
 await assert.rejects(f.coordinator.dispute(f.req,token,complaint(f)),/fsync/);
 assert.deepEqual((await f.coordinator.release(f.req,token)).responses,paid.responses);
 assert.equal(f.server.state.charges,1);
});
test('unreadable charge lookup never falls through to another debit',async t=>{
 const f=await httpFixture(t);f.server.state.badLookup=true;
 await assert.rejects(f.coordinator.release(f.req,token),/lookup/);assert.equal(f.server.state.charges,0);
});
test('paid dispute authenticates without current pricing, metadata or another charge allowance',async t=>{
 for(const mode of ['price_changed','old_contract','metadata_unavailable','budget_exhausted'])await t.test(mode,async t=>{
  const f=await httpFixture(t),c=complaint(f);
  await f.coordinator.release(f.req,token);
  if(mode==='price_changed')f.server.state.margin=20;
  if(mode==='old_contract')f.server.state.contract=false;
  if(mode==='metadata_unavailable')f.server.state.metadataUnavailable=true;
  if(mode==='budget_exhausted')f.server.state.budgetExhausted=true;
  f.coordinator.meter.precheck=async()=>{throw Error('dispute must not precheck a new payment');};
  f.coordinator.guardians=Object.fromEntries(f.policy.guardians.map(g=>[g.id,()=>{throw Error('dispute must not request shares');}]));
  const before=f.server.state.requests.length;
  const row=await f.coordinator.dispute(f.req,token,c);
  assert.equal(row.status,'manual_review_required');assert.equal(row.refund,'not_issued');
  assert.deepEqual(f.server.state.requests.slice(before).map(r=>r.path),['/api/services/verify']);
  assert.equal(f.server.state.charges,1);
  const file=f.coordinator.journal.file;f.coordinator.journal.close();
  const journal=new Journal(file);t.after(()=>journal.close());f.coordinator.journal=journal;
  assert.equal((await f.coordinator.dispute(f.req,token,c)).dispute_id,row.dispute_id);
  assert.equal((await f.coordinator.dispute(f.req,token,c)).replayed,true);
 });
});
test('dispute pricing independence does not bypass payer authentication or recipient proof',async t=>{
 for(const mode of ['revoked','unknown_token','wrong_payer','forged_complaint','forged_grant','verify_unavailable'])await t.test(mode,async t=>{
  const f=await httpFixture(t);await f.coordinator.release(f.req,token);
  f.server.state.contract=false;
  let caller=token,c=complaint(f),req=f.req;
  if(mode==='revoked')f.server.state.verifyOk=false;
  if(mode==='unknown_token')caller='invalid-token';
  if(mode==='wrong_payer')f.server.state.wallet='different-authenticated-wallet';
  if(mode==='forged_complaint')c={...c,signature:'forged'};
  if(mode==='forged_grant')req={...req,grant:{...req.grant,signature:'forged'}};
  if(mode==='verify_unavailable'){
   const call=f.coordinator.meter.call.bind(f.coordinator.meter);
   f.coordinator.meter.call=async(path,...args)=>{if(path==='/api/services/verify')throw Error('verification unavailable');return call(path,...args);};
  }
  const before=fs.readFileSync(f.coordinator.journal.file);
  await assert.rejects(f.coordinator.dispute(req,caller,c));
  assert.deepEqual(fs.readFileSync(f.coordinator.journal.file),before);assert.equal(f.server.state.charges,1);
 });
});
test('paid dispute accepts an expired original grant but never an unpaid one',async t=>{
 const f=await httpFixture(t),c=complaint(f);
 await f.coordinator.release(f.req,token);
 const unpaid=await f.message();
 f.time=f.req.grant.body.expires_at+1;
 assert(f.time>f.req.grant.body.expires_at);
 const row=await f.coordinator.dispute(f.req,token,c);
 assert.equal(row.status,'manual_review_required');assert.equal(row.refund,'not_issued');
 const otherBody={...c.body,envelope_hash:p.hash(unpaid.envelope),grant_hash:p.hash(unpaid.grant.body)};
 const other={body:otherBody,signature:p.sign(otherBody,f.recipient.signPrivate)};
 await assert.rejects(f.coordinator.dispute(unpaid,token,other),/paid original/);
 assert.equal(f.server.state.charges,1);
});
test('reordered and whitespace-varied signed complaint replays after journal restart without a second row',async t=>{
 const f=await httpFixture(t),c=complaint(f);
 await f.coordinator.release(f.req,token);
 const first=await f.coordinator.dispute(f.req,token,c);
 const file=f.coordinator.journal.file,before=fs.readFileSync(file);
 f.coordinator.journal.close();
 const journal=new Journal(file);t.after(()=>journal.close());f.coordinator.journal=journal;
 const rebuilt=JSON.parse(JSON.stringify({signature:c.signature,body:Object.fromEntries(Object.entries(c.body).reverse())},null,4));
 assert.notEqual(JSON.stringify(rebuilt),JSON.stringify(c));assert.notEqual(rebuilt,c);
 const replay=await f.coordinator.dispute(f.req,token,rebuilt);
 assert.equal(replay.dispute_id,first.dispute_id);assert.equal(replay.replayed,true);
 assert.deepEqual(fs.readFileSync(file),before);assert.equal(f.server.state.charges,1);
});
