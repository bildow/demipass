"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"),
  os = require("node:os"), path = require("node:path"), { spawn, spawnSync } = require("node:child_process");
const p = require("../sealed/crypto"), enroll = require("../sealed/enrollment"), r = require("../sealed/revocation");
async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "conduit-revoke-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, "state"); fs.mkdirSync(dir, { mode: 0o700 });
  const guardians = await Promise.all([0, 1, 2].map(i => p.identity("guardian-" + i)));
  const approvals = await Promise.all([0, 1, 2].map(i => p.identity("approval-" + i)));
  const issuers = await Promise.all([0, 1, 2].map(i => p.identity("issuer-" + i)));
  const policy = { version: 1, epoch: 1, threshold: 2, assurance: "fixture", guardians: guardians.map((g,i) => ({
    id: "guardian-" + i, publicKey: g.publicKey, approvalKey: approvals[i].publicKey.sign,
    domains: { host: "host-" + i, admin: "admin-" + i, credential: "credential-" + i, recovery: "recovery-" + i } })) };
  const trusted = issuers.map((id,i) => ({ guardian_id: "guardian-" + i, issuer_id: "issuer-" + i,
    issuer_key: id.publicKey.sign, deployment_sha256: p.hash({ deployment: i }) }));
  const now = Date.now(), sign = (body,i) => ({ ...body, signature: p.sign(body, issuers[i].signPrivate) });
  const evidence = policy.guardians.map((g,i) => sign({ format: enroll.FORMAT, policy_hash: p.hash(policy),
    guardian_id: g.id, guardian_fingerprint: p.keyId(g.publicKey), approval_key_hash: p.hash(g.approvalKey),
    domains: g.domains, deployment_sha256: trusted[i].deployment_sha256, issued_at: now - 1000,
    expires_at: now + 600000, issuer_id: trusted[i].issuer_id },i));
  const snapshots = (serial = 1, state = "active") => policy.guardians.map((g,i) => sign({ format: r.FORMAT,
    policy_hash: p.hash(policy), guardian_id: g.id, issuer_id: trusted[i].issuer_id, serial,
    state: i === 0 ? state : "active", issued_at: now - 100, expires_at: now + 120000 },i));
  const input = { policy, evidence, trusted, snapshots: snapshots(), now };
  let count = 0;
  const write = (body) => { const f = path.join(root, "request-" + count++ + ".json"); fs.writeFileSync(f,JSON.stringify(body),{mode:0o600}); return f; };
  const request = (expected = "new", changes = {}) => ({ fixture: true, mode: "evaluate", expected_checkpoint: expected,
    policy, evidence, trusted, snapshots: snapshots(), ...changes });
  const command = (body, env = process.env) => spawnSync("sh",[path.resolve(__dirname,"../sealed/revocation.sh"),dir,write(body)],
    { encoding:"utf8", timeout:10000, env });
  return { root, dir, input, sign, snapshots, request, command, write };
}
test("fresh signed records allow only offline evidence; revocation is sticky across higher serials", async t => {
  const f = await fixture(t), initial = r.evaluate(f.input);
  assert.equal(initial.verdict,"evidence_current"); assert.equal(initial.live_guardian_release,false);
  const revoked = r.evaluate({ ...f.input, snapshots:f.snapshots(2,"revoked"), previous:initial.checkpoint });
  assert.equal(revoked.verdict,"hold"); assert.deepEqual(revoked.revoked,["guardian-0"]);
  const attempted = r.evaluate({ ...f.input, snapshots:f.snapshots(3), previous:revoked.checkpoint });
  assert.equal(attempted.verdict,"hold"); assert.deepEqual(attempted.revoked,["guardian-0"]);
  assert.throws(()=>p.policyForUse(f.input.policy),/live guardian release disabled/);
});
test("missing, malformed, stale, forged, forked and rollback status evidence is refused", async t => {
  const f = await fixture(t), prior=r.evaluate(f.input).checkpoint;
  const cases={
    missing:x=>x.snapshots.pop(), duplicate:x=>{x.snapshots[1]=x.snapshots[0];},
    forged:x=>{x.snapshots[0].signature="A".repeat(86);},
    expired:x=>{const {signature,...b}=x.snapshots[0];b.expires_at=x.now;x.snapshots[0]=f.sign(b,0);},
    future:x=>{const {signature,...b}=x.snapshots[0];b.issued_at=x.now+1;x.snapshots[0]=f.sign(b,0);},
    overlong:x=>{const {signature,...b}=x.snapshots[0];b.expires_at=x.now+r.MAX_LIFETIME;x.snapshots[0]=f.sign(b,0);},
    wrongPolicy:x=>{x.snapshots[0].policy_hash="0".repeat(64);},
    wrongIssuer:x=>{x.snapshots[0].issuer_id="issuer-1";},
    badState:x=>{x.snapshots[0].state="unknown";},
    zeroSerial:x=>{x.snapshots[0].serial=0;},
    extraField:x=>{x.snapshots[0].allow=true;},
    fork:x=>{x.snapshots=f.snapshots(1,"revoked");},
    rollback:x=>{x.previous=r.evaluate({...f.input,snapshots:f.snapshots(2)}).checkpoint;},
    malformedCheckpoint:x=>{x.previous.entries["guardian-0"].revoked="false";},
    changedTrust:x=>{x.previous.context_hash="0".repeat(64);},
  };
  for(const [name,mutate] of Object.entries(cases)) await t.test(name,()=>{
    const x=structuredClone({...f.input,previous:prior}); mutate(x); assert.throws(()=>r.evaluate(x));
  });
});
test("real process restarts retain checkpoints, reject stale callers, and never clear revocation", async t => {
  const f=await fixture(t), first=f.command(f.request()); assert.equal(first.status,0,first.stderr);
  const a=JSON.parse(first.stdout); assert.equal(a.verdict,"evidence_current");
  const stale=f.command(f.request()); assert.equal(stale.status,2); assert.equal(JSON.parse(stale.stdout).verdict,"hold");
  const revoked=f.command(f.request(a.checkpoint_hash,{snapshots:f.snapshots(2,"revoked")})); assert.equal(revoked.status,0);
  const b=JSON.parse(revoked.stdout); assert.equal(b.verdict,"hold");
  const restart=f.command(f.request(b.checkpoint_hash,{snapshots:f.snapshots(3)})); assert.equal(restart.status,0);
  assert.equal(JSON.parse(restart.stdout).verdict,"hold");
  const inspect=f.command({fixture:true,mode:"inspect"}); assert.equal(inspect.status,0);
  assert.equal(JSON.parse(inspect.stdout).verdict,"inspect_only");
  assert.equal(JSON.parse(inspect.stdout).checkpoint_hash,JSON.parse(restart.stdout).checkpoint_hash);
  const source=fs.readFileSync(path.join(f.dir,"status.jsonl"));
  assert.equal(source.toString().trim().split("\n").length,3);
  assert.equal(f.command(f.request(JSON.parse(restart.stdout).checkpoint_hash,{fixture:false})).status,2);
  assert.deepEqual(fs.readFileSync(path.join(f.dir,"status.jsonl")),source);
});
test("deleted, truncated, corrupt or rolled-back storage cannot satisfy the caller's newer checkpoint", async t => {
  const f=await fixture(t), a=JSON.parse(f.command(f.request()).stdout), file=path.join(f.dir,"status.jsonl");
  const old=fs.readFileSync(file), b=JSON.parse(f.command(f.request(a.checkpoint_hash,{snapshots:f.snapshots(2)})).stdout);
  for(const mode of ["old","empty","partial","corrupt","missing"]) await t.test(mode,()=>{
    if(mode==="missing") fs.rmSync(file,{force:true});
    else fs.writeFileSync(file,mode==="old"?old:mode==="empty"?"":mode==="partial"?old.subarray(0,old.length-1):"{}\n",{mode:0o600});
    const got=f.command(f.request(b.checkpoint_hash,{snapshots:f.snapshots(3)}));
    assert.equal(got.status,2); assert.equal(JSON.parse(got.stdout).verdict,"hold");
  });
});
test("OS lock refuses competing process and releases on kill; failed fsync never returns current evidence", async t => {
  const f=await fixture(t), lock=path.join(f.dir,"lease.lock");
  fs.writeFileSync(lock,"",{mode:0o600});
  const child=spawn("sh",["-c",'exec 9>>"$1"; /usr/bin/flock -xn 9 || exit 3; exec node -e \'console.log("locked"); setInterval(()=>{},1000)\'',"lock-test",lock],{stdio:["ignore","pipe","pipe"]});
  t.after(()=>{if(child.exitCode===null)child.kill("SIGKILL");});
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error("lock fixture timeout")),5000);
    child.stdout.once("data",()=>{clearTimeout(timer);resolve();});child.once("error",reject);});
  assert.equal(f.command(f.request()).status,3);
  child.kill("SIGKILL"); await new Promise(resolve=>child.once("exit",resolve));
  const injection=path.join(f.root,"fail-fsync.js");
  // First two fsyncs open/reconcile the journal; the third is the checkpoint append.
  fs.writeFileSync(injection,'const f=require("node:fs"), orig=f.fsyncSync; let n=0; f.fsyncSync=function(fd){if(++n===3)throw Error("injected fsync");return orig(fd);};');
  const fail=f.command(f.request(),{...process.env,NODE_OPTIONS:"--require="+injection});
  assert.equal(fail.status,2); assert.equal(JSON.parse(fail.stdout).verdict,"hold");
  // Ambiguous write is reconciled under a fresh lock; retry with stale 'new' refuses.
  const inspect=f.command({fixture:true,mode:"inspect"}); assert.equal(inspect.status,0);
  assert.notEqual(JSON.parse(inspect.stdout).checkpoint_hash,"new");
  assert.equal(f.command(f.request()).status,2);
  const recovered=f.command(f.request(JSON.parse(inspect.stdout).checkpoint_hash));
  assert.equal(recovered.status,0); assert.equal(JSON.parse(recovered.stdout).verdict,"evidence_current");
});
test("checkpoint symlink, shared permissions and FIFO refuse before journal read", async t => {
  const f=await fixture(t), file=path.join(f.dir,"status.jsonl"), target=path.join(f.root,"untouched");
  fs.writeFileSync(target,"",{mode:0o600}); fs.symlinkSync(target,file);
  assert.equal(f.command(f.request()).status,2); assert.equal(fs.readFileSync(target).length,0);
  fs.unlinkSync(file); fs.writeFileSync(file,"",{mode:0o644});
  assert.equal(f.command(f.request()).status,2); fs.unlinkSync(file);
  assert.equal(spawnSync("mkfifo",["-m","600",file]).status,0);
  const got=f.command(f.request()); assert.equal(got.status,2); assert.equal(got.signal,null);
});
test("wrapper rejects FIFO, directory, symlink and shared lock paths before open", async t => {
  const f=await fixture(t), lock=path.join(f.dir,"lease.lock"), target=path.join(f.root,"lock-target");
  for (const kind of ["fifo","directory","symlink","shared"]) await t.test(kind,()=>{
    if(kind==="fifo") assert.equal(spawnSync("mkfifo",["-m","600",lock]).status,0);
    if(kind==="directory") fs.mkdirSync(lock,{mode:0o700});
    if(kind==="symlink") {fs.writeFileSync(target,"unchanged",{mode:0o600});fs.symlinkSync(target,lock);}
    if(kind==="shared") {fs.writeFileSync(lock,"",{mode:0o600});fs.chmodSync(lock,0o644);}
    const got=spawnSync("sh",[path.resolve(__dirname,"../sealed/revocation.sh"),f.dir,f.write(f.request())],
      {encoding:"utf8",timeout:2000});
    assert.equal(got.error,undefined); assert.equal(got.signal,null); assert.equal(got.status,2);
    assert.equal(fs.existsSync(path.join(f.dir,"status.jsonl")),false);
    if(kind==="symlink") assert.equal(fs.readFileSync(target,"utf8"),"unchanged");
    fs.rmSync(lock,{recursive:true});
  });
  // Refusal leaves the instance usable once the bad entry is removed.
  assert.equal(f.command(f.request()).status,0);
});
