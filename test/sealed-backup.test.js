"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"),
  os = require("node:os"), path = require("node:path");
const p = require("../sealed/crypto"), { Client } = require("../sealed/client"),
  { exportIdentity, restoreIdentity } = require("../sealed/backup");
async function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "conduit-backup-test-"));
  t.after(() => fs.rmSync(dir, { force: true, recursive: true }));
  const client = new Client({ directory: path.join(dir, "original"), mailbox: "recipient-mailbox" });
  const pub = await client.initialize(), recoveryIdentity = await p.identity("offline-recovery");
  const backup = await exportIdentity({ client, recoveryPublic: recoveryIdentity.publicKey });
  const target = (name) => new Client({ directory: path.join(dir, name), mailbox: client.mailbox });
  return { client, backup, recoveryIdentity, expectedFingerprint: pub.fingerprint, target };
}
test("encrypted identity backup restores same pin and decrypts pre-loss message without rekey", async (t) => {
  const f = await fixture(t), sender = await p.identity("sender-mailbox");
  const packet = await p.seal({ sender, recipient: f.client.key().publicKey, plaintext: "pre-loss message" });
  const serialized = JSON.stringify(f.backup), id = f.client.key();
  assert(!serialized.includes(id.kemPrivate)); assert(!serialized.includes(id.signPrivate.d));
  fs.unlinkSync(f.client.keyFile); // Disposable simulated loss only.
  const restored = f.target("restored");
  const result = await restoreIdentity({ ...f, client: restored });
  assert.equal(result.fingerprint, f.expectedFingerprint);
  assert.equal(result.live_guardian_release, false);
  assert.equal((await restored.initialize()).fingerprint, f.expectedFingerprint);
  assert.equal(fs.statSync(restored.keyFile).mode & 0o777, 0o600);
  assert.equal(await restored.open({ ...packet, sender: sender.publicKey }), "pre-loss message");
  const before = fs.readFileSync(restored.keyFile);
  await assert.rejects(restoreIdentity({ ...f, client: restored }), { code: "EEXIST" });
  assert.deepEqual(fs.readFileSync(restored.keyFile), before);
});
test("backup refuses wrong pins, recovery keys, mailbox, tampering and malformed identities before writes", async (t) => {
  const f = await fixture(t), other = await p.identity("wrong-recovery");
  const cases = {
    "no independent pin": (x) => { delete x.expectedFingerprint; },
    "wrong pin": (x) => { x.expectedFingerprint = "0".repeat(64); },
    "wrong recovery": (x) => { x.recoveryIdentity = other; },
    "tampered ciphertext": (x) => { x.backup.box.ct = "A".repeat(64); },
    "tampered metadata": (x) => { x.backup.header.created_at++; },
    "unknown fields": (x) => { x.backup.authorized = true; },
    "oversize": (x) => { x.backup.box.ct = "A".repeat(8193); },
    "mailbox mismatch": (x) => { x.client.mailbox = "different-mailbox"; },
    "null backup": (x) => { x.backup = null; },
  };
  let i = 0;
  for (const [name, mutate] of Object.entries(cases)) await t.test(name, async () => {
    const client = f.target("negative-" + i++), x = { ...f, client, backup: structuredClone(f.backup) };
    mutate(x); await assert.rejects(restoreIdentity(x)); assert(!fs.existsSync(client.keyFile));
  });
  await assert.rejects(exportIdentity({ client: f.client, recoveryPublic: f.client.key().publicKey }), /separate/);
  // Signed and authentically encrypted, but corrupt key material: signature alone is insufficient.
  for (const field of ["kemPrivate", "signPrivate"]) await t.test("mismatched " + field, async () => {
    const client = f.target("bad-" + field), id = f.client.key(); id[field] = other[field];
    const header = f.backup.header;
    const body = { header, box: await p.wrap(f.recoveryIdentity.publicKey, p.data(id), header) };
    const backup = { ...body, signature: p.sign(body, f.client.key().signPrivate) };
    await assert.rejects(restoreIdentity({ ...f, client, backup }));
    assert(!fs.existsSync(client.keyFile));
  });
});
test("restore refuses symlinks and concurrent restores cannot overwrite each other", async (t) => {
  const f = await fixture(t), linked = f.target("linked");
  fs.symlinkSync(f.client.keyFile, linked.keyFile);
  const before = fs.readFileSync(f.client.keyFile);
  await assert.rejects(restoreIdentity({ ...f, client: linked }), { code: "EEXIST" });
  assert.deepEqual(fs.readFileSync(f.client.keyFile), before);
  const client = f.target("race");
  const outcomes = await Promise.allSettled([restoreIdentity({ ...f, client }), restoreIdentity({ ...f, client })]);
  assert.equal(outcomes.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(outcomes.find((r) => r.status === "rejected").reason.code, "EEXIST");
  assert.equal(p.keyId(client.key().publicKey), f.expectedFingerprint);
});
test("offline command exports and restores with explicit pins and never logs key material", async (t) => {
  const f = await fixture(t), { spawnSync } = require("node:child_process");
  const root = path.dirname(f.client.dir), backupFile = path.join(root, "encrypted-backup.json"),
    publicFile = path.join(root, "recovery-public.json"), privateFile = path.join(root, "recovery-private.json");
  fs.writeFileSync(publicFile, JSON.stringify(f.recoveryIdentity.publicKey), { mode: 0o600 });
  fs.writeFileSync(privateFile, JSON.stringify(f.recoveryIdentity), { mode: 0o600 });
  const run = (args) => spawnSync(process.execPath, [path.resolve(__dirname, "../sealed/backup-cli.js"), ...args],
    { encoding: "utf8", timeout: 10000 });
  const exp = ["export", f.client.dir, f.client.mailbox, publicFile, p.keyId(f.recoveryIdentity.publicKey), backupFile];
  const exported = run(exp);
  assert.equal(exported.status, 0, exported.stderr);
  assert.equal(JSON.parse(exported.stdout).fingerprint, f.expectedFingerprint);
  assert.equal(fs.statSync(backupFile).mode & 0o777, 0o600);
  assert.notEqual(run(exp).status, 0); // Never overwrite even an encrypted prior backup.
  const restoredDir = path.join(root, "cli-restored");
  const restored = run(["restore", restoredDir, f.client.mailbox, privateFile, f.expectedFingerprint, backupFile]);
  assert.equal(restored.status, 0, restored.stderr);
  assert.equal(JSON.parse(restored.stdout).fingerprint, f.expectedFingerprint);
  for (const text of [exported.stdout, exported.stderr, restored.stdout, restored.stderr]) {
    assert(!text.includes(f.recoveryIdentity.kemPrivate));
    assert(!text.includes(f.client.key().signPrivate.d));
  }
  const wrong = run(["export", f.client.dir, f.client.mailbox, publicFile, "0".repeat(64), path.join(root, "wrong.json")]);
  assert.notEqual(wrong.status, 0); assert(!fs.existsSync(path.join(root, "wrong.json")));
});
