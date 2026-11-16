"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const { Client } = require("../sealed/client"),
  p = require("../sealed/crypto");
function dir(t) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "sealed-client-"));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}
test("local identities persist; deferred capsule is not transported; plaintext never persists", async (t) => {
  const root = dir(t),
    alice = new Client({
      directory: path.join(root, "alice"),
      mailbox: "audit-brain",
    }),
    bob = new Client({
      directory: path.join(root, "bob"),
      mailbox: "brain-flimflam",
    });
  const a = await alice.initialize(),
    b = await bob.initialize();
  assert.equal((await alice.initialize()).fingerprint, a.fingerprint);
  const prepared = await alice.prepare({
      recipient: b.public_key,
      plaintext: "PRIVATE local content",
      public_text: "public note",
    }),
    wire = alice.transport(prepared.id);
  assert.equal(wire.payload_type, p.FORMAT);
  assert.equal(wire.to, "brain-flimflam");
  assert.equal(JSON.parse(wire.body).capsule, null);
  assert(!wire.body.includes("PRIVATE"));
  const envelope = JSON.parse(wire.body).envelope;
  await assert.rejects(bob.open({ envelope, sender: a.public_key }));
  assert.equal(
    await bob.open({
      envelope,
      sender: a.public_key,
      capsule: alice.capsule(prepared.id),
    }),
    "PRIVATE local content",
  );
  for (const sub of ["keys", "outbox", "capsules"])
    for (const f of fs.readdirSync(path.join(root, "alice", sub))) {
      const file = path.join(root, "alice", sub, f);
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
      assert(!fs.readFileSync(file, "utf8").includes("PRIVATE"));
    }
  assert.throws(() => alice.capsule("../../key"));
  assert.throws(() => alice.transport(prepared.id.replace(/.$/, "x")));
});
test("unsafe key files and a different successor key do not inherit access from mailbox name", async (t) => {
  const root = dir(t),
    a = new Client({
      directory: path.join(root, "a"),
      mailbox: "sender-mailbox",
    }),
    b = new Client({
      directory: path.join(root, "b"),
      mailbox: "recipient-mailbox",
    });
  const ap = await a.initialize(),
    bp = await b.initialize();
  const r = await a.prepare({
    recipient: bp.public_key,
    plaintext: "only original key",
    defer_capsule: false,
  });
  const packet = JSON.parse(a.transport(r.id).body);
  const successor = new Client({
    directory: path.join(root, "successor"),
    mailbox: "recipient-mailbox",
  });
  await successor.initialize();
  await assert.rejects(
    successor.open({ ...packet, sender: ap.public_key }),
    /substitution/,
  );
  fs.chmodSync(a.keyFile, 0o644);
  assert.throws(() => a.key(), /unsafe/);
  fs.chmodSync(a.keyFile, 0o600);
  const original = a.keyFile + ".original";
  fs.renameSync(a.keyFile, original);
  fs.symlinkSync(original, a.keyFile);
  assert.throws(() => a.key());
});
test("MCP endpoint functions require explicit opt-in and never enable guardians", async () => {
  const sdk = require("../index");
  const old = process.env.DEMIPASS_SEALED_ENABLE;
  delete process.env.DEMIPASS_SEALED_ENABLE;
  try {
    await assert.rejects(sdk.conduitSealedIdentity(), /opt-in/);
    await assert.rejects(sdk.conduitSealedPrepare({ policy: {} }), /disabled/);
  } finally {
    if (old !== undefined) process.env.DEMIPASS_SEALED_ENABLE = old;
  }
});
