"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const p = require("../sealed/crypto"),
  { Guardian, Coordinator, makeGrant, approve } = require("../sealed/guardian"),
  { Journal } = require("../sealed/journal"),
  { serve, request } = require("../sealed/http");
async function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "conduit-sealed-"));
  let journals = [];
  let servers = [];
  t.after(async () => {
    for (const s of servers) await s.close();
    for (const j of journals) {
      try {
        j.close();
      } catch {}
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const sender = await p.identity("sender-mailbox"),
    recipient = await p.identity("recipient-mailbox"),
    gids = await Promise.all([0, 1, 2].map((i) => p.identity("guardian-" + i))),
    approvers = await Promise.all(
      [0, 1, 2].map((i) => p.identity("approver-" + i)),
    );
  const policy = {
    version: 1,
    epoch: 1,
    threshold: 2,
    assurance: "fixture",
    guardians: gids.map((g, i) => ({
      id: "guardian-" + i,
      publicKey: g.publicKey,
      approvalKey: approvers[i].publicKey.sign,
      domains: {
        host: "fixture-host-" + i,
        admin: "fixture-admin-" + i,
        credential: "fixture-credential-" + i,
        recovery: "fixture-recovery-" + i,
      },
    })),
  };
  const journal = (file) => {
    const j = new Journal(path.join(dir, file));
    journals.push(j);
    return j;
  };
  const guardians = gids.map(
    (id, i) =>
      new Guardian({
        id: "guardian-" + i,
        identity: id,
        policy,
        sender: sender.publicKey,
        recipient: recipient.publicKey,
        journal: journal("g" + i),
        fixture: true,
      }),
  );
  const packet = await p.seal({
    sender,
    recipient: recipient.publicKey,
    plaintext: "HIGHLY PRIVATE fixture 42",
    policy,
    fixture: true,
  });
  const grant = makeGrant(packet.envelope, recipient),
    approvals = Object.fromEntries(
      guardians.map((g, i) => [g.id, approve(grant, g.id, approvers[i])]),
    );
  const req = { ...packet, grant, approvals },
    ledger = new Map();
  let chargeCount = 0;
  const meter = {
    identify: async (token) => {
      if (token !== "payer-token") throw Error("bad payer");
      return { wallet: "wallet-a", token_id: "token-a" };
    },
    precheck: async () => {},
    lookup: async (k) => ledger.get(k) || null,
    charge: async (w, cost, key) => {
      if (ledger.has(key)) return ledger.get(key);
      chargeCount++;
      const r = {
        wallet: w.wallet,
        action: "release",
        cost_dd: cost,
        dd: cost,
        charge_id: "charge-" + chargeCount,
      };
      ledger.set(key, r);
      return r;
    },
  };
  const calls = Object.fromEntries(
    guardians.map((g) => [
      g.id,
      (r) => g.release({ ...r, approval: r.approvals[g.id] }),
    ]),
  );
  const coordinator = new Coordinator({
    policy,
    sender: sender.publicKey,
    recipient: recipient.publicKey,
    journal: journal("coordinator"),
    meter,
    guardians: calls,
    fixture: true,
  });
  return {
    dir,
    sender,
    recipient,
    gids,
    approvers,
    policy,
    guardians,
    packet,
    req,
    meter,
    ledger,
    calls,
    coordinator,
    journal,
    journals,
    servers,
    charges: () => chargeCount,
  };
}
test("direct/deferred/partial-public envelopes authenticate content and reject wrong keys and swaps", async (t) => {
  const f = await fixture(t),
    packet = await p.seal({
      sender: f.sender,
      recipient: f.recipient.publicKey,
      plaintext: "secret",
      publicText: "public routing note",
    });
  const args = {
    ...packet,
    sender: f.sender.publicKey,
    recipient: f.recipient,
  };
  assert.equal(await p.open(args), "secret");
  assert(!JSON.stringify(packet).includes("secret"));
  await assert.rejects(p.open({ ...args, capsule: undefined }));
  const changed = structuredClone(packet.envelope);
  changed.header.public_text = "different";
  await assert.rejects(p.open({ ...args, envelope: changed }), /signature/);
  const wrong = await p.identity("recipient-mailbox");
  await assert.rejects(p.open({ ...args, recipient: wrong }), /substitution/);
  const another = await p.seal({
    sender: f.sender,
    recipient: f.recipient.publicKey,
    plaintext: "another",
  });
  await assert.rejects(
    p.open({ ...args, capsule: another.capsule }),
    /mismatch/,
  );
  const flipped = structuredClone(packet.envelope);
  flipped.payload.ct =
    (flipped.payload.ct[0] === "A" ? "B" : "A") + flipped.payload.ct.slice(1);
  await assert.rejects(p.open({ ...args, envelope: flipped }), /signature/);
  assert(!("private_text" in packet.envelope));
  assert.equal(packet.envelope.header.public_text, "public routing note");
});
test("2-of-3 real cryptographic shares with one unavailable guardian; quorum alone cannot read recipient box", async (t) => {
  const f = await fixture(t);
  delete f.calls["guardian-2"];
  const release = await f.coordinator.release(f.req, "payer-token");
  assert.equal(f.charges(), 1);
  assert.equal(release.charge.dd, 2);
  assert.equal(
    await p.open({
      ...f.packet,
      sender: f.sender.publicKey,
      recipient: f.recipient,
      policy: f.policy,
      release,
    }),
    "HIGHLY PRIVATE fixture 42",
  );
  await assert.rejects(
    p.open({
      ...f.packet,
      sender: f.sender.publicKey,
      recipient: f.recipient,
      policy: f.policy,
      release: { ...release, responses: release.responses.slice(0, 1) },
    }),
    /quorum/,
  );
  await assert.rejects(
    p.open({
      ...f.packet,
      sender: f.sender.publicKey,
      recipient: f.recipient,
      policy: f.policy,
      release: {
        ...release,
        responses: [release.responses[0], release.responses[0]],
      },
    }),
    /repeated/,
  );
  const noKey = { ...f.recipient, kemPrivate: f.gids[0].kemPrivate };
  await assert.rejects(
    p.open({
      ...f.packet,
      sender: f.sender.publicKey,
      recipient: noKey,
      policy: f.policy,
      release,
    }),
  );
  for (const file of fs.readdirSync(f.dir))
    assert(
      !fs
        .readFileSync(path.join(f.dir, file), "utf8")
        .includes("HIGHLY PRIVATE"),
    );
});
test("guardian enrollment rejects shared domains/keys, unknown assurance, and all live configurations", async (t) => {
  const f = await fixture(t);
  for (const domain of ["host", "admin", "credential", "recovery"]) {
    const x = structuredClone(f.policy);
    x.guardians[1].domains[domain] = x.guardians[0].domains[domain];
    assert.throws(() => p.policyShape(x), /shared/);
  }
  const x = structuredClone(f.policy);
  x.guardians[1].approvalKey = x.guardians[0].approvalKey;
  assert.throws(() => p.policyShape(x), /shared/);
  assert.throws(() => p.policyForUse(f.policy), /disabled/);
  assert.throws(
    () =>
      p.policyForUse({ ...f.policy, assurance: "reviewed" }, { fixture: true }),
    /disabled/,
  );
  assert.throws(
    () => p.policyShape({ ...f.policy, assurance: "unknown" }),
    /assurance/,
  );
  await assert.rejects(
    p.seal({
      sender: f.sender,
      recipient: f.recipient.publicKey,
      plaintext: "no fake production",
      policy: f.policy,
    }),
    /disabled/,
  );
});
test("one generic approval, wrong nonce, expired approval, and missing quorum never charge", async (t) => {
  const f = await fixture(t),
    bad = structuredClone(f.req);
  bad.approvals["guardian-1"] = bad.approvals["guardian-0"];
  bad.approvals["guardian-2"] = bad.approvals["guardian-0"];
  await assert.rejects(f.coordinator.release(bad, "payer-token"), /quorum/);
  assert.equal(f.charges(), 0);
  const stale = makeGrant(f.packet.envelope, f.recipient, {
    now: Date.now() - 400000,
  });
  await assert.rejects(
    f.coordinator.release({ ...f.req, grant: stale }, "payer-token"),
    /expired/,
  );
  const changed = structuredClone(f.req);
  changed.grant.body.request_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
  await assert.rejects(f.coordinator.release(changed, "payer-token"), /proof/);
  assert.equal(f.charges(), 0);
});
test("concurrent retry and new client request IDs return one package and one fee", async (t) => {
  const f = await fixture(t),
    results = await Promise.all(
      Array.from({ length: 8 }, () =>
        f.coordinator.release(f.req, "payer-token"),
      ),
    );
  assert.equal(f.charges(), 1);
  for (const r of results) assert.deepEqual(r.responses, results[0].responses);
  const grant = makeGrant(f.packet.envelope, f.recipient),
    again = await f.coordinator.release({ ...f.req, grant }, "payer-token");
  assert.equal(f.charges(), 1);
  assert.deepEqual(again.responses, results[0].responses);
  const other = await p.seal({
    sender: f.sender,
    recipient: f.recipient.publicKey,
    plaintext: "different",
  });
  await assert.rejects(
    f.coordinator.release(
      { ...f.req, grant: makeGrant(other.envelope, f.recipient) },
      "payer-token",
    ),
    /binding/,
  );
});
test("uncertain payment/restart lookup and expired paid retries do not debit twice", async (t) => {
  const f = await fixture(t);
  const charge = f.meter.charge;
  f.meter.charge = async (...args) => {
    await charge(...args);
    throw Error("connection lost after debit");
  };
  await assert.rejects(
    f.coordinator.release(f.req, "payer-token"),
    /connection lost/,
  );
  assert.equal(f.charges(), 1);
  f.coordinator.journal.close();
  f.coordinator.journal = f.journal("coordinator");
  f.coordinator.now = () => Date.now() + 400000;
  const recovered = await f.coordinator.release(f.req, "payer-token");
  assert.equal(recovered.charge.dd, 2);
  assert.equal(f.charges(), 1);
  assert.equal(
    await p.open({
      ...f.packet,
      sender: f.sender.publicKey,
      recipient: f.recipient,
      policy: f.policy,
      release: recovered,
    }),
    "HIGHLY PRIVATE fixture 42",
  );
});
test("prepare write failure prevents charging; paid fsync failure remains recoverable without early disclosure", async (t) => {
  const f = await fixture(t);
  const set = f.coordinator.journal.set.bind(f.coordinator.journal);
  f.coordinator.journal.set = () => {
    throw Error("prepare disk full");
  };
  await assert.rejects(
    f.coordinator.release(f.req, "payer-token"),
    /disk full/,
  );
  assert.equal(f.charges(), 0);
  f.coordinator.journal.set = set;
  const sync = fs.fsyncSync;
  let inject = false;
  const charge = f.meter.charge;
  f.meter.charge = async (...args) => {
    const r = await charge(...args);
    inject = true;
    return r;
  };
  fs.fsyncSync = (fd) => {
    if (inject && fd === f.coordinator.journal.fd) {
      inject = false;
      throw Error("paid fsync failed");
    }
    return sync(fd);
  };
  try {
    await assert.rejects(
      f.coordinator.release(f.req, "payer-token"),
      /fsync failed/,
    );
  } finally {
    fs.fsyncSync = sync;
  }
  assert.equal(f.charges(), 1);
  f.coordinator.journal.close();
  f.coordinator.journal = f.journal("coordinator");
  assert.equal(
    (await f.coordinator.release(f.req, "payer-token")).charge.dd,
    2,
  );
  assert.equal(f.charges(), 1);
});
test("charge mismatch, missing paid state and corrupt journal all hold", async (t) => {
  const f = await fixture(t);
  const charge = f.meter.charge;
  f.meter.charge = async (...a) => ({ ...(await charge(...a)), dd: 3 });
  await assert.rejects(f.coordinator.release(f.req, "payer-token"), /mismatch/);
  assert.equal(f.charges(), 1);
  f.coordinator.journal.close();
  fs.writeFileSync(path.join(f.dir, "coordinator"), "");
  f.coordinator.journal = f.journal("coordinator");
  await assert.rejects(
    f.coordinator.release(f.req, "payer-token"),
    /missing local state/,
  );
  const bad = path.join(f.dir, "bad");
  fs.writeFileSync(bad, '{"fake":true}\n', { mode: 0o600 });
  assert.throws(() => new Journal(bad));
});
test("bounded real HTTP guardians and independent coordinator preserve encrypted end-to-end flow", async (t) => {
  const f = await fixture(t);
  for (let i = 0; i < 3; i++) {
    const token = "fixture-guardian-private-" + String(i).repeat(32),
      g = f.guardians[i];
    const s = await serve(
      (r) => g.release({ ...r, approval: r.approvals[g.id] }),
      { token, fixture: true },
    );
    f.servers.push(s);
    f.calls[g.id] = (r) =>
      request(s.url + "/release", r, { token, fixture: true });
    await assert.rejects(
      request(s.url + "/release", f.req, {
        token: "not-authorized",
        fixture: true,
      }),
      (e) => e.status === 403,
    );
  }
  const token = "fixture-key-service-client-" + "x".repeat(32);
  const service = await serve((r) => f.coordinator.release(r, "payer-token"), {
    token,
    fixture: true,
  });
  f.servers.push(service);
  const release = await request(service.url + "/release", f.req, {
    token,
    fixture: true,
  });
  assert.equal(
    await p.open({
      ...f.packet,
      sender: f.sender.publicKey,
      recipient: f.recipient,
      policy: f.policy,
      release,
    }),
    "HIGHLY PRIVATE fixture 42",
  );
  assert.equal(f.charges(), 1);
  assert.throws(() => serve(() => {}, { token }), /disabled/);
});
