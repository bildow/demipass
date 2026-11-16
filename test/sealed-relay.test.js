"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const { Client } = require("../sealed/client");
test(
  "real SDK ciphertext through candidate relay, delayed key capsule, billing replay, and forwarding refusals",
  { skip: !process.env.CONDUIT_TEST_SOURCE },
  async (t) => {
    const { relay } = require(
      path.resolve(process.env.CONDUIT_TEST_SOURCE, "test/harness.js"),
    );
    const A = "astra-11111111-1111-4111-8111-111111111111",
      B = "sol-22222222-2222-4222-8222-222222222222",
      C = "opus-33333333-3333-4333-8333-333333333333";
    const r = await relay({
      A: {
        wallet: "a",
        token_id: "a",
        scopes: ["post", "read", "forward", "ack"],
      },
      B: {
        wallet: "b",
        token_id: "b",
        scopes: ["post", "read", "forward", "ack"],
      },
    });
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "sealed-relay-"));
    t.after(async () => {
      await r.close();
      fs.rmSync(root, { recursive: true, force: true });
    });
    await r.pane("A", A);
    await r.pane("B", B);
    await r.pane("B", C);
    const a = new Client({ directory: path.join(root, "a"), mailbox: A }),
      b = new Client({ directory: path.join(root, "b"), mailbox: B }),
      ap = await a.initialize(),
      bp = await b.initialize();
    const ready = await a.prepare({
        recipient: bp.public_key,
        plaintext: "END TO END secret 83",
      }),
      wire = a.transport(ready.id);
    assert(
      (
        await r.api("/readme?format=json", { address: A })
      ).data.payload_types.includes(wire.payload_type),
    );
    const sent = await r.api("/messages", { address: A, body: wire });
    assert.equal(sent.status, 201, JSON.stringify(sent));
    const charges = r.charges();
    assert.equal(
      (await r.api("/messages", { address: A, body: wire })).data.replayed,
      true,
    );
    assert.equal(r.charges(), charges);
    const altered = JSON.parse(wire.body);
    altered.envelope.header.public_text = "substitution";
    assert.equal(
      (
        await r.api("/messages", {
          address: A,
          body: { ...wire, body: JSON.stringify(altered) },
        })
      ).status,
      409,
    );
    const history = await r.api("/history", { token: "B", address: B });
    assert.equal(history.data.messages[0].body, null);
    const inbox = await r.api("/inbox", { token: "B", address: B });
    const message = inbox.data.messages[0];
    assert.equal(message.payload_type, wire.payload_type);
    const packet = JSON.parse(message.body);
    await assert.rejects(b.open({ ...packet, sender: ap.public_key }));
    assert.equal(
      await b.open({
        ...packet,
        capsule: a.capsule(ready.id),
        sender: ap.public_key,
      }),
      "END TO END secret 83",
    );
    const before = r.charges();
    assert.equal(
      (
        await r.api("/messages/" + sent.data.msg_id + "/forward", {
          token: "B",
          address: B,
          body: { to: C },
        })
      ).status,
      409,
    );
    assert.equal(r.charges(), before);
    for (const patch of [
      { to: null, thread: sent.data.thread },
      { subject: "owner" },
      { to: C },
      { payload_type: "future-sealed-v9" },
    ])
      assert.equal(
        (await r.api("/messages", { address: A, body: { ...wire, ...patch } }))
          .status,
        400,
      );
    assert(
      !fs
        .readFileSync(r.store.logPath, "utf8")
        .includes("END TO END secret 83"),
    );
    const { Store } = require(
      path.resolve(process.env.CONDUIT_TEST_SOURCE, "lib/store.js"),
    );
    const replay = new Store(r.store.dir, { minFreeBytes: 0 });
    assert.equal(
      replay.messages.get(sent.data.msg_id).payload_type,
      wire.payload_type,
    );
    fs.closeSync(replay.fd);
  },
);
