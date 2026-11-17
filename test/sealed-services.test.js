"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  { spawn } = require("node:child_process"),
  { once } = require("node:events");
const { meterFixture } = require("./helpers/sealed-meter"),
  { DemiPassMeter } = require("../sealed/demipass-meter"),
  { request } = require("../sealed/http"),
  { writeNew } = require("../sealed/client"),
  p = require("../sealed/crypto"),
  { makeGrant, approve } = require("../sealed/guardian");
test("DemiPass adapter binds issuer, service, exact 2-DD price, approval, charge and recoverable lookup", async (t) => {
  const f = await meterFixture();
  t.after(f.close);
  const m = new DemiPassMeter(f.config),
    who = await m.identify("fixture-payer-token", {});
  await m.precheck(who, 2);
  assert.equal(await m.lookup("one"), null);
  const charged = await m.charge(who, 2, "one");
  assert.equal(charged.dd, 2);
  assert.equal((await m.lookup("one")).charge_id, charged.charge_id);
  await m.charge(who, 2, "one");
  assert.equal(f.state.charges, 1);
  for (const [key, bad, good] of [
    ["margin", 20, 0],
    ["service", "conduit", "conduit-keys"],
    ["action", "post", "release"],
    ["verifyOk", false, true],
  ]) {
    f.state[key] = bad;
    await assert.rejects(m.identify("fixture-payer-token", {}));
    f.state[key] = good;
  }
  f.state.badLookup = true;
  await assert.rejects(m.lookup("one"), /lookup/);
  f.state.badLookup = false;
  f.state.badReceipt = true;
  await assert.rejects(m.charge(who, 2, "one"), /receipt/);
  f.state.badReceipt = false;
  f.state.wrongToken = true;
  await assert.rejects(m.charge(who, 2, "one"), /receipt/);
  await assert.rejects(m.identify("unknown-token", {}));
  assert.throws(() => new DemiPassMeter({ ...f.config, service: "conduit" }));
  assert.throws(() => request("http://example.com", {}, {}), /HTTPS/);
});
test(
  "four separate fixture processes: lock exclusion, guardian loss, one signed fee, coordinator crash/restart recovery",
  { timeout: 20000 },
  async (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "sealed-process-")),
      children = [];
    const stop = async (c) => {
      if (c.exitCode !== null || c.signalCode !== null) return;
      const done = once(c, "exit");
      c.kill("SIGKILL");
      await done;
    };
    const meter = await meterFixture();
    t.after(async () => {
      for (const c of children) await stop(c);
      await meter.close();
      fs.rmSync(root, { recursive: true, force: true });
    });
    const sender = await p.identity("sender-mailbox"),
      recipient = await p.identity("recipient-mailbox"),
      gids = await Promise.all(
        [0, 1, 2].map((i) => p.identity("guardian-" + i)),
      ),
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
        domains: Object.fromEntries(
          ["host", "admin", "credential", "recovery"].map((k) => [
            k,
            "fixture-" + k + "-" + i,
          ]),
        ),
      })),
    };
    const status = await require("./helpers/sealed-status").statusFixture(policy);
    const feed = path.join(root,"evidence.json"); writeNew(feed,status.packet());
    const admission = {trusted:status.trusted,feed_file:feed,expected_checkpoint:"new"};
    const start = async (name, cfg) => {
      const dir = path.join(root, name);
      if (cfg) {
        fs.mkdirSync(dir, { mode: 0o700 });
        writeNew(path.join(dir, "config.json"), cfg);
      }
      const child = spawn(
        "sh",
        ["-c", 'umask 022; exec sh "$1" "$2"', "fixture-wrapper", path.resolve(__dirname, "../sealed/service.sh"), dir],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      children.push(child);
      let raw = "",
        err = "";
      child.stderr.on("data", (b) => (err += b));
      const ready = await new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(Error("service startup deadline")),
          5000,
        );
        child.once("exit", (code) => {
          clearTimeout(timer);
          reject(Error("startup exit " + code + " " + err));
        });
        child.stdout.on("data", (b) => {
          raw += b;
          if (raw.includes("\n")) {
            clearTimeout(timer);
            try {
              resolve(JSON.parse(raw.split("\n")[0]));
            } catch (e) {
              reject(e);
            }
          }
        });
      });
      assert.equal(fs.statSync(path.join(dir,"lease.lock")).mode & 0o777,0o600);
      return { child, ...ready };
    };
    const common = {
      fixture: true,
      admission,
      policy,
      sender: sender.publicKey,
      recipient: recipient.publicKey,
    };
    const endpoints = {};
    const guards = [];
    for (let i = 0; i < 3; i++) {
      const id = "guardian-" + i,
        token = "private-fixture-guardian-credential-" + i;
      const g = await start(id, {
        ...common,
        role: "guardian",
        id,
        identity: gids[i],
        transport_token: token,
      });
      guards.push(g);
      endpoints[id] = { url: g.url, token };
      assert.equal(g.live_release_enabled, false);
    }
    const coordinatorToken = "private-fixture-coordinator-credential";
    let coordinator = await start("coordinator", {
      ...common,
      role: "coordinator",
      transport_token: coordinatorToken,
      meter: meter.config,
      guardian_endpoints: endpoints,
    });
    await assert.rejects(start("coordinator"), /already owned/);
    const packet = await p.seal({
        sender,
        recipient: recipient.publicKey,
        plaintext: "private real-process output",
        policy,
        fixture: true,
      }),
      grant = makeGrant(packet.envelope, recipient),
      approvals = Object.fromEntries(
        guards.map((g, i) => [
          "guardian-" + i,
          approve(grant, "guardian-" + i, approvers[i]),
        ]),
      );
    const req = {
      request: { ...packet, grant, approvals },
      payer_token: "fixture-payer-token",
    };
    await stop(guards[2].child);
    const out = await request(coordinator.url + "/release", req, {
      token: coordinatorToken,
      fixture: true,
    });
    assert.equal(out.charge.dd, 2);
    assert.equal(meter.state.charges, 1);
    assert.equal(
      await p.open({
        ...packet,
        sender: sender.publicKey,
        recipient,
        policy,
        release: out,
      }),
      "private real-process output",
    );
    // Refresh the signed feed while processes are live. A saved guardian share
    // must now refuse, but a paid coordinator package remains recoverable.
    fs.writeFileSync(feed,JSON.stringify(status.packet(2,true)),{mode:0o600});
    await assert.rejects(request(guards[0].url+"/release",{...req.request,approval:approvals["guardian-0"]},
      {token:endpoints["guardian-0"].token,fixture:true}),{status:409});
    await stop(coordinator.child);
    // Operator retains and reconciles the accepted checkpoint; restart never resets to 'new'.
    const {Journal}=require("../sealed/journal");
    const checkpointJournal=new Journal(path.join(root,"coordinator/status.jsonl"));
    const checkpointHash=p.hash(checkpointJournal.get("checkpoint")); checkpointJournal.close();
    const configFile=path.join(root,"coordinator/config.json");
    const config=JSON.parse(fs.readFileSync(configFile)); config.admission.expected_checkpoint=checkpointHash;
    fs.writeFileSync(configFile,JSON.stringify(config),{mode:0o600});
    coordinator = await start("coordinator");
    const retry = await request(coordinator.url + "/release", req, {
      token: coordinatorToken,
      fixture: true,
    });
    assert.equal(retry.replayed, true);
    assert.deepEqual(retry.responses, out.responses);
    assert.equal(meter.state.charges, 1);
    const nextPacket=await p.seal({sender,recipient:recipient.publicKey,plaintext:"next",policy,fixture:true});
    const nextGrant=makeGrant(nextPacket.envelope,recipient);
    const nextApprovals=Object.fromEntries(policy.guardians.map((g,i)=>[g.id,approve(nextGrant,g.id,approvers[i])]));
    await assert.rejects(request(coordinator.url+"/release",{payer_token:"fixture-payer-token",
      request:{...nextPacket,grant:nextGrant,approvals:nextApprovals}},
      {token:coordinatorToken,fixture:true}),{status:409});
    assert.equal(meter.state.charges,1);
    const journal = fs.readFileSync(
      path.join(root, "coordinator/journal.jsonl"),
      "utf8",
    );
    assert(!journal.includes("private real-process output"));
  },
);
