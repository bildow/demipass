"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const p = require("../sealed/crypto"), { FORMAT, MAX_LIFETIME, verifyEnrollment } = require("../sealed/enrollment");
const clone = (x) => JSON.parse(JSON.stringify(x));
async function fixture() {
  const guardians = await Promise.all([0, 1, 2].map((i) => p.identity("guardian-" + i)));
  const approvers = await Promise.all([0, 1, 2].map((i) => p.identity("approval-" + i)));
  const issuers = await Promise.all([0, 1, 2].map((i) => p.identity("issuer-" + i)));
  const policy = { version: 1, epoch: 1, threshold: 2, assurance: "reviewed",
    guardians: guardians.map((g, i) => ({ id: "guardian-" + i, publicKey: g.publicKey,
      approvalKey: approvers[i].publicKey.sign, domains: { host: "host-" + i, admin: "admin-" + i,
        credential: "credential-" + i, recovery: "recovery-" + i } })) };
  const now = 1800000000000;
  const trusted = issuers.map((issuer, i) => ({ guardian_id: "guardian-" + i,
    issuer_id: "issuer-" + i, issuer_key: issuer.publicKey.sign, deployment_sha256: p.hash({ deployment: i }) }));
  const evidence = policy.guardians.map((g, i) => ({ format: FORMAT, policy_hash: p.hash(policy),
    guardian_id: g.id, guardian_fingerprint: p.keyId(g.publicKey), approval_key_hash: p.hash(g.approvalKey),
    domains: g.domains, deployment_sha256: trusted[i].deployment_sha256,
    issued_at: now - 100, expires_at: now + 60000, issuer_id: trusted[i].issuer_id }));
  const input = { policy, trusted, evidence, now };
  function resign(x = input) {
    x.evidence.forEach((e, i) => { delete e.signature; e.signature = p.sign(e, issuers[i].signPrivate); });
  }
  resign();
  return { input, issuers, guardians, resign };
}
test("three pinned signed fixture attestations validate offline but never enable release", async () => {
  const { input } = await fixture();
  const original = clone(input), result = verifyEnrollment(input);
  assert.equal(result.status, "evidence_verified_live_disabled");
  assert.equal(result.live_guardian_release, false);
  assert.equal(result.guardian_ids.length, 3);
  assert.equal(result.policy_hash, p.hash(input.policy));
  assert.equal(result.expires_at, input.now + 60000);
  assert.deepEqual(input, original);
  assert.throws(() => p.policyForUse(input.policy), /live guardian release disabled/);
  assert.throws(() => p.policyForUse(input.policy, { fixture: true }), /disabled/);
});
test("enrollment refuses missing, stale, altered, self-issued and cross-policy evidence", async (t) => {
  const { input, guardians, resign } = await fixture();
  const cases = {
    "missing evidence": (x) => x.evidence.pop(),
    "duplicate guardian": (x) => { x.evidence[1] = clone(x.evidence[0]); },
    "missing trust": (x) => x.trusted.pop(),
    "duplicate trust": (x) => { x.trusted[1] = clone(x.trusted[0]); },
    "unsigned evidence": (x) => { delete x.evidence[0].signature; },
    "altered signature": (x) => { x.evidence[0].signature = "A".repeat(86); },
    "changed policy epoch": (x) => { x.policy.epoch++; },
    "wrong deployment pin": (x) => { x.trusted[0].deployment_sha256 = "0".repeat(64); },
    "extra field": (x) => { x.evidence[0].approved = true; },
    "shared issuer id": (x) => { x.trusted[1].issuer_id = x.trusted[0].issuer_id; },
    "shared issuer key": (x) => { x.trusted[1].issuer_key = x.trusted[0].issuer_key; },
    "self issuer": (x) => { x.trusted[0].issuer_key = guardians[0].publicKey.sign; },
    "expired signed row": (x) => { x.evidence[0].expires_at = x.now; resign(x); },
    "future signed row": (x) => { x.evidence[0].issued_at = x.now + 1; resign(x); },
    "overlong signed lifetime": (x) => { x.evidence[0].expires_at = x.now + MAX_LIFETIME; resign(x); },
    "wrong signed domain": (x) => { x.evidence[0].domains.host = "different-host"; resign(x); },
    "wrong signed key": (x) => { x.evidence[0].guardian_fingerprint = "0".repeat(64); resign(x); },
    "wrong signed approval key": (x) => { x.evidence[0].approval_key_hash = "0".repeat(64); resign(x); },
    "noncanonical domain": (x) => { x.policy.guardians[1].domains.admin = "ADMIN-0"; },
    "invalid clock": (x) => { x.now = NaN; },
    "non-object row": (x) => { x.evidence[0] = null; },
  };
  for (const [name, mutate] of Object.entries(cases)) await t.test(name, () => {
    const x = clone(input); mutate(x); assert.throws(() => verifyEnrollment(x));
  });
});
