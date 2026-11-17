"use strict";
// Local fixture adapter for the production enforcement boundary. Never live authority.
const p = require("./crypto"), { evaluate, validateCheckpoint } = require("./revocation");
const state = new WeakMap();
class ReleaseGate {
  constructor({ policy, trusted, journal, feed, expected_checkpoint, fixture = false, now = Date.now }) {
    p.policyForUse(policy, { fixture });
    if (typeof feed !== "function" || typeof now !== "function" ||
        (expected_checkpoint !== "new" && (typeof expected_checkpoint !== "string" ||
         !/^[a-f0-9]{64}$/.test(expected_checkpoint)))) throw Error("release gate configuration required");
    const pins = JSON.parse(p.canonical({ policy, trusted }));
    const prior = journal.get("checkpoint");
    if (prior !== undefined) validateCheckpoint(prior);
    const actual = prior === undefined ? "new" : p.hash(prior);
    if (actual !== expected_checkpoint) throw Error("release checkpoint requires reconciliation");
    state.set(this, { ...pins, journal, feed, now, expected: actual, failed: false });
  }
  assertPolicy(policy) {
    const s = state.get(this);
    if (!s || p.hash(s.policy) !== p.hash(policy)) throw Error("release gate policy mismatch");
  }
  check() {
    const s = state.get(this);
    if (s.failed) throw Error("release gate persistence uncertain; restart and reconcile");
    const packet = s.feed();
    // Feed cannot override pins, policy, prior state or checking time.
    p.fields(packet, ["evidence", "snapshots"]);
    const prior = s.journal.get("checkpoint");
    if (prior !== undefined) validateCheckpoint(prior);
    const actual = prior === undefined ? "new" : p.hash(prior);
    if (actual !== s.expected) throw Error("release checkpoint changed");
    const checkedAt = s.now();
    const result = evaluate({ policy: s.policy, trusted: s.trusted, ...packet,
      previous: prior === undefined ? null : prior, now: checkedAt });
    if (result.checkpoint_hash !== actual) {
      try { s.journal.set("checkpoint", result.checkpoint); }
      catch (e) { s.failed = true; throw e; }
      s.expected = result.checkpoint_hash;
    }
    const completedAt = s.now();
    if (!Number.isSafeInteger(completedAt) || completedAt < checkedAt || completedAt >= result.expires_at)
      throw Error("status expired or clock changed during persistence");
    // Revocations must be durable even though they deny release.
    if (result.verdict !== "evidence_current") throw Error("guardian status holds release");
    return { checkpoint_hash: result.checkpoint_hash, expires_at: result.expires_at,
      live_guardian_release: false };
  }
}
function requireGate(gate, policy) {
  if (!(gate instanceof ReleaseGate) || !state.has(gate)) throw Error("verified release gate required");
  ReleaseGate.prototype.assertPolicy.call(gate, policy);
  return () => ReleaseGate.prototype.check.call(gate);
}
module.exports = { ReleaseGate, requireGate };
