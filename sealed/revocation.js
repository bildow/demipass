"use strict";
// Offline status evaluation. No accepted result is permission to release a key.
const p = require("./crypto"), { verifyEnrollment } = require("./enrollment");
const FORMAT = "conduit-guardian-status-v1", MAX_LIFETIME = 300000;
// Shape only: inspection cannot certify issuer provenance, freshness or trust pins.
function validateCheckpoint(checkpoint) {
  p.fields(checkpoint, ["context_hash", "entries"]);
  if (typeof checkpoint.context_hash !== "string" || !/^[a-f0-9]{64}$/.test(checkpoint.context_hash))
    throw Error("invalid checkpoint context");
  const ids = Object.keys(checkpoint.entries || {});
  p.fields(checkpoint.entries, ids);
  if (ids.length !== 3 || ids.some(id => !/^[a-z][a-z0-9-]{1,40}$/.test(id)))
    throw Error("invalid checkpoint guardians");
  for (const old of Object.values(checkpoint.entries)) {
    p.fields(old, ["serial", "hash", "issued_at", "revoked"]);
    if (!Number.isSafeInteger(old.serial) || old.serial < 1 || typeof old.hash !== "string" ||
        !/^[a-f0-9]{64}$/.test(old.hash) || !Number.isSafeInteger(old.issued_at) || old.issued_at < 0 ||
        typeof old.revoked !== "boolean") throw Error("invalid prior checkpoint");
  }
}
function evaluate({ policy, evidence, trusted, snapshots, previous = null, now = Date.now() }) {
  const encoded = p.canonical({ policy, evidence, trusted, snapshots, previous });
  if (Buffer.byteLength(encoded) > 98304) throw Error("oversize status packet");
  ({ policy, evidence, trusted, snapshots, previous } = JSON.parse(encoded));
  const enrollment = verifyEnrollment({ policy, evidence, trusted, now });
  const context_hash = p.hash({ policy, trusted });
  if (!Array.isArray(snapshots) || snapshots.length !== 3) throw Error("three status snapshots required");
  if (previous !== null) {
    validateCheckpoint(previous);
    if (previous.context_hash !== context_hash) throw Error("trust context changed; separate acceptance required");
    p.fields(previous.entries, policy.guardians.map(g => g.id));
  }
  const entries = {}, revoked = [];
  let expires_at = enrollment.expires_at;
  for (const g of policy.guardians) {
    const rows = snapshots.filter(s => s && s.guardian_id === g.id);
    if (rows.length !== 1) throw Error("missing or duplicate guardian status");
    const s = rows[0], t = trusted.find(t => t.guardian_id === g.id);
    p.fields(s, ["format", "policy_hash", "guardian_id", "issuer_id", "serial", "state", "issued_at", "expires_at", "signature"]);
    if (s.format !== FORMAT || s.policy_hash !== enrollment.policy_hash || s.issuer_id !== t.issuer_id ||
        !Number.isSafeInteger(s.serial) || s.serial < 1 || !["active", "revoked"].includes(s.state))
      throw Error("invalid status binding");
    if (!Number.isSafeInteger(s.issued_at) || !Number.isSafeInteger(s.expires_at) || s.issued_at < 0 ||
        s.issued_at > now || s.expires_at <= now || s.expires_at <= s.issued_at ||
        s.expires_at - s.issued_at > MAX_LIFETIME) throw Error("stale or invalid status lifetime");
    const { signature, ...body } = s;
    if (!p.verify(body, signature, t.issuer_key)) throw Error("invalid status signature");
    const hash = p.hash(s), old = previous && previous.entries[g.id];
    if (previous !== null) {
      if (s.serial < old.serial || s.issued_at < old.issued_at || (s.serial === old.serial && hash !== old.hash))
        throw Error("status rollback or same-serial fork");
    }
    const isRevoked = s.state === "revoked" || Boolean(old && old.revoked);
    entries[g.id] = { serial: s.serial, hash, issued_at: s.issued_at, revoked: isRevoked };
    if (isRevoked) revoked.push(g.id);
    expires_at = Math.min(expires_at, s.expires_at);
  }
  const checkpoint = { context_hash, entries };
  return { verdict: revoked.length ? "hold" : "evidence_current", revoked, expires_at,
    checkpoint, checkpoint_hash: p.hash(checkpoint), live_guardian_release: false };
}
module.exports = { FORMAT, MAX_LIFETIME, validateCheckpoint, evaluate };
