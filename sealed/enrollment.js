"use strict";
// Offline evidence validation only. This module never authorizes key release.
const p = require("./crypto");
const FORMAT = "conduit-guardian-enrollment-v1";
const MAX_LIFETIME = 24 * 60 * 60 * 1000;
const digest = (x) => typeof x === "string" && /^[a-f0-9]{64}$/.test(x);
function signingKey(key) {
  p.fields(key, ["kty", "crv", "x"]);
  if (key.kty !== "OKP" || key.crv !== "Ed25519") throw Error("invalid issuer key");
  p.bytes(key.x, 32);
}
function verifyEnrollment({ policy, evidence, trusted, now = Date.now() }) {
  // Snapshot caller inputs before validation; no network, filesystem or authority discovery.
  const encoded = p.canonical({ policy, evidence, trusted });
  if (Buffer.byteLength(encoded) > 65536) throw Error("oversize enrollment packet");
  const snapshot = JSON.parse(encoded);
  ({ policy, evidence, trusted } = snapshot);
  p.policyShape(policy);
  if (!Number.isSafeInteger(now) || now < 0) throw Error("invalid clock");
  if (!Array.isArray(evidence) || evidence.length !== 3 ||
      !Array.isArray(trusted) || trusted.length !== 3) throw Error("three enrollments required");
  const policyHash = p.hash(policy), seen = new Set(), issuerIds = new Set(), issuerKeys = new Set();
  const guardianKeys = new Set(policy.guardians.flatMap((g) =>
    [g.publicKey.kem, g.publicKey.sign.x, g.approvalKey.x]));
  for (const g of policy.guardians) {
    for (const label of Object.values(g.domains))
      if (!/^[a-z0-9][a-z0-9.-]{1,119}$/.test(label)) throw Error("noncanonical domain label");
    const matches = trusted.filter((t) => t && t.guardian_id === g.id);
    if (matches.length !== 1) throw Error("missing or duplicate trusted guardian");
    const t = matches[0];
    p.fields(t, ["guardian_id", "issuer_id", "issuer_key", "deployment_sha256"]);
    signingKey(t.issuer_key);
    if (typeof t.issuer_id !== "string" || !/^[a-z][a-z0-9-]{1,79}$/.test(t.issuer_id) ||
        !digest(t.deployment_sha256)) throw Error("invalid trusted pin");
    if (issuerIds.has(t.issuer_id) || issuerKeys.has(t.issuer_key.x) || guardianKeys.has(t.issuer_key.x))
      throw Error("shared or self-issued enrollment authority");
    issuerIds.add(t.issuer_id); issuerKeys.add(t.issuer_key.x);
    const rows = evidence.filter((e) => e && e.guardian_id === g.id);
    if (rows.length !== 1) throw Error("missing or duplicate enrollment evidence");
    const e = rows[0];
    p.fields(e, ["format", "policy_hash", "guardian_id", "guardian_fingerprint", "approval_key_hash",
      "domains", "deployment_sha256", "issued_at", "expires_at", "issuer_id", "signature"]);
    const { signature, ...body } = e;
    if (e.format !== FORMAT || e.policy_hash !== policyHash ||
        e.guardian_fingerprint !== p.keyId(g.publicKey) || e.approval_key_hash !== p.hash(g.approvalKey) ||
        p.canonical(e.domains) !== p.canonical(g.domains) || e.deployment_sha256 !== t.deployment_sha256 ||
        e.issuer_id !== t.issuer_id) throw Error("enrollment binding mismatch");
    if (!Number.isSafeInteger(e.issued_at) || !Number.isSafeInteger(e.expires_at) ||
        e.issued_at < 0 || e.issued_at > now || e.expires_at <= now ||
        e.expires_at <= e.issued_at || e.expires_at - e.issued_at > MAX_LIFETIME)
      throw Error("expired or invalid enrollment lifetime");
    if (!p.verify(body, signature, t.issuer_key)) throw Error("invalid enrollment signature");
    seen.add(g.id);
  }
  return {
    status: "evidence_verified_live_disabled", policy_hash: policyHash,
    guardian_ids: [...seen], checked_at: now,
    expires_at: Math.min(...evidence.map((e) => e.expires_at)),
    live_guardian_release: false,
    limits: ["Issuer pins must be supplied by an independently accepted operator policy.",
      "Signatures and distinct labels do not prove physical or administrative independence.",
      "Revocation, rotation, independent custodian selection and live acceptance remain required."],
  };
}
module.exports = { FORMAT, MAX_LIFETIME, verifyEnrollment };
