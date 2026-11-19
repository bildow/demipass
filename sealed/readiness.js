"use strict";
// Local, read-only evidence inspection. No network, keys, journal writes or release authority.
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const p = require("./crypto"), { readPrivate } = require("./client");
const { evaluate } = require("./revocation");
const FORMAT = "conduit-readiness-v1";
const ROLES = ["brain", "claude", "codex"];
const LIMITS = [
  "Local configuration is an operator assertion, not independently verified custody.",
  "Distinct keys and domain labels do not prove separate administrators or recovery control.",
  "This inspection neither installs pins nor advances a retained checkpoint.",
  "Fixture results cannot establish production deployment or model receipt/read behavior.",
];
const LIVE_GATES = ["independent_custodian_selection", "live_service_implementation_and_review",
  "live_mcp_release_integration", "installed_source_and_config_proof", "independent_live_acceptance",
  "brain_inbound_policy_and_tests"];
function result(now) {
  return { format: FORMAT, status: "hold", checked_at: now, live_guardian_release: false,
    brain_inbound: { state: "hold", enabled: false, reason: "missing_verified_inbound_policy_and_tests",
      tome_commit: null, server_enforcement: "not_verified" },
    checks: [], participants: [], deployment_blockers: [...LIVE_GATES], limits: [...LIMITS] };
}
function sourceDigest(root = path.resolve(__dirname, "..")) {
  // No Git, shell, environment-dependent inventory or imported applicant code.
  const names = ["index.js", "mcp-server.js", "http-json.js", "services.js", "package.json"];
  const sealed = path.join(root, "sealed"), dir = fs.lstatSync(sealed);
  if (!dir.isDirectory() || dir.isSymbolicLink()) throw Error("unsafe source directory");
  names.push(...fs.readdirSync(sealed).map(n => "sealed/" + n));
  const hashes = names.sort().map(name => {
    const fd = fs.openSync(path.join(root, name), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try {
      const st = fs.fstatSync(fd);
      if (!st.isFile() || st.size > 1024 * 1024) throw Error("unsafe source file");
      return { name, sha256: crypto.createHash("sha256").update(fs.readFileSync(fd)).digest("hex") };
    } finally { fs.closeSync(fd); }
  });
  return p.hash(hashes);
}
function inspect({ config, evidence, actual_source_sha256, now = Date.now() }) {
  if (!Number.isSafeInteger(now) || now < 0) throw Error("invalid inspection clock");
  const out = result(now);
  const check = (id, state, reason) => out.checks.push({ id, state, reason });
  if (config === null) { check("configuration", "missing", "operator_configuration_required"); return out; }
  try {
    const encoded = p.canonical(config);
    if (Buffer.byteLength(encoded) > 98304) throw Error("oversize");
    config = JSON.parse(encoded);
    p.fields(config, ["format", "participants", "source_sha256", "policy", "trusted", "previous"]);
    if (config.format !== FORMAT || !Array.isArray(config.participants) || config.participants.length !== 3) throw Error("shape");
    const roles = new Set(), mailboxes = new Set(), keys = new Set();
    for (const peer of config.participants) {
      p.fields(peer, ["role", "mailbox", "public_key"]);
      if (!ROLES.includes(peer.role) || roles.has(peer.role) ||
          typeof peer.mailbox !== "string" || !/^[a-z][a-z0-9-]{1,79}$/.test(peer.mailbox) || mailboxes.has(peer.mailbox)) throw Error("peer");
      roles.add(peer.role); mailboxes.add(peer.mailbox);
      if (peer.public_key !== null) {
        p.validatePublic(peer.public_key);
        if (peer.public_key.mailbox !== peer.mailbox) throw Error("peer binding");
        for (const key of [peer.public_key.kem, peer.public_key.sign.x]) {
          if (keys.has(key)) throw Error("shared endpoint key"); keys.add(key);
        }
      }
    }
    if (config.source_sha256 !== null && !/^[a-f0-9]{64}$/.test(config.source_sha256)) throw Error("source pin");
    if (!Array.isArray(config.trusted) || (config.policy === null && (config.trusted.length || config.previous !== null))) throw Error("orphan pins");
    if (config.policy !== null) {
      p.policyShape(config.policy);
      for (const g of config.policy.guardians)
        if ([g.publicKey.kem, g.publicKey.sign.x, g.approvalKey.x].some(k => keys.has(k))) throw Error("endpoint reused as guardian");
      for (const issuer of config.trusted)
        if (issuer && issuer.issuer_key && keys.has(issuer.issuer_key.x)) throw Error("endpoint reused as issuer");
    }
  } catch (_) { check("configuration", "invalid", "invalid_operator_configuration"); return out; }
  check("configuration", "valid", "typed_local_configuration");
  out.digest_format = "sha256-canonical-json-v1";
  out.config_canonical_sha256 = p.hash(config);
  out.participants = config.participants.map(peer => ({ role: peer.role, mailbox: peer.mailbox,
    fingerprint: peer.public_key === null ? null : p.keyId(peer.public_key),
    key_state: peer.public_key === null ? "missing" : "locally_pinned_not_ownership_proof" }));
  check("participant_keys", out.participants.every(x => x.fingerprint) ? "valid" : "missing", "brain_claude_codex_each_need_separate_pinned_keys");
  const matched = config.source_sha256 !== null && /^[a-f0-9]{64}$/.test(actual_source_sha256 || "") && config.source_sha256 === actual_source_sha256;
  check("source", matched ? "valid" : config.source_sha256 === null ? "missing" : "invalid", matched ? "local_inventory_matches_pin" : "source_pin_missing_or_mismatch");
  out.source_sha256 = /^[a-f0-9]{64}$/.test(actual_source_sha256 || "") ? actual_source_sha256 : null;
  if (config.policy === null) { check("guardian_evidence", "missing", "custodians_not_configured"); return out; }
  if (evidence === null) { check("guardian_evidence", "missing", "signed_enrollment_and_status_required"); return out; }
  try {
    p.fields(evidence, ["evidence", "snapshots"]);
    const evaluated = evaluate({ policy: config.policy, trusted: config.trusted, previous: config.previous, ...evidence, now });
    out.policy_sha256 = p.hash(config.policy);
    if (evaluated.verdict === "evidence_current") out.evidence_canonical_sha256 = p.hash(evidence);
    out.observed_checkpoint_sha256 = evaluated.checkpoint_hash;
    out.expires_at = evaluated.expires_at;
    check("guardian_evidence", evaluated.verdict === "evidence_current" ? "valid" : "invalid",
      evaluated.verdict === "evidence_current" ? "signed_evidence_current" : "guardian_revoked");
  } catch (_) { check("guardian_evidence", "invalid", "missing_invalid_expired_or_rolled_back_evidence"); }
  if (out.checks.every(c => c.state === "valid"))
    out.status = config.policy.assurance === "fixture" ? "fixture_evidence_current_live_disabled" : "evidence_current_live_disabled";
  return out;
}
function localReadiness(args = {}) {
  // Even an MCP client ignoring JSON schema cannot inject a path, key, time or approval.
  p.fields(args, []);
  const now = Date.now(), configFile = process.env.DEMIPASS_SEALED_READINESS_CONFIG;
  const evidenceFile = process.env.DEMIPASS_SEALED_READINESS_EVIDENCE;
  if (!configFile) return inspect({ config: null, evidence: null, now });
  try {
    if (!path.isAbsolute(configFile) || (evidenceFile && (!path.isAbsolute(evidenceFile) || path.resolve(evidenceFile) === path.resolve(configFile)))) throw Error("paths");
    const config = readPrivate(configFile), evidence = evidenceFile ? readPrivate(evidenceFile) : null;
    return inspect({ config, evidence, actual_source_sha256: sourceDigest(), now });
  } catch (_) {
    const out = result(now);
    out.checks.push({ id: "local_inputs", state: "invalid", reason: "unreadable_unsafe_or_malformed_local_inputs" });
    return out; // Never echo JSON parser details, filesystem paths, credentials or supplied contents.
  }
}
module.exports = { FORMAT, ROLES, sourceDigest, inspect, localReadiness };
