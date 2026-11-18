"use strict";
const crypto = require("node:crypto");
const p = require("./crypto");
const { requireGate } = require("./release-gate");

function makeGrant(
  envelope,
  recipient,
  { now = Date.now(), ttl = 120000 } = {},
) {
  if (!Number.isSafeInteger(ttl) || ttl < 1000 || ttl > 300000)
    throw Error("grant TTL out of range");
  const body = {
    purpose: "conduit-key-release-v1",
    request_id: crypto.randomUUID(),
    envelope_hash: p.hash(envelope),
    capsule_hash: envelope.capsule_hash,
    recipient_key: envelope.header.recipient_key,
    policy_hash: envelope.header.policy_hash,
    expires_at: now + ttl,
  };
  return { body, signature: p.sign(body, recipient.signPrivate) };
}
function validateGrant(
  grant,
  envelope,
  recipient,
  now = Date.now(),
  allowExpired = false,
) {
  p.fields(grant, ["body", "signature"]);
  const b = grant.body;
  p.fields(b, [
    "purpose",
    "request_id",
    "envelope_hash",
    "capsule_hash",
    "recipient_key",
    "policy_hash",
    "expires_at",
  ]);
  if (
    b.purpose !== "conduit-key-release-v1" ||
    !/^[a-f0-9-]{36}$/.test(b.request_id) ||
    b.envelope_hash !== p.hash(envelope) ||
    b.capsule_hash !== envelope.capsule_hash ||
    b.recipient_key !== p.keyId(recipient) ||
    b.policy_hash !== envelope.header.policy_hash
  )
    throw Error("invalid grant binding");
  if (
    !Number.isSafeInteger(b.expires_at) ||
    (!allowExpired && b.expires_at <= now) ||
    b.expires_at > now + 300000
  )
    throw Error("grant expired or too long");
  if (!p.verify(b, grant.signature, recipient.sign))
    throw Error("recipient proof missing");
  return p.hash(b);
}
function approve(grant, guardianId, approvalIdentity) {
  const body = {
    purpose: "conduit-guardian-approval-v1",
    guardian: guardianId,
    grant_hash: p.hash(grant.body),
    expires_at: grant.body.expires_at,
  };
  return { body, signature: p.sign(body, approvalIdentity.signPrivate) };
}
function checkApproval(approval, guardian, grant, grantHash) {
  p.fields(approval, ["body", "signature"]);
  p.fields(approval.body, ["purpose", "guardian", "grant_hash", "expires_at"]);
  const b = approval.body;
  if (
    b.purpose !== "conduit-guardian-approval-v1" ||
    b.guardian !== guardian.id ||
    b.grant_hash !== grantHash ||
    b.expires_at !== grant.body.expires_at ||
    !p.verify(b, approval.signature, guardian.approvalKey)
  )
    throw Error("independent guardian approval invalid");
}

class Guardian {
  constructor({
    id,
    identity,
    policy,
    sender,
    recipient,
    journal,
    fixture = false,
    admission,
    now = Date.now,
  }) {
    p.policyForUse(policy, { fixture });
    this.policy = structuredClone(policy);
    this.checkStatus = requireGate(admission, this.policy);
    this.id = id;
    this.identity = identity;
    this.sender = sender;
    this.recipient = recipient;
    this.journal = journal;
    this.now = now;
    this.guardian = policy.guardians.find((g) => g.id === id);
    if (
      !this.guardian ||
      p.keyId(this.guardian.publicKey) !== p.keyId(identity.publicKey)
    )
      throw Error("guardian identity mismatch");
  }
  async release({ envelope, capsule, grant, approval }) {
    const header = p.validateEnvelope(envelope, this.sender, this.recipient);
    if (header.mode !== "guarded" || header.policy_hash !== p.hash(this.policy))
      throw Error("guardian policy mismatch");
    const context = p.validateCapsule(envelope, capsule),
      gh = validateGrant(grant, envelope, this.recipient, this.now());
    checkApproval(approval, this.guardian, grant, gh);
    this.checkStatus();
    validateGrant(grant, envelope, this.recipient, this.now());
    // A nonce is bound to one immutable request; retries return the saved encrypted response.
    const key = "guardian:" + this.id + ":" + grant.body.request_id,
      old = this.journal.get(key);
    if (old) {
      if (old.grant_hash !== gh)
        throw Error("replayed nonce for different grant");
      return old.response;
    }
    const candidates = capsule.shares.filter((x) => x.guardian === this.id);
    if (candidates.length !== 1)
      throw Error("guardian share missing or duplicated");
    const fragment = await p.unwrap(this.identity, candidates[0].box, {
      context,
      guardian: this.id,
      role: "guardian-share",
    });
    try {
      if (fragment.length !== 33) throw Error("invalid share length");
      const body = {
        guardian: this.id,
        grant_hash: gh,
        envelope_hash: p.hash(envelope),
        capsule_hash: envelope.capsule_hash,
        recipient_key: header.recipient_key,
        policy_hash: header.policy_hash,
        share: await p.wrap(this.recipient, fragment, {
          context,
          guardian: this.id,
          grant: gh,
          role: "released-share",
        }),
      };
      const response = {
        body,
        signature: p.sign(body, this.identity.signPrivate),
      };
      // Revocation or expiry during crypto must prevent disclosure, including a raced retry.
      this.checkStatus();
      validateGrant(grant, envelope, this.recipient, this.now());
      // Compare again after crypto awaits; one in-process request may have completed meanwhile.
      const raced = this.journal.get(key);
      if (raced) {
        if (raced.grant_hash !== gh)
          throw Error("replayed nonce for different grant");
        return raced.response;
      }
      validateGrant(grant, envelope, this.recipient, this.now());
      this.journal.set(key, { grant_hash: gh, response });
      this.checkStatus();
      validateGrant(grant, envelope, this.recipient, this.now());
      return response;
    } finally {
      fragment.fill(0);
    }
  }
}

function validResponse(r, g, grant, envelope) {
  if (!r || !r.body || !p.verify(r.body, r.signature, g.publicKey.sign))
    return false;
  try {
    p.fields(r.body, [
      "guardian",
      "grant_hash",
      "envelope_hash",
      "capsule_hash",
      "recipient_key",
      "policy_hash",
      "share",
    ]);
    p.fields(r.body.share, ["enc", "ct"]);
    p.bytes(r.body.share.enc, 32);
    p.bytes(r.body.share.ct, 49);
  } catch {
    return false;
  }
  const b = r.body;
  return (
    b.guardian === g.id &&
    b.grant_hash === p.hash(grant.body) &&
    b.envelope_hash === p.hash(envelope) &&
    b.capsule_hash === envelope.capsule_hash &&
    b.recipient_key === envelope.header.recipient_key &&
    b.policy_hash === envelope.header.policy_hash
  );
}

class Coordinator {
  constructor({
    policy,
    sender,
    recipient,
    journal,
    meter,
    guardians,
    fixture = false,
    admission,
    now = Date.now,
  }) {
    p.policyForUse(policy, { fixture });
    this.policy = structuredClone(policy);
    this.checkStatus = requireGate(admission, this.policy);
    this.sender = sender;
    this.recipient = recipient;
    this.journal = journal;
    this.meter = meter;
    this.guardians = guardians;
    this.now = now;
    this.locks = new Map();
  }
  async authorize(request, token, {dispute = false} = {}) {
    const { envelope, capsule, grant } = request;
    const h = p.validateEnvelope(envelope, this.sender, this.recipient);
    p.validateCapsule(envelope, capsule);
    if (h.mode !== "guarded" || h.policy_hash !== p.hash(this.policy))
      throw Error("coordinator policy mismatch");
    // Authenticate every request; payment identity never substitutes for recipient proof of possession.
    if (
      !grant ||
      !grant.body ||
      !p.verify(grant.body, grant.signature, this.recipient.sign)
    )
      throw Error("recipient proof missing");
    const who = await this.meter[dispute ? "identifyDispute" : "identify"](token, {
      envelope_hash: p.hash(envelope),
      recipient_key: h.recipient_key,
      policy_hash: h.policy_hash,
    });
    if (
      !who ||
      typeof who.wallet !== "string" ||
      typeof who.token_id !== "string"
    )
      throw Error("invalid payer");
    // One fee per exact envelope/recipient/policy grant, even if clients invent fresh request IDs.
    const key =
      "release:" +
      p.hash({
        envelope: p.hash(envelope),
        recipient: h.recipient_key,
        policy: h.policy_hash,
      });
    return {key, who};
  }
  async release(request, token) {
    const {key, who} = await this.authorize(request, token);
    return this.exclusive(key, () => this._release(key, request, who));
  }
  async exclusive(key, operation) {
    const previous = this.locks.get(key) || Promise.resolve();
    let unlock;
    const held = new Promise((r) => (unlock = r));
    const tail = previous.then(() => held);
    this.locks.set(key, tail);
    await previous;
    try {
      return await operation();
    } finally {
      unlock();
      if (this.locks.get(key) === tail) this.locks.delete(key);
    }
  }
  // A signed complaint is a durable request for review, NOT a refund or proof
  // of faulty ciphertext. Identity is verified, but no price lookup, payment
  // precheck, debit or share request is made.
  async dispute(request, token, complaint) {
    const {key, who} = await this.authorize(request, token, {dispute: true});
    p.fields(complaint, ["body", "signature"]);
    p.fields(complaint.body, ["version", "type", "envelope_hash", "grant_hash", "reason"]);
    const body = complaint.body;
    if (body.version !== 1 || body.type !== "conduit-release-dispute" ||
        !["decryption_failed", "package_unavailable", "billing_mismatch"].includes(body.reason) ||
        body.envelope_hash !== p.hash(request.envelope) ||
        body.grant_hash !== p.hash(request.grant.body) ||
        !p.verify(body, complaint.signature, this.recipient.sign))
      throw Error("invalid signed dispute");
    return this.exclusive(key, () => {
      const record = this.journal.get(key);
      if (!record || record.status !== "paid" || record.payer !== who.wallet ||
          record.grant_hash !== body.grant_hash)
        throw Error("paid original grant required; uncertain payment needs reconciliation");
      validateGrant(request.grant, request.envelope, this.recipient, this.now(), true);
      const disputeKey = "dispute:" + p.hash({key, complaint});
      const old = this.journal.get(disputeKey);
      if (old) return {...old, replayed:true};
      const at = this.now();
      if (!Number.isSafeInteger(at) || at < 0) throw Error("invalid dispute clock");
      const row = {dispute_id:disputeKey, charge_id:record.charge.charge_id,
        complaint, at, status:"manual_review_required", refund:"not_issued"};
      this.journal.set(disputeKey,row);
      return {...row, replayed:false};
    });
  }
  async _release(key, request, who) {
    const { envelope, capsule, grant } = request;
    let record = this.journal.get(key);
    if (record && record.payer !== who.wallet)
      throw Error("release belongs to another payer");
    const gh = validateGrant(
      grant,
      envelope,
      this.recipient,
      this.now(),
      Boolean(record),
    );
    if (record && record.status === "paid")
      return { ...record.package, charge: record.charge, replayed: true };
    if (record && record.grant_hash !== gh)
      throw Error("resume the original prepared grant");
    if (!record) {
      if (await this.meter.lookup(key))
        throw Error(
          "paid release missing local state: reconcile, do not reconstruct",
        );
      validateGrant(grant, envelope, this.recipient, this.now());
      this.checkStatus();
      await this.meter.precheck(who, 2);
      this.checkStatus();
      const responses = [];
      // All RPCs have deadlines in the HTTP adapter; unavailable guardians cannot stall forever.
      const results = await Promise.allSettled(
        this.policy.guardians.map((g) =>
          Promise.resolve().then(() => {
            if (!this.guardians[g.id]) throw Error("guardian unavailable");
            return this.guardians[g.id](request);
          }),
        ),
      );
      results.forEach((r, i) => {
        const g = this.policy.guardians[i];
        if (
          r.status === "fulfilled" &&
          validResponse(r.value, g, grant, envelope)
        )
          responses.push(r.value);
      });
      if (responses.length < this.policy.threshold)
        throw Error("quorum unavailable: nothing charged");
      this.checkStatus();
      validateGrant(grant, envelope, this.recipient, this.now());
      record = {
        status: "prepared",
        payer: who.wallet,
        grant_hash: gh,
        package: {
          envelope_hash: p.hash(envelope),
          grant_hash: gh,
          // Keep all three when available. A signature authenticates the
          // guardian, not its hidden share; only the recipient can try pairs.
          responses,
        },
      };
      this.journal.set(key, record); // fsync encrypted fulfillment BEFORE payment
    }
    // After an uncertain response, LOOK UP this immutable charge key before attempting another charge.
    let charge = await this.meter.lookup(key);
    if (!charge) {
      validateGrant(grant, envelope, this.recipient, this.now());
      this.checkStatus();
      await this.meter.precheck(who, 2);
      this.checkStatus();
      validateGrant(grant, envelope, this.recipient, this.now());
      charge = await this.meter.charge(who, 2, key);
    }
    if (
      !charge ||
      charge.wallet !== who.wallet ||
      charge.action !== "release" ||
      charge.cost_dd !== 2 ||
      charge.dd !== 2 ||
      typeof charge.charge_id !== "string" ||
      !charge.charge_id
    )
      throw Error("charge mismatch: release held");
    const paid = { ...record, status: "paid", charge };
    this.journal.set(key, paid);
    return { ...paid.package, charge, replayed: false };
  }
}
module.exports = {
  Guardian,
  Coordinator,
  makeGrant,
  validateGrant,
  approve,
  checkApproval,
  validResponse,
};
