"use strict";
// Versioned application protocol over maintained primitives. No private key leaves an endpoint.
const c = require("node:crypto");
const { CipherSuite, KemId, KdfId, AeadId } = require("hpke-js");
const { split, combine } = require("shamir-secret-sharing");
const suite = new CipherSuite({
  kem: KemId.DhkemX25519HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Aes256Gcm,
});
const FORMAT = "conduit-sealed-v1";
const MAX_PRIVATE = 24576;
const b64 = (x) => Buffer.from(x).toString("base64url");
function bytes(s, length) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s))
    throw Error("invalid encoding");
  const b = Buffer.from(s, "base64url");
  if (b64(b) !== s || (length !== undefined && b.length !== length))
    throw Error("invalid encoded length");
  return b;
}
function fields(x, names) {
  if (
    !x ||
    typeof x !== "object" ||
    Array.isArray(x) ||
    Object.keys(x).sort().join("|") !== names.slice().sort().join("|")
  )
    throw Error("invalid object fields");
}
function canonical(x) {
  if (x === null || typeof x === "boolean" || typeof x === "string")
    return JSON.stringify(x);
  if (typeof x === "number" && Number.isSafeInteger(x)) return String(x);
  if (Array.isArray(x)) return "[" + x.map(canonical).join(",") + "]";
  if (
    x &&
    typeof x === "object" &&
    Object.getPrototypeOf(x) === Object.prototype
  )
    return (
      "{" +
      Object.keys(x)
        .sort()
        .map((k) => JSON.stringify(k) + ":" + canonical(x[k]))
        .join(",") +
      "}"
    );
  throw Error("noncanonical value");
}
const data = (x) => Buffer.from(canonical(x));
const hash = (x) => c.createHash("sha256").update(data(x)).digest("hex");
const keyId = (pub) => hash(pub);
function sign(x, privateKey) {
  return b64(
    c.sign(
      null,
      data(x),
      c.createPrivateKey({ key: privateKey, format: "jwk" }),
    ),
  );
}
function verify(x, sig, publicKey) {
  try {
    return c.verify(
      null,
      data(x),
      c.createPublicKey({ key: publicKey, format: "jwk" }),
      bytes(sig, 64),
    );
  } catch {
    return false;
  }
}
async function identity(mailbox) {
  if (typeof mailbox !== "string" || !/^[a-z][a-z0-9-]{1,79}$/.test(mailbox))
    throw Error("invalid mailbox");
  const kp = await suite.kem.generateKeyPair(),
    signing = c.generateKeyPairSync("ed25519");
  const publicKey = {
    mailbox,
    kem: b64(await suite.kem.serializePublicKey(kp.publicKey)),
    sign: signing.publicKey.export({ format: "jwk" }),
  };
  return {
    publicKey,
    kemPrivate: b64(await suite.kem.serializePrivateKey(kp.privateKey)),
    signPrivate: signing.privateKey.export({ format: "jwk" }),
  };
}
function validatePublic(pub) {
  fields(pub, ["mailbox", "kem", "sign"]);
  if (!/^[a-z][a-z0-9-]{1,79}$/.test(pub.mailbox))
    throw Error("invalid mailbox");
  bytes(pub.kem, 32);
  fields(pub.sign, ["crv", "x", "kty"]);
  if (pub.sign.kty !== "OKP" || pub.sign.crv !== "Ed25519")
    throw Error("invalid signing key");
  bytes(pub.sign.x, 32);
}
async function wrap(pub, plain, context) {
  const result = await suite.seal(
    {
      recipientPublicKey: await suite.kem.deserializePublicKey(
        bytes(pub.kem, 32),
      ),
      info: data({ format: FORMAT, context }),
    },
    plain,
    data(context),
  );
  return { enc: b64(result.enc), ct: b64(result.ct) };
}
async function unwrap(id, box, context) {
  fields(box, ["enc", "ct"]);
  return Buffer.from(
    await suite.open(
      {
        recipientKey: await suite.kem.deserializePrivateKey(
          bytes(id.kemPrivate, 32),
        ),
        enc: bytes(box.enc, 32),
        info: data({ format: FORMAT, context }),
      },
      bytes(box.ct),
      data(context),
    ),
  );
}
function encrypt(key, plain, aad) {
  const iv = c.randomBytes(12),
    cipher = c.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(data(aad));
  return {
    iv: b64(iv),
    ct: b64(
      Buffer.concat([
        cipher.update(plain),
        cipher.final(),
        cipher.getAuthTag(),
      ]),
    ),
  };
}
function decrypt(key, box, aad) {
  fields(box, ["iv", "ct"]);
  const raw = bytes(box.ct);
  if (raw.length < 16) throw Error("short ciphertext");
  const d = c.createDecipheriv("aes-256-gcm", key, bytes(box.iv, 12));
  d.setAAD(data(aad));
  d.setAuthTag(raw.subarray(-16));
  return Buffer.concat([d.update(raw.subarray(0, -16)), d.final()]);
}
function policyShape(policy) {
  fields(policy, ["version", "epoch", "threshold", "guardians", "assurance"]);
  if (
    policy.version !== 1 ||
    !Number.isSafeInteger(policy.epoch) ||
    policy.epoch < 1 ||
    policy.threshold !== 2 ||
    !Array.isArray(policy.guardians) ||
    policy.guardians.length !== 3
  )
    throw Error("requires version 1, 2-of-3 policy");
  if (!["fixture", "reviewed"].includes(policy.assurance))
    throw Error("unknown assurance");
  const allKeys = new Set();
  for (const g of policy.guardians) {
    fields(g, ["id", "publicKey", "approvalKey", "domains"]);
    validatePublic(g.publicKey);
    fields(g.domains, ["host", "admin", "credential", "recovery"]);
    if (typeof g.id !== "string" || !/^[a-z][a-z0-9-]{1,40}$/.test(g.id))
      throw Error("invalid guardian id");
    fields(g.approvalKey, ["kty", "crv", "x"]);
    if (g.approvalKey.kty !== "OKP" || g.approvalKey.crv !== "Ed25519")
      throw Error("invalid approval key");
    bytes(g.approvalKey.x, 32);
    for (const k of [g.publicKey.kem, g.publicKey.sign.x, g.approvalKey.x]) {
      if (allKeys.has(k)) throw Error("shared guardian key");
      allKeys.add(k);
    }
    for (const v of Object.values(g.domains))
      if (typeof v !== "string" || v.length < 2 || v.length > 120)
        throw Error("missing failure domain");
  }
  for (const getter of [
    (g) => g.id,
    ...["host", "admin", "credential", "recovery"].map(
      (k) => (g) => g.domains[k],
    ),
  ])
    if (new Set(policy.guardians.map(getter)).size !== 3)
      throw Error("shared failure domain or guardian");
  return policy;
}
function policyForUse(policy, { fixture = false } = {}) {
  policyShape(policy);
  // Labels or a self-asserted "reviewed" flag are NEVER a production enrollment verifier.
  if (!fixture || policy.assurance !== "fixture")
    throw Error(
      "live guardian release disabled: independent enrollment verifier required",
    );
  return policy;
}
function validateEnvelope(envelope, sender, recipient) {
  if (Buffer.byteLength(JSON.stringify(envelope)) > 48000)
    throw Error("oversize envelope");
  validatePublic(sender);
  validatePublic(recipient);
  fields(envelope, [
    "format",
    "header",
    "payload",
    "capsule_hash",
    "signature",
  ]);
  const h = envelope.header;
  fields(h, [
    "id",
    "sender",
    "recipient",
    "sender_key",
    "recipient_key",
    "epoch",
    "policy_hash",
    "mode",
    "created_at",
    "public_text",
  ]);
  if (
    envelope.format !== FORMAT ||
    !["direct", "guarded"].includes(h.mode) ||
    !Number.isSafeInteger(h.created_at) ||
    !Number.isSafeInteger(h.epoch) ||
    h.epoch < 1 ||
    !/^[0-9a-f-]{36}$/.test(h.id) ||
    typeof h.public_text !== "string" ||
    Buffer.byteLength(h.public_text) > 1024 ||
    !/^[a-f0-9]{64}$/.test(envelope.capsule_hash)
  )
    throw Error("invalid envelope");
  if (
    h.sender !== sender.mailbox ||
    h.recipient !== recipient.mailbox ||
    h.sender_key !== keyId(sender) ||
    h.recipient_key !== keyId(recipient)
  )
    throw Error("key or mailbox substitution");
  if (
    h.mode === "direct"
      ? h.policy_hash !== null || h.epoch !== 1
      : !/^[a-f0-9]{64}$/.test(h.policy_hash)
  )
    throw Error("invalid policy binding");
  fields(envelope.payload, ["iv", "ct"]);
  bytes(envelope.payload.iv, 12);
  const ct = bytes(envelope.payload.ct);
  if (ct.length < 16 || ct.length > MAX_PRIVATE + 16)
    throw Error("invalid payload length");
  const { signature, ...unsigned } = envelope;
  if (!verify(unsigned, signature, sender.sign))
    throw Error("invalid sender signature");
  return h;
}
function validateCapsule(envelope, capsule) {
  if (Buffer.byteLength(JSON.stringify(capsule)) > 8192)
    throw Error("oversize capsule");
  fields(capsule, ["format", "context", "box", "shares"]);
  if (
    capsule.format !== FORMAT ||
    hash(capsule) !== envelope.capsule_hash ||
    capsule.context !==
      hash({ header: envelope.header, payload: envelope.payload })
  )
    throw Error("capsule mismatch");
  if (
    !Array.isArray(capsule.shares) ||
    capsule.shares.length !== (envelope.header.mode === "guarded" ? 3 : 0)
  )
    throw Error("invalid shares");
  if (envelope.header.mode === "direct") {
    fields(capsule.box, ["enc", "ct"]);
    bytes(capsule.box.enc, 32);
    bytes(capsule.box.ct, 48);
  } else {
    fields(capsule.box, ["iv", "ct"]);
    bytes(capsule.box.iv, 12);
    if (bytes(capsule.box.ct).length > 1024) throw Error("oversize gate box");
    const seen = new Set();
    for (const share of capsule.shares) {
      fields(share, ["guardian", "box"]);
      if (typeof share.guardian !== "string" || seen.has(share.guardian))
        throw Error("repeated guardian share");
      seen.add(share.guardian);
      fields(share.box, ["enc", "ct"]);
      bytes(share.box.enc, 32);
      bytes(share.box.ct, 49);
    }
  }
  return capsule.context;
}
async function seal({
  sender,
  recipient,
  plaintext,
  publicText = "",
  policy = null,
  fixture = false,
}) {
  validatePublic(sender.publicKey);
  validatePublic(recipient);
  if (
    typeof plaintext !== "string" ||
    Buffer.byteLength(plaintext) > MAX_PRIVATE
  )
    throw Error("private content must be a string of at most 24576 bytes");
  if (typeof publicText !== "string" || Buffer.byteLength(publicText) > 1024)
    throw Error("public text exceeds 1024 bytes");
  if (policy) policyForUse(policy, { fixture });
  const h = {
    id: c.randomUUID(),
    sender: sender.publicKey.mailbox,
    recipient: recipient.mailbox,
    sender_key: keyId(sender.publicKey),
    recipient_key: keyId(recipient),
    epoch: policy ? policy.epoch : 1,
    policy_hash: policy ? hash(policy) : null,
    mode: policy ? "guarded" : "direct",
    created_at: Date.now(),
    public_text: publicText,
  };
  const dek = c.randomBytes(32);
  let gate;
  try {
    const payload = encrypt(dek, Buffer.from(plaintext), h),
      context = hash({ header: h, payload });
    let box = await wrap(recipient, dek, { context, role: "recipient-key" });
    const shares = [];
    if (policy) {
      gate = c.randomBytes(32);
      box = encrypt(gate, data(box), { context, role: "gate" });
      const fragments = await split(new Uint8Array(gate), 3, 2);
      for (let i = 0; i < 3; i++) {
        const g = policy.guardians[i];
        try {
          shares.push({
            guardian: g.id,
            box: await wrap(g.publicKey, fragments[i], {
              context,
              guardian: g.id,
              role: "guardian-share",
            }),
          });
        } finally {
          fragments[i].fill(0);
        }
      }
    }
    const capsule = { format: FORMAT, context, box, shares };
    const unsigned = {
      format: FORMAT,
      header: h,
      payload,
      capsule_hash: hash(capsule),
    };
    return {
      envelope: { ...unsigned, signature: sign(unsigned, sender.signPrivate) },
      capsule,
    };
  } finally {
    dek.fill(0);
    if (gate) gate.fill(0);
  }
}
async function open({
  envelope,
  capsule,
  recipient,
  sender,
  policy = null,
  release = null,
}) {
  const h = validateEnvelope(envelope, sender, recipient.publicKey),
    context = validateCapsule(envelope, capsule);
  let box = capsule.box,
    gate,
    dek;
  const shares = [];
  try {
    if (h.mode === "guarded") {
      policyShape(policy);
      if (hash(policy) !== h.policy_hash) throw Error("policy mismatch");
      if (
        !release ||
        release.envelope_hash !== hash(envelope) ||
        !Array.isArray(release.responses)
      )
        throw Error("guardian release required");
      const seen = new Set();
      for (const r of release.responses) {
        fields(r, ["body", "signature"]);
        const g = policy.guardians.find((x) => x.id === r.body.guardian);
        if (
          !g ||
          seen.has(g.id) ||
          !verify(r.body, r.signature, g.publicKey.sign)
        )
          throw Error("invalid or repeated guardian");
        const body = r.body;
        fields(body, [
          "guardian",
          "grant_hash",
          "envelope_hash",
          "capsule_hash",
          "recipient_key",
          "policy_hash",
          "share",
        ]);
        if (
          body.envelope_hash !== hash(envelope) ||
          body.capsule_hash !== envelope.capsule_hash ||
          body.recipient_key !== h.recipient_key ||
          body.policy_hash !== h.policy_hash ||
          body.grant_hash !== release.grant_hash
        )
          throw Error("release binding mismatch");
        seen.add(g.id);
        shares.push(
          new Uint8Array(
            await unwrap(recipient, body.share, {
              context,
              guardian: g.id,
              grant: body.grant_hash,
              role: "released-share",
            }),
          ),
        );
      }
      if (seen.size < policy.threshold) throw Error("guardian quorum missing");
      gate = Buffer.from(await combine(shares));
      box = JSON.parse(
        decrypt(gate, box, { context, role: "gate" }).toString("utf8"),
      );
    }
    dek = await unwrap(recipient, box, { context, role: "recipient-key" });
    return decrypt(dek, envelope.payload, h).toString("utf8");
  } finally {
    if (gate) gate.fill(0);
    if (dek) dek.fill(0);
    for (const s of shares) s.fill(0);
  }
}
module.exports = {
  FORMAT,
  MAX_PRIVATE,
  identity,
  validatePublic,
  seal,
  open,
  hash,
  keyId,
  sign,
  verify,
  wrap,
  unwrap,
  bytes,
  b64,
  fields,
  canonical,
  data,
  policyShape,
  policyForUse,
  validateEnvelope,
  validateCapsule,
};
