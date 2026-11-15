"use strict";
// Local operator API, deliberately not exposed through MCP. Never returns private keys.
const c = require("node:crypto"), p = require("./crypto"), { writeNew } = require("./client");
const FORMAT = "conduit-identity-backup-v1";
async function validateIdentity(id) {
  p.fields(id, ["publicKey", "kemPrivate", "signPrivate"]);
  p.validatePublic(id.publicKey);
  p.bytes(id.kemPrivate, 32);
  p.fields(id.signPrivate, ["kty", "crv", "x", "d"]);
  if (id.signPrivate.kty !== "OKP" || id.signPrivate.crv !== "Ed25519" ||
      id.signPrivate.x !== id.publicKey.sign.x) throw Error("identity signing mismatch");
  p.bytes(id.signPrivate.d, 32);
  const challenge = c.randomBytes(32), context = { format: FORMAT, purpose: "key-pair-check" };
  let opened;
  try {
    const box = await p.wrap(id.publicKey, challenge, context);
    opened = await p.unwrap(id, box, context);
    if (!opened.equals(challenge) || !p.verify(context, p.sign(context, id.signPrivate), id.publicKey.sign))
      throw Error("identity key-pair mismatch");
  } finally { challenge.fill(0); if (opened) opened.fill(0); }
}
async function exportIdentity({ client, recoveryPublic, now = Date.now() }) {
  p.validatePublic(recoveryPublic);
  if (!Number.isSafeInteger(now) || now < 0) throw Error("invalid clock");
  const id = client.key();
  await validateIdentity(id);
  // Losing the endpoint must not also lose the only backup decryption key.
  if (recoveryPublic.kem === id.publicKey.kem || recoveryPublic.sign.x === id.publicKey.sign.x)
    throw Error("separate recovery identity required");
  const header = { format: FORMAT, identity: id.publicKey,
    recovery_fingerprint: p.keyId(recoveryPublic), created_at: now };
  const plain = p.data(id);
  try {
    const body = { header, box: await p.wrap(recoveryPublic, plain, header) };
    return { ...body, signature: p.sign(body, id.signPrivate) };
  } finally { plain.fill(0); }
}
async function restoreIdentity({ client, backup, recoveryIdentity, expectedFingerprint }) {
  if (typeof expectedFingerprint !== "string" || !/^[a-f0-9]{64}$/.test(expectedFingerprint))
    throw Error("independently pinned identity fingerprint required");
  // Reject huge/untyped input before HPKE or disk writes. JSON objects only, no raw archive paths.
  if (Buffer.byteLength(p.canonical(backup)) > 8192) throw Error("oversize identity backup");
  backup = JSON.parse(p.canonical(backup));
  p.fields(backup, ["header", "box", "signature"]);
  const { header, box, signature } = backup;
  p.fields(header, ["format", "identity", "recovery_fingerprint", "created_at"]);
  p.validatePublic(header.identity);
  p.validatePublic(recoveryIdentity.publicKey);
  if (header.format !== FORMAT || header.identity.mailbox !== client.mailbox ||
      p.keyId(header.identity) !== expectedFingerprint ||
      header.recovery_fingerprint !== p.keyId(recoveryIdentity.publicKey) ||
      !Number.isSafeInteger(header.created_at) || header.created_at < 0 ||
      !p.verify({ header, box }, signature, header.identity.sign)) throw Error("backup binding mismatch");
  let plain;
  try {
    plain = await p.unwrap(recoveryIdentity, box, header);
    const id = JSON.parse(plain.toString("utf8"));
    await validateIdentity(id);
    if (p.canonical(id.publicKey) !== p.canonical(header.identity)) throw Error("backup identity mismatch");
    // O_EXCL prevents replacement, including a competing initialize/restore or symlink.
    writeNew(client.keyFile, id);
    return { restored: true, fingerprint: expectedFingerprint, live_guardian_release: false };
  } finally { if (plain) plain.fill(0); }
}
module.exports = { FORMAT, exportIdentity, restoreIdentity };
