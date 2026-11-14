"use strict";
const fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  p = require("./crypto");
function privateDirectory(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(dir);
  if (
    !st.isDirectory() ||
    st.isSymbolicLink() ||
    st.mode & 0o077 ||
    st.uid !== process.getuid()
  )
    throw Error("sealed directory must be owned and private");
}
function readPrivate(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const st = fs.fstatSync(fd);
    if (
      !st.isFile() ||
      st.mode & 0o077 ||
      st.uid !== process.getuid() ||
      st.size > 131072
    )
      throw Error("unsafe private file");
    return JSON.parse(fs.readFileSync(fd, "utf8"));
  } finally {
    fs.closeSync(fd);
  }
}
function writeNew(file, value) {
  const fd = fs.openSync(
    file,
    fs.constants.O_CREAT |
      fs.constants.O_EXCL |
      fs.constants.O_WRONLY |
      fs.constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const b = Buffer.from(JSON.stringify(value) + "\n");
    let off = 0;
    while (off < b.length) {
      const n = fs.writeSync(fd, b, off, b.length - off);
      if (n <= 0) throw Error("short write");
      off += n;
    }
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  const d = fs.openSync(path.dirname(file), "r");
  try {
    fs.fsyncSync(d);
  } finally {
    fs.closeSync(d);
  }
}
class Client {
  constructor({
    directory = path.join(os.homedir(), ".local/state/demipass/sealed"),
    mailbox,
  }) {
    if (typeof mailbox !== "string" || !/^[a-z][a-z0-9-]{1,79}$/.test(mailbox))
      throw Error("canonical stable mailbox required");
    if (Number(process.versions.node.split(".")[0]) < 20)
      throw Error("sealed messages require Node 20 or later");
    this.mailbox = mailbox;
    this.dir = path.resolve(directory);
    privateDirectory(this.dir);
    for (const d of ["keys", "outbox", "capsules"])
      privateDirectory(path.join(this.dir, d));
    this.keyFile = path.join(this.dir, "keys", mailbox + ".json");
  }
  key() {
    const id = readPrivate(this.keyFile);
    p.validatePublic(id.publicKey);
    if (
      id.publicKey.mailbox !== this.mailbox ||
      !p.verify(
        { check: "key-pair" },
        p.sign({ check: "key-pair" }, id.signPrivate),
        id.publicKey.sign,
      )
    )
      throw Error("key identity mismatch");
    return id;
  }
  async initialize() {
    if (!fs.existsSync(this.keyFile)) {
      const id = await p.identity(this.mailbox);
      try {
        writeNew(this.keyFile, id);
      } catch (e) {
        if (e.code !== "EEXIST") throw e;
      }
    }
    const pub = this.key().publicKey;
    return {
      public_key: pub,
      fingerprint: p.keyId(pub),
      live_guardian_release: false,
      trust:
        "Pin this public key out of band. A relay address does not establish key ownership.",
    };
  }
  file(kind, id) {
    if (typeof id !== "string" || !/^[a-f0-9-]{36}$/.test(id))
      throw Error("invalid envelope id");
    return path.join(this.dir, kind, id + ".json");
  }
  async prepare({
    recipient,
    plaintext,
    public_text = "",
    defer_capsule = true,
    policy = null,
    fixture = false,
  }) {
    // Caller must obtain recipient from a trusted channel; never learn keys from relay ciphertext.
    if (typeof defer_capsule !== "boolean")
      throw Error("defer_capsule must be boolean");
    const packet = await p.seal({
      sender: this.key(),
      recipient,
      plaintext,
      publicText: public_text,
      policy,
      fixture,
    });
    const id = packet.envelope.header.id;
    writeNew(this.file("capsules", id), packet.capsule);
    writeNew(this.file("outbox", id), {
      envelope: packet.envelope,
      recipient,
      include_capsule: !defer_capsule,
    });
    return {
      id,
      recipient_fingerprint: p.keyId(recipient),
      capsule_deferred: defer_capsule,
      capsule_file: this.file("capsules", id),
      bytes: Buffer.byteLength(JSON.stringify(packet.envelope)),
      private_bytes: Buffer.byteLength(plaintext),
    };
  }
  transport(id) {
    const saved = readPrivate(this.file("outbox", id)),
      capsule = readPrivate(this.file("capsules", id));
    p.validateEnvelope(saved.envelope, this.key().publicKey, saved.recipient);
    p.validateCapsule(saved.envelope, capsule);
    return {
      to: saved.envelope.header.recipient,
      payload_type: p.FORMAT,
      client_msg_id: id,
      body: JSON.stringify({
        envelope: saved.envelope,
        capsule: saved.include_capsule ? capsule : null,
      }),
    };
  }
  capsule(id) {
    return readPrivate(this.file("capsules", id));
  }
  async open({ envelope, capsule, sender, policy = null, release = null }) {
    return p.open({
      envelope,
      capsule,
      sender,
      policy,
      release,
      recipient: this.key(),
    });
  }
}
module.exports = { Client, readPrivate, writeNew, privateDirectory };
