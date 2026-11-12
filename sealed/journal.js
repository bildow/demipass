"use strict";
// A single OS-locked writer owns each journal. Ciphertext and public evidence only.
const fs = require("node:fs"),
  path = require("node:path");
const { hash, fields } = require("./crypto");
const openPaths = new Set();
class Journal {
  constructor(file) {
    this.file = path.resolve(file);
    this.rows = new Map();
    this.prev = "0".repeat(64);
    this.failed = false;
    if (openPaths.has(this.file)) throw Error("journal already open");
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    if (fs.existsSync(this.file)) {
      if (
        fs.lstatSync(this.file).isSymbolicLink() ||
        fs.statSync(this.file).mode & 0o077
      )
        throw Error("journal must be private regular storage");
      const raw = fs.readFileSync(this.file, "utf8");
      if (raw && !raw.endsWith("\n"))
        throw Error("incomplete journal: hold and reconcile");
      for (const line of raw.trimEnd().split("\n").filter(Boolean)) {
        const row = JSON.parse(line);
        fields(row, ["previous", "key", "value", "digest"]);
        const { digest, ...body } = row;
        if (
          row.previous !== this.prev ||
          hash(body) !== digest ||
          typeof row.key !== "string"
        )
          throw Error("corrupt journal");
        this.prev = digest;
        this.rows.set(row.key, row.value);
      }
    }
    this.fd = fs.openSync(
      this.file,
      fs.constants.O_APPEND |
        fs.constants.O_CREAT |
        fs.constants.O_WRONLY |
        fs.constants.O_NOFOLLOW,
      0o600,
    );
    openPaths.add(this.file);
    // Re-fsync replayed bytes too: a prior process may have observed a failed fsync.
    try {
      fs.fsyncSync(this.fd);
      const dir = fs.openSync(path.dirname(this.file), "r");
      try {
        fs.fsyncSync(dir);
      } finally {
        fs.closeSync(dir);
      }
    } catch (e) {
      fs.closeSync(this.fd);
      openPaths.delete(this.file);
      throw e;
    }
  }
  get(key) {
    if (this.failed) throw Error("journal failed: restart and reconcile");
    return this.rows.has(key) ? structuredClone(this.rows.get(key)) : undefined;
  }
  set(key, value) {
    if (this.failed) throw Error("journal failed: restart and reconcile");
    const body = { previous: this.prev, key, value },
      digest = hash(body),
      buf = Buffer.from(JSON.stringify({ ...body, digest }) + "\n");
    try {
      let off = 0;
      while (off < buf.length) {
        const n = fs.writeSync(this.fd, buf, off, buf.length - off);
        if (n <= 0) throw Error("short write");
        off += n;
      }
      fs.fsyncSync(this.fd);
    } catch (e) {
      this.failed = true;
      throw e;
    }
    this.prev = digest;
    this.rows.set(key, structuredClone(value));
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    fs.closeSync(this.fd);
    openPaths.delete(this.file);
  }
}
module.exports = { Journal };
