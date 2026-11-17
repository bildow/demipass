#!/usr/bin/env node
"use strict";
const fs = require("node:fs"), path = require("node:path"), p = require("./crypto");
const { privateDirectory, readPrivate } = require("./client"), { Journal } = require("./journal");
const { evaluate, validateCheckpoint } = require("./revocation");
function main(args) {
  if (args.length !== 2) throw Error("arguments");
  const dir = path.resolve(args[0]); privateDirectory(dir);
  const lock = fs.fstatSync(9), named = fs.lstatSync(path.join(dir, "lease.lock"));
  if (!lock.isFile() || named.isSymbolicLink() || lock.dev !== named.dev || lock.ino !== named.ino ||
      named.uid !== process.getuid() || (named.mode & 0o077)) throw Error("lease required");
  const request = readPrivate(args[1]);
  if (request.fixture !== true) throw Error("live status service disabled");
  if (request.mode === "inspect") p.fields(request, ["fixture", "mode"]);
  else {
    p.fields(request, ["fixture", "mode", "expected_checkpoint", "policy", "evidence", "trusted", "snapshots"]);
    if (request.mode !== "evaluate" || (request.expected_checkpoint !== "new" &&
        !/^[a-f0-9]{64}$/.test(request.expected_checkpoint))) throw Error("expected checkpoint required");
  }
  const journalFile = path.join(dir, "status.jsonl");
  try {
    const st = fs.lstatSync(journalFile);
    if (!st.isFile() || st.isSymbolicLink() || st.uid !== process.getuid() || (st.mode & 0o077))
      throw Error("unsafe checkpoint storage");
  } catch (e) { if (e.code !== "ENOENT") throw e; }
  // Inspection never initializes missing storage. Missing state needs explicit new bootstrap.
  if (!fs.existsSync(journalFile) && (request.mode === "inspect" || request.expected_checkpoint !== "new"))
    throw Error("checkpoint storage missing");
  const journal = new Journal(journalFile);
  try {
    const stored = journal.get("checkpoint");
    if (stored !== undefined) validateCheckpoint(stored);
    const previous = stored === undefined ? null : stored;
    const actual = previous ? p.hash(previous) : "new";
    if (request.mode === "inspect") return { verdict: "inspect_only", checkpoint_hash: actual, live_guardian_release: false };
    if (actual !== request.expected_checkpoint) throw Error("checkpoint changed or rolled back");
    const result = evaluate({ ...request, previous });
    // Persist a revocation too. Never return a successful current-status result before fsync.
    if (result.checkpoint_hash !== actual) journal.set("checkpoint", result.checkpoint);
    return result;
  } finally { journal.close(); }
}
if (require.main === module) {
  try { process.stdout.write(JSON.stringify(main(process.argv.slice(2))) + "\n"); }
  catch (_) {
    process.stdout.write(JSON.stringify({ verdict: "hold", reason: "status_or_checkpoint_unverified", live_guardian_release: false }) + "\n");
    process.exitCode = 2;
  }
}
module.exports = { main };
