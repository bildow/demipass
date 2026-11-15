#!/usr/bin/env node
"use strict";
// Offline operator tool. No identity generation, provider calls, relay calls or key logging.
const { Client, readPrivate, writeNew } = require("./client");
const { exportIdentity, restoreIdentity } = require("./backup");
const p = require("./crypto");
async function main(args) {
  const [command, directory, mailbox, recoveryFile, pin, backupFile] = args;
  if (args.length !== 6 || !["export", "restore"].includes(command))
    throw Error("usage: node sealed/backup-cli.js export|restore DIRECTORY MAILBOX RECOVERY_FILE PIN BACKUP_FILE");
  if (!/^[a-f0-9]{64}$/.test(pin)) throw Error("independently verified fingerprint required");
  const recovery = readPrivate(recoveryFile);
  // On export this is a public identity file; on restore it is the private recovery identity.
  if (command === "export") {
    p.validatePublic(recovery);
    if (p.keyId(recovery) !== pin) throw Error("recovery fingerprint mismatch");
  }
  const client = new Client({ directory, mailbox });
  if (command === "export") {
    const backup = await exportIdentity({ client, recoveryPublic: recovery });
    writeNew(backupFile, backup);
    return { exported: true, fingerprint: p.keyId(backup.header.identity), live_guardian_release: false };
  }
  return restoreIdentity({ client, backup: readPrivate(backupFile), recoveryIdentity: recovery, expectedFingerprint: pin });
}
if (require.main === module) main(process.argv.slice(2)).then(
  (result) => process.stdout.write(JSON.stringify(result) + "\n"),
  () => { process.stderr.write("Identity backup operation refused or incomplete; no overwrite or automatic retry performed. Check inputs and private file permissions.\n"); process.exitCode = 1; },
);
module.exports = { main };
