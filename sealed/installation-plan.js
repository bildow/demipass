'use strict';
// Read-only plan. Never creates a permit, keys, wallets, units or trust pins.
const path=require('node:path');
function plan(directory,role){
 if(typeof directory!=='string'||!path.isAbsolute(directory)||!['guardian','coordinator','endpoint'].includes(role))throw Error('absolute directory and role required');
 return {format:'conduit-installation-plan-v1',role,directory:path.resolve(directory),source_sha256:require('./readiness').sourceDigest(),
  state:'held_until_operator_provisioning',live_guardian_release:false,
  required:['private 0700 instance directory','private 0600 config and credentials','independent selected custodians and reviewed Tome custody record','exact-source independent acceptance receipt','private expiring operator permit (not generated)','pinned signed enrollment and current status feed','retained checkpoint reconciliation','distinct guardian transport and approval credentials','TLS certificate and key for each service','backup and restoration evidence'],
  command:['/bin/sh',path.resolve(__dirname,role==='endpoint'?'endpoint.sh':'service.sh'),path.resolve(directory)],
  stop:'Stop service/MCP process; remove or disable permit. Keep all ciphertext, keys, checkpoints, payment and dispute journals.',
  rollback:'Do not switch to a fixture runner or reset journals. Restore the accepted artifact and reconcile original checkpoint/paid records before restart.',
  limits:['A local source hash is not loaded-code or host-integrity attestation.','Distinct signed labels do not prove independent administrators.','No live guardian or Brain inbound activation is performed.']};
}
if(require.main===module){try{if(process.argv.length!==4)throw Error('usage');process.stdout.write(JSON.stringify(plan(process.argv[2],process.argv[3]),null,2)+'\n');}catch{process.stderr.write('usage: node sealed/installation-plan.js ABSOLUTE_INSTANCE_DIRECTORY guardian|coordinator|endpoint\n');process.exitCode=2;}}
module.exports={plan};
