#!/usr/bin/env node
'use strict';
// Invoked by the owner's existing launcher AFTER its update gate. This does not
// approve Claude's development-channel confirmation or change any permissions.
const { spawn } = require('child_process');
const { policy, claudeArgs } = require('../conduit-startup');
const [binary, ...args] = process.argv.slice(2);
if (!binary || !require('path').isAbsolute(binary)) throw Error('absolute_claude_binary_required');
let child;
try { child = spawn(binary, claudeArgs(args, policy().claude_channels), { stdio: 'inherit' }); }
catch { process.exit(1); }
for (const signal of ['SIGINT','SIGTERM','SIGHUP']) process.on(signal, () => child.kill(signal));
child.on('error', () => { process.exitCode = 1; });
child.on('exit', (code, signal) => { process.exitCode = code ?? (signal === 'SIGINT' ? 130 : 1); });
