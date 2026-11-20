#!/usr/bin/env node
'use strict';
// Invoked by the owner's existing launcher AFTER its update gate. This does not
// approve Claude's development-channel confirmation or change any permissions.
const { spawn } = require('child_process');
const { policy, claudeArgs } = require('../conduit-startup');
const [binary, ...args] = process.argv.slice(2);
if (!binary || !require('path').isAbsolute(binary)) throw Error('absolute_claude_binary_required');
let child;
let enabled=false;
try { enabled=policy().claude_channels; } catch { console.error('Conduit startup policy invalid; launching Claude without automatic channel activation.'); }
try { child = spawn(binary, claudeArgs(args, enabled), { stdio: 'inherit' }); }
catch { process.exit(1); }
// Terminal signals already reach both members of the foreground group. Sending
// SIGINT twice turns a turn interruption into an unintended Claude exit.
for (const signal of ['SIGINT','SIGHUP']) process.on(signal, () => {});
process.on('SIGTERM', () => child.kill('SIGTERM'));
child.on('error', () => { process.exitCode = 1; });
child.on('exit', (code, signal) => { process.exitCode = code ?? (signal === 'SIGINT' ? 130 : 1); });
