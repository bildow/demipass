#!/usr/bin/env node
/**
 * demipass-login — sign this machine / agent in to DemiPass without a password.
 *
 *   npx demipass-login                       start a device login (default scope: transact)
 *   npx demipass-login --scope read          request a narrower scope
 *   npx demipass-login --label brain@phasewhip
 *   npx demipass-login --no-open             don't try to open a browser
 *   npx demipass-login --print-token         ALSO print the access token to stdout (for piping into legacy env configs)
 *   npx demipass-login status                who am I, where the bearer came from, expiry
 *   npx demipass-login logout                revoke + delete local credentials
 *
 * The operator approves at https://demipass.com/device (any device — the phone vault works).
 * Tokens are saved to ~/.config/demipass/credentials.json (0600) — or $DEMIPASS_CREDENTIALS —
 * and refreshed automatically by the SDK / MCP server before they expire.
 */
const os = require('os');
const { spawn } = require('child_process');
const demipass = require('../index.js');

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const arg = (name, def) => { const i = argv.indexOf(name); return i > -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : def; };
const cmd = argv[0] && !argv[0].startsWith('--') ? argv[0] : 'login';

demipass.configure({ baseUrl: arg('--url', process.env.DEMIPASS_URL || 'https://api.dustforge.com') });
demipass.loadBearerFromEnvironment();

function tryOpen(url) {
  if (has('--no-open')) return;
  if (process.platform === 'linux' && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) return;
  const cmdline = process.platform === 'darwin' ? ['open', url] : process.platform === 'win32' ? ['cmd', '/c', 'start', '', url] : ['xdg-open', url];
  try { const c = spawn(cmdline[0], cmdline.slice(1), { stdio: 'ignore', detached: true }); c.on('error', () => {}); c.unref(); } catch {}
}

(async () => {
  if (cmd === 'status') { console.log(JSON.stringify(demipass.loginStatus(), null, 2)); return; }
  if (cmd === 'logout') { console.log(JSON.stringify(await demipass.logout(), null, 2)); return; }
  if (cmd === 'help' || has('--help') || has('-h')) { process.stdout.write(require('fs').readFileSync(__filename, 'utf8').split('*/')[0].split('\n').slice(2).map(l => l.replace(/^ \* ?/, '')).join('\n') + '\n'); return; }
  if (cmd !== 'login') { process.stderr.write(`unknown command: ${cmd} (try: login | status | logout)\n`); process.exit(2); }

  const scope = arg('--scope', 'transact');
  const label = arg('--label', `${process.env.DEMIPASS_AGENT_LABEL || 'demipass-cli'}@${os.hostname()}`);
  const timeoutMs = Number(arg('--timeout', 900)) * 1000;
  const res = await demipass.deviceLogin({
    agentLabel: label, scope, timeoutMs,
    onCode: (c) => {
      process.stderr.write(
        `\nDemiPass login — approve the "${scope}" request for "${label}"\n\n` +
        `  Open:  ${c.verification_url_complete}\n` +
        `  Code:  ${c.user_code}\n\n` +
        `Any device works — the phone vault can approve it (Settings → Approve an agent login).\n` +
        `The code expires in ${Math.round(c.expires_in / 60)} min. Waiting for approval…\n`);
      tryOpen(c.verification_url_complete);
    },
  });
  process.stderr.write(
    `\nApproved. Signed in as ${res.email || res.did} (scope ${res.scope}), token valid until ${res.token_expires_at}.\n` +
    `Credentials saved to ${res.path} (0600). The SDK and MCP server pick this up automatically and keep it fresh.\n`);
  if (has('--print-token')) process.stdout.write((demipass.loadCredentials() || {}).token + '\n');
})().catch((e) => { process.stderr.write(`\n${e.message}\n`); process.exit(1); });
