// Submit the Firefox build to addons.mozilla.org on the LISTED channel (public listing, human review).
// The add-on (demipass-browser@demipass.com) already exists on AMO as unlisted 0.1.0 — the signed build that
// demipass.com/extension serves. A listed version needs its own version number (AMO versions are unique across
// channels) and listing metadata; once approved, AMO also serves it as the update for unlisted installs.
//
//   node extension/build.mjs --package
//   AMO_JWT_ISSUER=… AMO_JWT_SECRET=… node extension/release/amo-listed.mjs [--notes FILE] [--screenshots DIR] [--dry-run]
//
// Keys: AMO → Developer Hub → Manage API Keys, account "dustforge". They are read from the environment only and
// never printed. --notes: reviewer notes (test account steps) from a file kept outside the repo.
// --screenshots: PNGs (1280×800) added as previews. Prints the AMO version id and review status.

import crypto from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const ext = path.resolve(here, '..');
const API = 'https://addons.mozilla.org/api/v5/';
const arg = (name) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : null; };
const DRY = process.argv.includes('--dry-run');

const manifest = JSON.parse(readFileSync(path.join(ext, 'dist/firefox/manifest.json'), 'utf8'));
const GUID = manifest.browser_specific_settings.gecko.id;
const XPI = path.join(ext, 'dist', `demipass-firefox-${manifest.version}.xpi`);

// The listing. Text matches the Chrome Web Store listing.
const LISTING = {
  summary: { 'en-US': 'Save logins to your DemiPass vault and fill them after you approve on your phone. Needs the DemiPass Android app.' },
  description: { 'en-US': [
    'DemiPass keeps your passwords and API keys in a vault that your AI agents can use without ever seeing them. The browser extension connects that vault to the websites you sign in to.',
    '',
    '<b>Save as you sign in.</b> When you sign in with a password you typed, DemiPass offers to save it. Nothing is sent until you click Save.',
    '<b>Fill with your phone.</b> Choose a saved login, then approve the fill and enter your PIN in the DemiPass app. The password goes only to the site it was saved for.',
    '<b>Your agents use secrets without seeing them.</b> Logins you save here can also be granted to your agents, which use them through DemiPass without the value entering their context.',
    '',
    'Requires a DemiPass account and the DemiPass Android app, which holds your vault and approves every pairing and fill. Get it at https://demipass.com.',
    '',
    'Privacy: page contents stay in your browser. The extension sends a site\'s address only when you open it on that site, fill a login or save one. No ads, no analytics, no tracking. Full policy: https://demipass.com/privacy',
  ].join('\n') },
  categories: ['privacy-security'],
  homepage: { 'en-US': 'https://demipass.com/extension' },
  support_url: { 'en-US': 'https://demipass.com' },
  support_email: { 'en-US': 'support@dustforge.com' },
};

function jwt() {
  const iss = process.env.AMO_JWT_ISSUER, secret = process.env.AMO_JWT_SECRET;
  if (!iss || !secret) throw new Error('AMO_JWT_ISSUER and AMO_JWT_SECRET must be set (AMO → Manage API Keys)');
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const body = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss, jti: crypto.randomUUID(), iat: now, exp: now + 60 })}`;
  return `${body}.${crypto.createHmac('sha256', secret).update(body).digest('base64url')}`;
}

async function call(method, p, body, isForm = false) {
  if (DRY) { console.log(`[dry-run] ${method} ${API}${p}`, isForm ? '(multipart)' : JSON.stringify(body || {}).slice(0, 200)); return {}; }
  const headers = { Authorization: `JWT ${jwt()}` };
  if (body && !isForm) headers['Content-Type'] = 'application/json';
  const r = await fetch(API + p, { method, headers, body: body ? (isForm ? body : JSON.stringify(body)) : undefined });
  const text = await r.text();
  if (!r.ok) throw new Error(`${method} ${p} → ${r.status}: ${text.slice(0, 600)}`);
  return text ? JSON.parse(text) : {};
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 1. Listing metadata first: AMO refuses a first listed version on an add-on without a summary and categories.
await call('PATCH', `addons/addon/${encodeURIComponent(GUID)}/`, LISTING);
console.log('listing metadata set');

// 2. Upload the build on the listed channel and wait for validation.
const form = new FormData();
form.append('channel', 'listed');
form.append('upload', new Blob([readFileSync(XPI)], { type: 'application/x-xpinstall' }), path.basename(XPI));
let up = await call('POST', 'addons/upload/', form, true);
for (let i = 0; !DRY && !up.processed && i < 60; i++) { await sleep(5000); up = await call('GET', `addons/upload/${up.uuid}/`); }
if (!DRY && !up.valid) throw new Error(`validation failed: ${JSON.stringify(up.validation && up.validation.messages).slice(0, 1500)}`);
console.log(`uploaded ${path.basename(XPI)} (${manifest.version}), valid`);

// 3. Create the listed version (goes to human review).
const notesFile = arg('--notes');
const version = await call('POST', `addons/addon/${encodeURIComponent(GUID)}/versions/`, {
  upload: up.uuid, license: 'MIT', ...(notesFile ? { approval_notes: readFileSync(notesFile, 'utf8') } : {}) });
console.log(`listed version ${version.version || manifest.version} created: id ${version.id}, file status ${version.file && version.file.status}`);

// 4. Screenshots.
const shots = arg('--screenshots');
if (shots) {
  for (const f of readdirSync(shots).filter((n) => /\.png$/i.test(n)).sort()) {
    const fd = new FormData();
    fd.append('image', new Blob([readFileSync(path.join(shots, f))], { type: 'image/png' }), f);
    await call('POST', `addons/addon/${encodeURIComponent(GUID)}/previews/`, fd, true);
    console.log(`preview added: ${f}`);
  }
}
console.log('Left for the owner in the Developer Hub: the privacy policy text (Edit Product Page → Privacy Policy → https://demipass.com/privacy).');
