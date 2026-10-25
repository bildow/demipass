// Browser smoke test: loads the unpacked extension in Playwright's Chromium,
// pointed at the local mock API, and drives the real popup and content script.
//
//   PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core node extension/test/e2e/smoke.js
//
// playwright-core is not a dependency of this repo; point PLAYWRIGHT_CORE at
// any install whose browser build is in ~/.cache/ms-playwright.
//
// Test-only change to the extension: the copy loaded here gets host
// permissions for http://localhost/* and http://127.0.0.1/*. Headless
// Chromium cannot click the toolbar button, which is what grants activeTab in
// real use; the extra host permission stands in for that grant. Nothing else
// is changed.

import { createRequire } from 'node:module';
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { startMock, createMockState, approveDevice, phoneDecide } from '../mock-server.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const extSrc = path.resolve(here, '../..');
const require = createRequire(import.meta.url);
const pwPath = process.env.PLAYWRIGHT_CORE || 'playwright-core';
let chromium;
try { ({ chromium } = require(pwPath)); } catch {
  console.log('SKIP: playwright-core not found (set PLAYWRIGHT_CORE)');
  process.exit(0);
}

const results = [];
async function step(name, fn) {
  try { await fn(); results.push(['PASS', name]); console.log('PASS', name); }
  catch (e) { results.push(['FAIL', name]); console.log('FAIL', name, '\n   ', e && e.message); throw e; }
}

const SECRET_MANUAL = 'correct-horse-battery-' + Math.random().toString(36).slice(2, 8);
const SECRET_TYPED = 'typed-on-the-page-' + Math.random().toString(36).slice(2, 8);

const work = mkdtempSync(path.join(process.env.SMOKE_TMP || tmpdir(), 'dp-ext-smoke-'));
const extDir = path.join(work, 'extension');
cpSync(extSrc, extDir, { recursive: true, filter: (p) => !p.includes(`${path.sep}test`) });
const manifest = JSON.parse(readFileSync(path.join(extDir, 'manifest.json'), 'utf8'));
manifest.host_permissions.push('http://localhost/*', 'http://127.0.0.1/*');
writeFileSync(path.join(extDir, 'manifest.json'), JSON.stringify(manifest, null, 2));

// 30 s access tokens sit inside the client's 60 s refresh skew, so every
// authenticated call in this run rotates the refresh token.
const mock = await startMock({ state: createMockState({ accessTtlSec: 30 }) });
const { state } = mock;
const A = `http://localhost:${mock.sitePort}`;
const B = `http://127.0.0.1:${mock.sitePort}`;

const context = await chromium.launchPersistentContext(path.join(work, 'profile'), {
  channel: 'chromium',
  headless: true,
  args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
});
const consoleLines = [];
context.on('console', (m) => consoleLines.push(m.text()));
context.on('page', (p) => p.on('console', (m) => consoleLines.push(m.text())));

let failed = false;
try {
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent('serviceworker');
  sw.on?.('console', (m) => consoleLines.push(m.text()));
  const extId = new URL(sw.url()).host;
  const ext = (p) => `chrome-extension://${extId}/${p}`;

  async function tabIdOf(page) {
    await page.bringToFront();
    return sw.evaluate(async () => (await chrome.tabs.query({ active: true, lastFocusedWindow: true }))[0].id);
  }
  async function openPopupFor(page) {
    const id = await tabIdOf(page);
    const pop = await context.newPage();
    await pop.goto(ext(`ui/popup.html?tab=${id}`));
    return { pop, id };
  }
  const waitText = (page, sel, re, timeout = 15000) =>
    page.waitForFunction(([s, src]) => new RegExp(src).test(document.querySelector(s)?.textContent || ''), [sel, re.source], { timeout });

  await step('point the extension at the mock API (options page)', async () => {
    const opt = await context.newPage();
    await opt.goto(ext('ui/options.html'));
    await opt.fill('#base', mock.apiBase);
    await opt.click('button[type=submit]');
    await waitText(opt, '#msg', /Using http:\/\/127\.0\.0\.1/);
    await opt.close();
  });

  await step('pair through the device flow (mock approval)', async () => {
    const pop = await context.newPage();
    await pop.goto(ext('ui/popup.html'));
    await pop.click('#pair-btn');
    await pop.waitForSelector('#user-code:not(:empty)');
    const code = (await pop.textContent('#user-code')).trim();
    assert.match(code, /^[0-9A-F]{4}-[0-9A-F]{4}$/);
    assert.equal(await pop.getAttribute('#pair-link', 'href'), 'https://demipass.com/device?code=' + code);
    const devReq = [...state.device.values()].find((d) => d.user_code === code);
    assert.equal(devReq.scope, 'transact');
    await approveDevice(state, code);
    await pop.waitForSelector('#signout:not([hidden])', { timeout: 15000 });
    await pop.close();
  });

  await step('tokens: access in storage.session, refresh sealed in storage.local', async () => {
    const s = await sw.evaluate(async () => ({ local: await chrome.storage.local.get(null), session: await chrome.storage.session.get(null) }));
    assert.ok(s.session.dp_access, 'access token in session');
    assert.ok(s.local.dp_refresh_sealed && s.local.dp_refresh_sealed.ct, 'sealed refresh in local');
    assert.equal(JSON.stringify(s.local).includes('dpr_'), false, 'no plaintext refresh token in storage.local');
    assert.equal(JSON.stringify(s.session).includes('dpr_'), false);
  });

  const pageA = await context.newPage();
  await pageA.goto(A + '/login.html');

  let ref;
  await step('"Add for this site" stores a password bound to the page origin', async () => {
    const { pop } = await openPopupFor(pageA);
    await pop.waitForSelector('#add:not([hidden])');
    await pop.fill('#add-name', 'mock-login');
    await pop.fill('#add-login', 'me@example.com');
    await pop.fill('#add-password', SECRET_MANUAL);
    await pop.click('#add-form button[type=submit]');
    await waitText(pop, '#add-msg', /Added/);
    const [r, s] = [...state.secrets].find(([, x]) => x.name === 'mock-login');
    ref = r;
    assert.deepEqual(s.origins, [A]);
    assert.equal(s.login, 'me@example.com');
    assert.equal(s.secret_type, 'password');
    assert.equal(s.value, SECRET_MANUAL);
    assert.equal(await pop.inputValue('#add-password'), '', 'password box cleared');
    await pop.close();
  });

  await step('fill on the bound origin: phone approval, then fields filled', async () => {
    const { pop } = await openPopupFor(pageA);
    await pop.waitForSelector(`#entry-list button[data-ref="${ref}"]`);
    await pop.click(`#entry-list button[data-ref="${ref}"]`);
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    assert.equal(await pageA.inputValue('#pass'), '', 'nothing filled before approval');
    const [reqId, f] = [...state.fills].find(([, x]) => x.status === 'pending');
    assert.equal(f.origin, A);
    assert.equal(await phoneDecide(mock.apiBase, state, reqId, 'approve'), 200);
    await waitText(pop, '#fill-msg', /^Filled\.$/);
    assert.equal(await pageA.inputValue('#user'), 'me@example.com');
    assert.equal(await pageA.inputValue('#pass'), SECRET_MANUAL);
    assert.equal(await pageA.inputValue('#q'), '', 'search box untouched');
    await pop.close();
  });

  await step('denied on the phone: nothing filled', async () => {
    const pageA2 = await context.newPage();
    await pageA2.goto(A + '/login.html');
    const { pop } = await openPopupFor(pageA2);
    await pop.click(`#entry-list button[data-ref="${ref}"]`);
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    const [reqId] = [...state.fills].find(([, x]) => x.status === 'pending');
    await phoneDecide(mock.apiBase, state, reqId, 'deny');
    await waitText(pop, '#fill-msg', /Denied/);
    assert.equal(await pageA2.inputValue('#pass'), '');
    await pop.close(); await pageA2.close();
  });

  await step('other origin: no candidates listed, and a forced fill is refused by origin binding', async () => {
    const pageB = await context.newPage();
    await pageB.goto(B + '/login.html');
    const { pop, id } = await openPopupFor(pageB);
    await waitText(pop, '#entry-list', /No entries are bound to this site/);
    // Bypass the UI: ask the worker to fill the localhost-bound entry into this 127.0.0.1 page.
    const out = await pop.evaluate(async ([tabId, ref]) => {
      const ctx = await chrome.runtime.sendMessage({ type: 'ui:context', tabId });
      const t = ctx.targets[0];
      const r = await chrome.runtime.sendMessage({ type: 'ui:fill', tabId, documentId: t.documentId, ref });
      for (let i = 0; i < 50; i++) {
        const s = await chrome.runtime.sendMessage({ type: 'ui:fillStatus', fillId: r.fillId });
        if (!['requesting', 'pending', 'approved', 'filling'].includes(s.state)) return { origin: t.origin, ...s };
        await new Promise((res) => setTimeout(res, 100));
      }
      return { state: 'timeout' };
    }, [id, ref]);
    assert.equal(out.origin, B, 'worker used the browser-reported origin');
    assert.equal(out.state, 'refused');
    const call = state.calls.filter((c) => c.path === '/api/blindkey/fill/request').pop();
    assert.equal(call.status, 403);
    assert.equal(call.meta.origin, B);
    assert.equal(await pageB.inputValue('#pass'), '');
    await pop.close(); await pageB.close();
  });

  await step('page navigates to another origin while waiting: request is never redeemed, nothing filled', async () => {
    const pageA3 = await context.newPage();
    await pageA3.goto(A + '/login.html');
    const { pop } = await openPopupFor(pageA3);
    await pop.click(`#entry-list button[data-ref="${ref}"]`);
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    const [reqId] = [...state.fills].find(([, x]) => x.status === 'pending');
    await pageA3.goto(B + '/login.html');
    await waitText(pop, '#fill-msg', /page changed/);
    await phoneDecide(mock.apiBase, state, reqId, 'approve');
    await new Promise((r) => setTimeout(r, 2500));
    assert.equal(state.fills.get(reqId).status, 'approved', 'approved but never redeemed');
    assert.equal(await pageA3.inputValue('#pass'), '');
    await pop.close(); await pageA3.close();
  });

  await step('save on submit: typed login reaches /store only after Save in the popup', async () => {
    const pageC = await context.newPage();
    await pageC.goto(A + '/login.html');
    await pageC.fill('#user', 'typed@example.com');
    await pageC.fill('#pass', SECRET_TYPED);
    const storesBefore = state.calls.filter((c) => c.path === '/api/blindkey/store').length;
    await Promise.all([pageC.waitForURL(/\/done$/), pageC.click('button[type=submit]')]);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(state.calls.filter((c) => c.path === '/api/blindkey/store').length, storesBefore, 'no store before Save');
    const badge = await sw.evaluate(async (tabId) => chrome.action.getBadgeText({ tabId }), await tabIdOf(pageC));
    assert.equal(badge, 'SAVE');
    const { pop } = await openPopupFor(pageC);
    await pop.waitForSelector('#capture:not([hidden])');
    assert.equal(await pop.textContent('#cap-origin'), A);
    assert.equal(await pop.textContent('#cap-user'), 'typed@example.com');
    assert.equal(await pop.inputValue('#cap-name'), `localhost:${mock.sitePort} (typed@example.com)`);
    await pop.click('#cap-save');
    await waitText(pop, '#cap-msg', /Saved as/);
    const s = [...state.secrets.values()].find((x) => x.login === 'typed@example.com');
    assert.equal(s.value, SECRET_TYPED);
    assert.equal(s.secret_type, 'password');
    assert.deepEqual(s.origins, [A]);
    const popHtml = await pop.content();
    assert.equal(popHtml.includes(SECRET_TYPED), false, 'popup never received the value');
    await pop.close(); await pageC.close();
  });

  await step('no value in extension storage or any console output', async () => {
    const s = await sw.evaluate(async () => JSON.stringify({ l: await chrome.storage.local.get(null), s: await chrome.storage.session.get(null) }));
    for (const v of [SECRET_MANUAL, SECRET_TYPED]) {
      assert.equal(s.includes(v), false);
      assert.equal(consoleLines.some((l) => l.includes(v)), false);
    }
  });

  await step('refresh rotated on every call without losing the session', async () => {
    const rotations = state.calls.filter((c) => c.path === '/api/identity/refresh' && c.status === 200).length;
    assert.ok(rotations >= 5, 'rotations: ' + rotations);
    assert.equal(state.calls.filter((c) => c.path === '/api/identity/refresh' && c.status !== 200).length, 0, 'no failed refresh');
  });

  await step('sign out revokes the refresh token', async () => {
    const pop = await context.newPage();
    await pop.goto(ext('ui/popup.html'));
    await pop.waitForSelector('#signout:not([hidden])');
    await pop.click('#signout');
    await pop.waitForSelector('#pair-btn:not([hidden])');
    assert.ok(state.calls.some((c) => c.path === '/api/identity/refresh/revoke' && c.status === 200));
    assert.ok([...state.refresh.values()].filter((r) => r.sid !== 'sid_phone').every((r) => r.revoked), 'every extension refresh token revoked');
    const local = await sw.evaluate(async () => chrome.storage.local.get(null));
    assert.equal('dp_refresh_sealed' in local, false);
  });
} catch {
  failed = true;
} finally {
  await context.close();
  await mock.close();
  rmSync(work, { recursive: true, force: true });
}

const pass = results.filter((r) => r[0] === 'PASS').length;
console.log(`\nsmoke: ${pass}/${results.length} steps passed${failed ? ' (stopped at first failure)' : ''}`);
process.exit(failed ? 1 : 0);
