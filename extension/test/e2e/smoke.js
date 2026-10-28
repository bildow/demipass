// Browser smoke test: builds the extension, loads it into a real browser
// pointed at the local mock API, and drives the real popup, options page and
// content script against a local login site. Never talks to api.dustforge.com.
//
//   node extension/test/e2e/smoke.js                         # Playwright Chromium (headless)
//   node extension/test/e2e/smoke.js --browser=firefox
//   node extension/test/e2e/smoke.js --browser=chromium,chrome,brave,firefox,zen
//
// Browsers and where they are looked for (override with the env var):
//   chromium  Playwright's Chromium build            PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core
//   chrome    Chrome for Testing                     CHROME_BIN   (~/.local/opt/chrome-for-testing-*/chrome)
//   brave     Brave                                  BRAVE_BIN    (/usr/bin/brave-browser)
//   firefox   Firefox release + geckodriver          FIREFOX_BIN  (~/.local/opt/firefox-*/firefox), GECKODRIVER
//   zen       Zen (Firefox fork) + geckodriver       ZEN_BIN      (~/.local/opt/zen-*/zen)
// Chromium-family browsers are driven by Playwright (playwright-core is not a
// dependency of this repo), Gecko browsers by geckodriver (W3C WebDriver).
// A browser that is not installed is skipped, not failed.
//
// Test-only changes to the build that is loaded:
//  - host permissions for http://localhost/* and http://127.0.0.1/*. Nothing
//    in headless automation can click the toolbar button, which is what
//    grants activeTab in real use; the host permission stands in for it.
//  - Gecko only: an empty ui/blank.html, the extension page the test uses to
//    call extension APIs (Firefox gives WebDriver no handle on the event page).
// Nothing else is changed.

import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { startMock, createMockState, approveDevice, phoneDecide, expireAccessTokens } from '../mock-server.js';
import { buildTarget, zipDir } from '../../build.mjs';
import { launchChromium } from './driver-chromium.js';
import { launchGecko } from './driver-gecko.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function newest(dir, re, rel) {
  try {
    const hits = readdirSync(dir).filter((n) => re.test(n)).sort().reverse();
    for (const h of hits) { const p = path.join(dir, h, rel); if (existsSync(p)) return p; }
  } catch {}
  return null;
}
const OPT = path.join(homedir(), '.local/opt');
const BROWSERS = {
  chromium: { family: 'chromium', bin: () => null },
  chrome: { family: 'chromium', bin: () => process.env.CHROME_BIN || newest(OPT, /^chrome-for-testing-/, 'chrome') },
  brave: { family: 'chromium', bin: () => process.env.BRAVE_BIN || (existsSync('/usr/bin/brave-browser') ? '/usr/bin/brave-browser' : null) },
  firefox: { family: 'gecko', bin: () => process.env.FIREFOX_BIN || newest(OPT, /^firefox-/, 'firefox') },
  zen: { family: 'gecko', bin: () => process.env.ZEN_BIN || newest(OPT, /^zen-/, 'zen') },
};
const geckodriverBin = () => process.env.GECKODRIVER || newest(OPT, /^geckodriver-/, 'geckodriver');

const TEST_HOSTS = ['http://localhost/*', 'http://127.0.0.1/*'];
// Firefox event-page idle timeout for this run (default 30 s). Shorter than
// the default, longer than the 20 s keepalive tick.
const GECKO_IDLE_MS = 25000;

async function launch(name, work) {
  const b = BROWSERS[name];
  if (!b) throw new Error('unknown browser ' + name);
  const bin = b.bin();
  if (b.family === 'chromium') {
    if (name !== 'chromium' && !bin) return { skip: `${name} not installed` };
    const { out } = buildTarget('chromium', {
      out: path.join(work, 'ext'),
      manifestEdit: (m) => { m.host_permissions.push(...TEST_HOSTS); },
    });
    return launchChromium({ extDir: out, work, executablePath: bin || undefined, label: name });
  }
  const gd = geckodriverBin();
  if (!bin) return { skip: `${name} not installed` };
  if (!gd) return { skip: 'geckodriver not installed (set GECKODRIVER)' };
  const { out, manifest } = buildTarget('firefox', {
    out: path.join(work, 'ext'),
    manifestEdit: (m) => { m.host_permissions.push(...TEST_HOSTS); },
  });
  writeFileSync(path.join(out, 'ui/blank.html'), '<!doctype html><meta charset="utf-8"><title>test</title>\n');
  const xpi = path.join(work, 'test.xpi');
  writeFileSync(xpi, zipDir(out));
  return launchGecko({
    xpi, addonId: manifest.browser_specific_settings.gecko.id, binary: bin, geckodriver: gd, work, label: name,
    idleTimeoutMs: GECKO_IDLE_MS,
    extraPrefs: { 'app.normandy.enabled': false, 'messaging-system.rsexperimentloader.enabled': false, 'datareporting.healthreport.uploadEnabled': false, 'toolkit.telemetry.enabled': false },
  });
}

// ---- the scenario (same steps for every browser) -----------------------------

async function scenario(d, mock, step) {
  const { state } = mock;
  const A = `http://localhost:${mock.sitePort}`;
  const B = `http://127.0.0.1:${mock.sitePort}`;
  const SECRET_MANUAL = 'correct-horse-battery-' + Math.random().toString(36).slice(2, 8);
  const SECRET_TYPED = 'typed-on-the-page-' + Math.random().toString(36).slice(2, 8);
  const gecko = d.extBase.startsWith('moz-extension:');
  const ext = (p) => d.extBase + p;
  let seq = 0;
  const login = (origin) => `${origin}/login.html?p=${++seq}`; // unique URL -> tab lookup

  const waitText = (page, sel, re, timeout = 15000) =>
    page.waitFn(([s, src]) => new RegExp(src).test(document.querySelector(s)?.textContent || ''), [sel, re.source], timeout);
  const waitVisible = (page, sel, timeout = 15000) =>
    page.waitFn((s) => { const el = document.querySelector(s); return !!(el && el.getClientRects().length); }, sel, timeout);
  const isVisible = (page, sel) => page.eval((s) => { const el = document.querySelector(s); return !!(el && el.getClientRects().length); }, sel);
  const inputValue = (page, sel) => page.eval((s) => document.querySelector(s).value, sel);
  const text = (page, sel) => page.eval((s) => document.querySelector(s).textContent, sel);

  async function tabIdOf(page) {
    const url = await page.url();
    const id = await d.extEval(async (u) => {
      const api = globalThis.browser ?? globalThis.chrome;
      const t = (await api.tabs.query({})).find((x) => x.url === u);
      return t ? t.id : null;
    }, url);
    assert.equal(typeof id, 'number', 'tab found for ' + url);
    return id;
  }
  async function openPopupFor(page) {
    const id = await tabIdOf(page);
    return { pop: await d.newPage(ext(`ui/popup.html?tab=${id}`)), id };
  }
  const storageDump = () => d.extEval(async () => {
    const api = globalThis.browser ?? globalThis.chrome;
    return { local: await api.storage.local.get(null), session: await api.storage.session.get(null) };
  });

  await step('point the extension at the mock API (options page)', async () => {
    const opt = await d.newPage(ext('ui/options.html'));
    await opt.fill('#base', mock.apiBase);
    await opt.click('button[type=submit]');
    await waitText(opt, '#msg', /Using http:\/\/127\.0\.0\.1/);
    await opt.close();
  });

  await step('pair through the device flow (mock approval)', async () => {
    const pop = await d.newPage(ext('ui/popup.html'));
    await pop.click('#pair-btn');
    await pop.waitFn(() => !!document.querySelector('#user-code')?.textContent);
    const code = (await text(pop, '#user-code')).trim();
    assert.match(code, /^[0-9A-F]{4}-[0-9A-F]{4}$/);
    assert.equal(await pop.eval(() => document.querySelector('#pair-link').getAttribute('href')), 'https://demipass.com/device?code=' + code);
    const devReq = [...state.device.values()].find((x) => x.user_code === code);
    assert.equal(devReq.scope, 'transact');
    assert.match(devReq.label, /^DemiPass browser extension/);
    console.log(`    pairing label: ${devReq.label}`);
    await approveDevice(state, code);
    await waitVisible(pop, '#signout');
    await pop.close();
  });

  await step('tokens: access in storage.session, refresh sealed in storage.local', async () => {
    const s = await storageDump();
    assert.ok(s.session.dp_access, 'access token in session');
    assert.ok(s.local.dp_refresh_sealed && s.local.dp_refresh_sealed.ct, 'sealed refresh in local');
    assert.equal(JSON.stringify(s.local).includes('dpr_'), false, 'no plaintext refresh token in storage.local');
    assert.equal(JSON.stringify(s.session).includes('dpr_'), false);
  });

  if (gecko) {
    await step('Firefox site access: off -> popup says so -> "Allow on this site" / "Allow on all sites" grant it', async () => {
      // Firefox lets the person revoke host access in about:addons. Do that here.
      await d.extEval(async (hosts) => {
        const api = globalThis.browser;
        await api.permissions.remove({ origins: ['<all_urls>', ...hosts] });
      }, TEST_HOSTS);
      const page = await d.newPage(login(A));
      await sleep(500);
      await d.grantActiveTab(page); // = the person clicks the DemiPass toolbar button
      // Tab URLs are hidden without host access: take the most recently used other tab.
      const lastTab = () => d.extEval(async () => {
        const api = globalThis.browser;
        const self = (await api.tabs.getCurrent()).id;
        return (await api.tabs.query({})).filter((t) => t.id !== self).sort((a, b) => b.lastAccessed - a.lastAccessed)[0].id;
      });
      const pop = await d.newPage(ext(`ui/popup.html?tab=${await lastTab()}`));
      await waitVisible(pop, '#access');
      assert.match(await text(pop, '#access-text'), /Site access is off for localhost/);
      assert.equal(await isVisible(pop, '#access-site'), true);
      assert.equal(await isVisible(pop, '#access-all'), true);
      await pop.click('#access-site');
      await waitText(pop, '#access-msg', /Access granted/);
      await pop.waitFn(() => document.querySelector('#access').hidden);
      const perms = await d.extEval(async () => (await globalThis.browser.permissions.getAll()).origins);
      assert.ok(perms.includes('http://localhost/*'), perms.join(','));
      assert.equal(perms.includes('<all_urls>'), false);
      // After the grant the popup re-reads the page: the login form is found
      // in the tab that was already open (the detector is injected on demand).
      await waitVisible(pop, '#add');
      await pop.close();
      const pageB = await d.newPage(login(B));
      await sleep(500);
      await d.grantActiveTab(pageB);
      const pop2 = await d.newPage(ext(`ui/popup.html?tab=${await lastTab()}`));
      await waitVisible(pop2, '#access');
      assert.match(await text(pop2, '#access-text'), /Site access is off for 127\.0\.0\.1/);
      await pop2.click('#access-all');
      await waitText(pop2, '#access-msg', /Access granted/);
      await pop2.waitFn(() => document.querySelector('#access').hidden);
      const perms2 = await d.extEval(async () => (await globalThis.browser.permissions.getAll()).origins);
      assert.ok(perms2.includes('<all_urls>'), perms2.join(','));
      await pop2.close(); await pageB.close(); await page.close();
    });
  }

  const pageA = await d.newPage(login(A));

  let ref;
  await step('"Add for this site" stores a password bound to the page origin', async () => {
    const { pop } = await openPopupFor(pageA);
    await waitVisible(pop, '#add');
    assert.equal(await isVisible(pop, '#access'), false, 'no site-access banner when access is granted');
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
    assert.equal(await inputValue(pop, '#add-password'), '', 'password box cleared');
    await pop.close();
  });

  const fillBtn = () => `#entry-list button[data-ref="${ref}"]`;

  await step('fill on the bound origin: phone approval, then fields filled', async () => {
    const { pop } = await openPopupFor(pageA);
    await pop.click(fillBtn());
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    assert.equal(await inputValue(pageA, '#pass'), '', 'nothing filled before approval');
    const [reqId, f] = [...state.fills].find(([, x]) => x.status === 'pending');
    assert.equal(f.origin, A);
    assert.equal(await phoneDecide(mock.apiBase, state, reqId, 'approve'), 200);
    await waitText(pop, '#fill-msg', /^Filled\.$/);
    assert.equal(await inputValue(pageA, '#user'), 'me@example.com');
    assert.equal(await inputValue(pageA, '#pass'), SECRET_MANUAL);
    assert.equal(await inputValue(pageA, '#q'), '', 'search box untouched');
    await pop.close();
  });

  await step('the page cannot see the document nonce the fill is bound to', async () => {
    const seen = await pageA.eval(() => typeof window.__demipassDoc + '/' + typeof window.DemiPassFormDetect);
    assert.equal(seen, 'undefined/undefined');
  });

  await step('denied on the phone: nothing filled', async () => {
    const page = await d.newPage(login(A));
    const { pop } = await openPopupFor(page);
    await pop.click(fillBtn());
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    const [reqId] = [...state.fills].find(([, x]) => x.status === 'pending');
    await phoneDecide(mock.apiBase, state, reqId, 'deny');
    await waitText(pop, '#fill-msg', /Denied/);
    assert.equal(await inputValue(page, '#pass'), '');
    await pop.close(); await page.close();
  });

  await step('other origin: no candidates listed, and a forced fill is refused by origin binding', async () => {
    const pageB = await d.newPage(login(B));
    const { pop, id } = await openPopupFor(pageB);
    await waitText(pop, '#entry-list', /No entries are bound to this site/);
    // Bypass the UI: ask the background to fill the localhost-bound entry into this 127.0.0.1 page.
    const out = await pop.eval(async ([tabId, r]) => {
      const api = globalThis.browser ?? globalThis.chrome;
      const ctx = await api.runtime.sendMessage({ type: 'ui:context', tabId });
      const t = ctx.targets[0];
      const f = await api.runtime.sendMessage({ type: 'ui:fill', tabId, docKey: t.docKey, ref: r });
      for (let i = 0; i < 50; i++) {
        const s = await api.runtime.sendMessage({ type: 'ui:fillStatus', fillId: f.fillId });
        if (!['requesting', 'pending', 'approved', 'filling'].includes(s.state)) return { origin: t.origin, ...s };
        await new Promise((res) => setTimeout(res, 100));
      }
      return { state: 'timeout' };
    }, [id, ref]);
    assert.equal(out.origin, B, 'background used the browser-reported origin');
    assert.equal(out.state, 'refused');
    const call = state.calls.filter((c) => c.path === '/api/blindkey/fill/request').pop();
    assert.equal(call.status, 403);
    assert.equal(call.meta.origin, B);
    assert.equal(await inputValue(pageB, '#pass'), '');
    await pop.close(); await pageB.close();
  });

  // The abandoned request is withdrawn (denied by this session), so the
  // phone does not keep a dead card and the 20-waiting limit is not eaten.
  async function assertWithdrawn(reqId) {
    const end = Date.now() + 8000;
    while (state.fills.get(reqId).status === 'pending' && Date.now() < end) await sleep(100);
    assert.equal(state.fills.get(reqId).status, 'withdrawn', 'withdrawn from the phone');
    assert.ok(state.calls.some((c) => c.path === '/api/blindkey/fill/withdraw' && c.meta.request_id === reqId && c.status === 200), 'withdrawn by request_id');
    assert.equal(state.calls.some((c) => c.path === '/api/blindkey/fill/redeem' && c.meta.request_id === reqId && c.status === 200), false, 'never redeemed');
  }

  await step('page navigates to another origin while waiting: nothing filled, request withdrawn from the phone', async () => {
    const page = await d.newPage(login(A));
    const { pop } = await openPopupFor(page);
    await pop.click(fillBtn());
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    const [reqId] = [...state.fills].find(([, x]) => x.status === 'pending');
    await page.goto(login(B));
    await waitText(pop, '#fill-msg', /page changed/);
    await assertWithdrawn(reqId);
    assert.equal(await inputValue(page, '#pass'), '');
    await pop.close(); await page.close();
  });

  await step('page reloads (same origin, new document) while waiting: nothing filled, request withdrawn', async () => {
    const page = await d.newPage(login(A));
    const { pop } = await openPopupFor(page);
    await pop.click(fillBtn());
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    const [reqId] = [...state.fills].find(([, x]) => x.status === 'pending');
    await page.goto(await page.url()); // same URL, same origin: a new document
    await waitText(pop, '#fill-msg', /page changed/);
    await assertWithdrawn(reqId);
    assert.equal(await inputValue(page, '#pass'), '');
    await pop.close(); await page.close();
  });

  // Audit P1: same document, so an approved fill must still land.
  const sameDocCases = [
    ['pushState', '/spa.html', (pg) => pg.eval(() => { window.pushNow(); return true; })],
    ['location.hash change', '/spa.html', (pg) => pg.eval(() => { location.hash = 'step2'; return true; })],
    ['a cross-origin ad iframe reloading', '/ads.html', (pg) => pg.eval(() => { window.rotate(); return true; })],
  ];
  for (const [what, pathName, during] of sameDocCases) {
    await step(`${what} while waiting (same document): the approved fill still lands`, async () => {
      const page = await d.newPage(`${A}${pathName}?p=${++seq}`);
      const { pop } = await openPopupFor(page);
      await pop.click(fillBtn());
      await waitText(pop, '#fill-msg', /Approve on your phone/);
      await during(page);
      await sleep(2500); // a few polls (and liveness checks) while it happens
      const [reqId] = [...state.fills].find(([, x]) => x.status === 'pending');
      assert.equal(await phoneDecide(mock.apiBase, state, reqId, 'approve'), 200);
      await waitText(pop, '#fill-msg', /^Filled\.$/);
      assert.equal(await inputValue(page, '#pass'), SECRET_MANUAL);
      await pop.close(); await page.close();
    });
  }

  await step('a page-dispatched (untrusted) pagehide does not stop a fill (audit N4)', async () => {
    const page = await d.newPage(`${A}/forge2.html?p=${++seq}`);
    const { pop } = await openPopupFor(page);
    await pop.click(fillBtn());
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    await page.eval(() => { window.fakeGone(); return true; });
    await sleep(2500);
    const [reqId] = [...state.fills].find(([, x]) => x.status === 'pending');
    assert.equal(await phoneDecide(mock.apiBase, state, reqId, 'approve'), 200);
    await waitText(pop, '#fill-msg', /^Filled\.$/);
    await pop.close(); await page.close();
  });

  await step('two tabs ask for the same login; tab 1 expires -> tab 2\'s request is untouched and fills (audit N5)', async () => {
    const p1 = await d.newPage(`${A}/stay.html?t=1&p=${++seq}`);
    const p2 = await d.newPage(`${A}/stay.html?t=2&p=${++seq}`);
    const { pop: pop1 } = await openPopupFor(p1);
    await pop1.click(fillBtn());
    await waitText(pop1, '#fill-msg', /Approve on your phone/);
    const [r1] = [...state.fills].find(([, x]) => x.status === 'pending');
    const { pop: pop2 } = await openPopupFor(p2);
    await pop2.click(fillBtn());
    await waitText(pop2, '#fill-msg', /Approve on your phone/);
    const [r2] = [...state.fills].find(([k, x]) => x.status === 'pending' && k !== r1);
    state.fills.get(r1).expires = Date.now() - 1; // the person let tab 1's card run out
    await waitText(pop1, '#fill-msg', /expired/i);
    await sleep(1500);
    assert.equal(state.fills.get(r2).status, 'pending', 'tab 2 still waiting');
    assert.equal(state.calls.some((c) => c.path === '/api/blindkey/fill/withdraw' && (c.meta.request_id === r2 || c.meta.request_id === r1)), false, 'an expired request is not withdrawn, and tab 2\'s never is');
    assert.equal(await phoneDecide(mock.apiBase, state, r2, 'approve'), 200);
    await waitText(pop2, '#fill-msg', /^Filled\.$/);
    assert.equal(await inputValue(p2, '#pass'), SECRET_MANUAL);
    assert.equal(await inputValue(p1, '#pass'), '');
    await pop1.close(); await pop2.close(); await p1.close(); await p2.close();
  });

  await step('fill into a cross-origin iframe (frame target, its own origin binding)', async () => {
    state.secrets.set('DP-PWD-frame-1', { name: 'frame-login', value: 'frame-secret-value', secret_type: 'password', login: 'f@example.com', origins: [B] });
    const page = await d.newPage(`${A}/top-frame.html?p=${++seq}`);
    await sleep(800);
    const { pop } = await openPopupFor(page);
    const btn = '#entry-list button[data-ref="DP-PWD-frame-1"]';
    await waitVisible(pop, btn);
    assert.match(await pop.eval(() => document.querySelector('#entry-list').textContent), /in frame http:\/\/127\.0\.0\.1/);
    await pop.click(btn);
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    const [reqId, f] = [...state.fills].find(([, x]) => x.status === 'pending');
    assert.equal(f.origin, B, 'requested for the frame\'s origin');
    await phoneDecide(mock.apiBase, state, reqId, 'approve');
    await waitText(pop, '#fill-msg', /^Filled\.$/);
    assert.equal(await inputValue(page, '#pass'), '', 'the top frame is untouched');
    const inFrame = await d.frameInputValue(page, '#f', '#pass');
    assert.equal(inFrame, 'frame-secret-value');
    await pop.close(); await page.close();
  });

  await step('"Add for this site": the tab moved to another origin before Add -> refused, nothing stored (audit P4)', async () => {
    const page = await d.newPage(login(A));
    const { pop } = await openPopupFor(page);
    await waitVisible(pop, '#add');
    await pop.fill('#add-name', 'race-probe');
    await pop.fill('#add-login', 'me@example.com');
    await pop.fill('#add-password', 'typed-for-site-A');
    await page.goto(login(B));
    await sleep(800);
    await pop.click('#add-form button[type=submit]');
    await waitText(pop, '#add-msg', /not the site shown/);
    assert.equal([...state.secrets.values()].some((x) => x.name === 'race-probe'), false);
    await pop.close(); await page.close();
  });

  await step('"Add for this site" under an existing name asks first; Replace keeps its other bound origins', async () => {
    state.secrets.set('DP-PWD-shared-1', { name: 'shared-login', value: 'old-value', secret_type: 'password', login: 'me@example.com', origins: ['https://other.example'] });
    const page = await d.newPage(login(A));
    const { pop } = await openPopupFor(page);
    await waitVisible(pop, '#add');
    await pop.fill('#add-name', 'shared-login');
    await pop.fill('#add-password', 'new-value');
    const stores = () => state.calls.filter((c) => c.path === '/api/blindkey/store').length;
    const before = stores();
    await pop.click('#add-form button[type=submit]');
    await waitText(pop, '#add-msg', /already exists in your vault/);
    assert.equal(await text(pop, '#add-submit'), 'Replace');
    assert.equal(stores(), before, 'nothing stored before Replace');
    await pop.click('#add-form button[type=submit]');
    await waitText(pop, '#add-msg', /Replaced/);
    const sec = state.secrets.get('DP-PWD-shared-1');
    assert.equal(sec.value, 'new-value');
    assert.deepEqual(sec.origins.sort(), [A, 'https://other.example'].sort(), 'origins merged, not replaced');
    await pop.close(); await page.close();
  });

  await step('a name with surrounding spaces still matches the existing one: one Replace replaces (audit N6)', async () => {
    const page = await d.newPage(login(A));
    const { pop } = await openPopupFor(page);
    await waitVisible(pop, '#add');
    await pop.fill('#add-name', '  shared-login ');
    await pop.fill('#add-password', 'newer-value');
    await pop.click('#add-submit');
    await waitText(pop, '#add-msg', /“shared-login” already exists/);
    await pop.click('#add-submit');
    await waitText(pop, '#add-msg', /Replaced “shared-login”/);
    assert.equal(state.secrets.get('DP-PWD-shared-1').value, 'newer-value');
    await pop.close(); await page.close();
  });

  await step('Replace stored the value but adding this site failed -> says exactly that', async () => {
    const page = await d.newPage(`${B}/login.html?p=${++seq}`);
    const { pop } = await openPopupFor(page);
    await waitVisible(pop, '#add');
    await pop.fill('#add-name', 'shared-login');
    await pop.fill('#add-password', 'value-from-b');
    await pop.click('#add-submit');
    await waitText(pop, '#add-msg', /already exists/);
    state.failOrigins = true;
    try {
      await pop.click('#add-submit');
      await waitText(pop, '#add-msg', /Password replaced in “shared-login”, but this site wasn't added to it\. Try again\./);
    } finally { state.failOrigins = false; }
    const sec = state.secrets.get('DP-PWD-shared-1');
    assert.equal(sec.value, 'value-from-b');
    assert.equal(sec.origins.includes(B), false);
    await pop.close(); await page.close();
  });

  await step('a page-forged login (script value + requestSubmit, synthetic events) gets no SAVE prompt (audit P2)', async () => {
    const page = await d.newPage(`${A}/forge.html?p=${++seq}`);
    await sleep(500);
    await page.eval(() => { window.forge('attacker-chosen-1'); return true; });
    await page.eval(() => { window.forgeEvents('attacker-chosen-2'); return true; });
    await sleep(500);
    const tabId = await tabIdOf(page);
    const badge = await d.extEval(async (t) => (globalThis.browser ?? globalThis.chrome).action.getBadgeText({ tabId: t }), tabId);
    assert.equal(badge, '');
    const { pop } = await openPopupFor(page);
    await waitVisible(pop, '#add');
    assert.equal(await isVisible(pop, '#capture'), false);
    await pop.close(); await page.close();
  });

  await step('execCommand(insertText) + requestSubmit, and another manager\'s script fill + a real click: no SAVE prompt (audit N1, N2)', async () => {
    const page = await d.newPage(`${A}/forge2.html?p=${++seq}`);
    await sleep(500);
    const v = await page.eval(() => window.forge2('attacker-chosen-3'));
    assert.equal(v, 'attacker-chosen-3', 'the forged value really is in the field');
    await page.eval(() => { window.pmFill('pm-filled-value'); return true; });
    await page.click('button[type=submit]'); // a real click on Sign in
    await sleep(600);
    const tabId = await tabIdOf(page);
    const badge = await d.extEval(async (t) => (globalThis.browser ?? globalThis.chrome).action.getBadgeText({ tabId: t }), tabId);
    assert.equal(badge, '');
    await page.close();
  });

  const noBadge = async (page) => {
    const tabId = await tabIdOf(page);
    return d.extEval(async (t) => (globalThis.browser ?? globalThis.chrome).action.getBadgeText({ tabId: t }), tabId);
  };

  await step('typing in a search box while a 1px password field steals focus, then execCommand + requestSubmit: no SAVE prompt (audit N8)', async () => {
    const page = await d.newPage(`${A}/piggy.html?p=${++seq}`);
    await sleep(500);
    await page.type('#q', 'weather tomorrow');
    await sleep(600);
    assert.equal(await page.eval(() => window.result), 'attacker-chosen', 'the page did run its swap + submit');
    assert.equal(await noBadge(page), '');
    await page.close();
  });

  for (const [what, pathName] of [['on a timer', '/swap.html'], ['nested inside the person\'s own keystroke', '/swap-sync.html']]) {
    await step(`the page swaps the typed password (execCommand ${what}) before the person submits: nothing offered (audit N8b)`, async () => {
      const page = await d.newPage(`${A}${pathName}?p=${++seq}`);
      await sleep(500);
      await page.type('#user', 'me@example.com');
      await page.type('#pass', 'my-real-password');
      await sleep(300);
      assert.notEqual(await inputValue(page, '#pass'), 'my-real-password', 'the page did swap it');
      await page.click('button[type=submit]');
      await sleep(600);
      assert.equal(await noBadge(page), '');
      await page.close();
    });
  }

  await step('typed while a show-password toggle had the field as text, then hidden again: the save is offered (audit N3)', async () => {
    const page = await d.newPage(`${A}/toggle.html?p=${++seq}`);
    await sleep(500);
    await page.type('#user', 'toggle@example.com');
    await page.click('#eye');
    await page.type('#pass', 'typed-while-visible');
    await page.click('#eye');
    await page.click('button[type=submit]');
    await sleep(600);
    const { pop } = await openPopupFor(page);
    await waitVisible(pop, '#capture');
    assert.equal(await text(pop, '#cap-user'), 'toggle@example.com');
    await pop.click('#cap-dismiss');
    await pop.close(); await page.close();
  });

  // Sends that carry no sign-in words still offer the save (round 3 false negatives).
  const savedOffer = async (page, user) => {
    await sleep(300);
    assert.equal(await noBadge(page), 'SAVE');
    const { pop } = await openPopupFor(page);
    await waitVisible(pop, '#capture');
    assert.equal(await text(pop, '#cap-user'), user);
    await pop.click('#cap-dismiss');
    await pop.close();
  };
  await step('an icon-only button in the form (no label) offers the save', async () => {
    const page = await d.newPage(`${A}/icon-btn.html?p=${++seq}`);
    await sleep(500);
    await page.type('#user', 'icon@example.com');
    await page.type('#pass', 'typed-icon-button');
    await page.clickAndWaitUrl('#go', /\/done$/);
    await savedOffer(page, 'icon@example.com');
    await page.close();
  });
  await step('an unlabeled role=button outside any form offers the save', async () => {
    const page = await d.newPage(`${A}/outside-btn.html?p=${++seq}`);
    await sleep(500);
    await page.type('#user', 'outside-user');
    await page.type('#pass', 'typed-outside-button');
    await page.clickAndWaitUrl('#go', /\/done$/);
    await savedOffer(page, 'outside-user');
    await page.close();
  });
  await step('a page with no form: Enter in the username field offers the save', async () => {
    const page = await d.newPage(`${A}/formless.html?p=${++seq}`);
    await sleep(500);
    await page.type('#pass', 'typed-formless');
    await page.type('#user', 'formless@example.com');
    await page.pressAndWaitUrl('#user', 'Enter', /\/done$/);
    await savedOffer(page, 'formless@example.com');
    await page.close();
  });
  await step('multi-step login: the username sent on step one names the save made on step two', async () => {
    const page = await d.newPage(`${A}/step1.html?p=${++seq}`);
    await sleep(500);
    await page.type('#user', 'twostep@example.com');
    await page.clickAndWaitUrl('button[type=submit]', /\/step2\.html/);
    await sleep(500);
    await page.type('#pass', 'typed-on-step-two');
    await page.clickAndWaitUrl('button[type=submit]', /\/done$/);
    await savedOffer(page, 'twostep@example.com');
    await page.close();
  });
  await step('the show-password toggle is not a send: no save offered by clicking it', async () => {
    const page = await d.newPage(`${A}/toggle.html?p=${++seq}`);
    await sleep(500);
    await page.type('#user', 'toggle2@example.com');
    await page.type('#pass', 'typed-then-peek');
    await page.click('#eye');
    await sleep(500);
    assert.equal(await noBadge(page), '');
    await page.close();
  });

  await step('a cross-origin iframe cannot replace the top frame\'s pending save (audit P3)', async () => {
    const page = await d.newPage(`${A}/top-frame.html?p=${++seq}`);
    await sleep(800);
    await page.type('#user', 'alice@example.com');
    await page.type('#pass', 'typed-by-the-person');
    await page.click('button[type=submit]'); // the page keeps the person here
    await sleep(500);
    await page.eval(() => { window.forgeInFrame(); return true; });
    await sleep(800);
    const { pop } = await openPopupFor(page);
    await waitVisible(pop, '#capture');
    assert.equal(await text(pop, '#cap-origin'), A);
    assert.equal(await text(pop, '#cap-user'), 'alice@example.com');
    await pop.click('#cap-dismiss');
    await pop.close(); await page.close();
  });

  async function saveOnSubmit(page, user, secret) {
    await page.type('#user', user);
    await page.type('#pass', secret);
    const storesBefore = state.calls.filter((c) => c.path === '/api/blindkey/store').length;
    await page.clickAndWaitUrl('button[type=submit]', /\/done$/);
    await sleep(300);
    assert.equal(state.calls.filter((c) => c.path === '/api/blindkey/store').length, storesBefore, 'no store before Save');
    const tabId = await tabIdOf(page);
    const badge = await d.extEval(async (t) => (globalThis.browser ?? globalThis.chrome).action.getBadgeText({ tabId: t }), tabId);
    assert.equal(badge, 'SAVE');
    return tabId;
  }
  async function saveFromPopup(page, user, secret) {
    const { pop } = await openPopupFor(page);
    await waitVisible(pop, '#capture');
    assert.equal(await text(pop, '#cap-origin'), A);
    assert.equal(await text(pop, '#cap-user'), user);
    assert.equal(await inputValue(pop, '#cap-name'), `localhost:${mock.sitePort} (${user})`);
    await pop.click('#cap-save');
    await waitText(pop, '#cap-msg', /Saved as/);
    const s = [...state.secrets.values()].find((x) => x.login === user);
    assert.equal(s.value, secret);
    assert.equal(s.secret_type, 'password');
    assert.deepEqual(s.origins, [A]);
    assert.equal((await pop.content()).includes(secret), false, 'popup never received the value');
    await pop.close();
  }

  await step('save on submit: typed login reaches /store only after Save in the popup', async () => {
    const page = await d.newPage(login(A));
    await saveOnSubmit(page, 'typed@example.com', SECRET_TYPED);
    await saveFromPopup(page, 'typed@example.com', SECRET_TYPED);
    await page.close();
  });

  await step('save on submit replacing a saved login keeps every origin it was bound to (audit: capture path)', async () => {
    state.secrets.set('DP-PWD-multi-1', { name: 'multi-site', value: 'old-multi', secret_type: 'password', login: 'multi@example.com', origins: [A, 'https://other.example'] });
    const page = await d.newPage(login(A));
    await saveOnSubmit(page, 'multi@example.com', 'new-multi-value');
    const { pop } = await openPopupFor(page);
    await waitVisible(pop, '#capture');
    assert.match(await text(pop, '#cap-existing'), /Replaces the saved password in “multi-site”/);
    assert.equal(await inputValue(pop, '#cap-name'), 'multi-site');
    await pop.click('#cap-save');
    await waitText(pop, '#cap-msg', /Saved as “multi-site”/);
    const sec = state.secrets.get('DP-PWD-multi-1');
    assert.equal(sec.value, 'new-multi-value');
    assert.deepEqual(sec.origins.sort(), [A, 'https://other.example'].sort());
    await pop.close(); await page.close();
  });

  await step('saving under a rotated name: the server\'s 409 is shown in full, the capture is kept, "Save to <current>" saves there (audit round 3)', async () => {
    const user = 'rot@example.com';
    const oldName = `localhost:${mock.sitePort} (${user})`;
    const current = oldName + '_v2';
    state.rotated = new Map([[oldName, current]]);
    state.secrets.set('DP-PWD-rot-2', { name: current, value: 'old-rotated', secret_type: 'password', login: user, origins: ['https://other.example'] });
    try {
      const page = await d.newPage(login(A));
      await saveOnSubmit(page, user, 'new-after-rotation');
      const { pop } = await openPopupFor(page);
      await waitVisible(pop, '#capture');
      assert.equal(await inputValue(pop, '#cap-name'), oldName);
      await pop.click('#cap-save');
      await waitText(pop, '#cap-msg', new RegExp(`its current version is “${current.replace(/[().]/g, '\\$&')}”`));
      assert.equal(await inputValue(pop, '#cap-name'), current);
      assert.equal(await text(pop, '#cap-save'), `Save to “${current}”`);
      assert.equal(state.secrets.get('DP-PWD-rot-2').value, 'old-rotated', 'nothing stored yet');
      await pop.click('#cap-save'); // the pending capture is still there
      await waitText(pop, '#cap-msg', /Saved as/);
      const sec = state.secrets.get('DP-PWD-rot-2');
      assert.equal(sec.value, 'new-after-rotation');
      assert.deepEqual(sec.origins.sort(), [A, 'https://other.example'].sort());
      await pop.close(); await page.close();
    } finally { state.rotated = null; }
  });

  await step('an API base written to storage.local is ignored after a background restart; no request goes there (audit P5)', async () => {
    const seen = [];
    const evil = await new Promise((r) => { const sv = http.createServer((req, res) => { seen.push(req.url); req.resume(); res.writeHead(500, { 'Access-Control-Allow-Origin': '*' }); res.end('{}'); }); sv.listen(0, '127.0.0.1', () => r(sv)); });
    try {
      const EVIL = `http://127.0.0.1:${evil.address().port}`;
      // storage.local is what a content script (or a compromised renderer) can write.
      await d.extEval(async (u) => { await (globalThis.browser ?? globalThis.chrome).storage.local.set({ dp_api_base: u }); return true; }, EVIL);
      await d.restartBackground();
      await sleep(500);
      const { pop } = await openPopupFor(pageA);
      await waitVisible(pop, fillBtn()); // still paired, still talking to the mock
      assert.equal(await text(pop, '#dev'), `Dev server: ${mock.apiBase}`);
      await pop.close();
      assert.deepEqual(seen, [], 'nothing was sent to the base from storage.local');
      const local = (await storageDump()).local;
      assert.equal('dp_api_base' in local, false, 'the stray key is deleted');
    } finally { evil.close(); }
  });

  if (d.supportsIdleControl) {
    const bgStart = () => d.extEval(async () => (await globalThis.browser.runtime.getBackgroundPage()).performance.timeOrigin);
    const idle = d.idleTimeoutMs;
    await step(`Firefox event page: unloads after ${idle / 1000} s idle and comes back paired`, async () => {
      const t0 = await bgStart();
      await sleep(idle * 2 + 15000); // keepalive's last tick (<= 20 s) + idle timeout, twice over
      const t1 = await bgStart();
      assert.ok(t1 > t0, `background restarted (${t0} -> ${t1})`);
      const { pop } = await openPopupFor(pageA);
      await waitVisible(pop, fillBtn()); // tokens survived the restart (storage.session + sealed refresh)
      await pop.close();
    });
    await step(`Firefox event page: a pending save keeps it alive past ${(idle * 3) / 1000} s, then saves`, async () => {
      const page = await d.newPage(login(A));
      await saveOnSubmit(page, 'idle@example.com', SECRET_TYPED + '-idle');
      const t0 = await bgStart();
      await sleep(idle * 3);
      assert.equal(await bgStart(), t0, 'background was not restarted while the save was pending');
      await saveFromPopup(page, 'idle@example.com', SECRET_TYPED + '-idle');
      await page.close();
    });
  }

  await step('no value in extension storage or any console output (console capture checked with a canary)', async () => {
    const canary = 'dp-console-canary-' + Math.random().toString(36).slice(2);
    await d.extEval((c) => { console.log(c); return true; }, canary);
    const pageCanary = await d.newPage(login(A));
    await pageCanary.eval((c) => { console.log(c + '-page'); return true; }, canary);
    await sleep(500);
    await pageCanary.close();
    assert.ok(d.logs.some((l) => l.includes(canary + '-page')), 'page console is captured');
    const bgCaptured = d.logs.some((l) => l.includes(canary) && !l.includes(canary + '-page'));
    if (!bgCaptured) console.log('    note: extension-context console not captured by this driver');
    const s = JSON.stringify(await storageDump());
    for (const v of [SECRET_MANUAL, SECRET_TYPED]) {
      assert.equal(s.includes(v), false);
      assert.equal(d.logs.some((l) => l.includes(v)), false);
    }
  });

  const pendingFills = () => [...state.fills].filter(([, x]) => x.status === 'pending');

  await step('token expiring within 5 minutes is refreshed before fill/request', async () => {
    state.accessTtlSec = 200; // outside the 60 s skew, inside the 5 min fill window
    expireAccessTokens(state); // next call refreshes and gets a 200 s token
    const page = await d.newPage(login(A));
    const { pop } = await openPopupFor(page);
    await waitVisible(pop, fillBtn());
    const mark = state.calls.length;
    await pop.click(fillBtn());
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    const seqs = state.calls.slice(mark).map((c) => `${c.path} ${c.status}`);
    const iReq = seqs.indexOf('/api/blindkey/fill/request 201');
    assert.ok(iReq > 0 && seqs[iReq - 1] === '/api/identity/refresh 200', seqs.join(' | '));
    state.accessTtlSec = 3600;
    const [reqId] = pendingFills()[0];
    await phoneDecide(mock.apiBase, state, reqId, 'approve');
    await waitText(pop, '#fill-msg', /^Filled\.$/);
    assert.equal(await inputValue(page, '#pass'), SECRET_MANUAL);
    await pop.close(); await page.close();
  });

  await step('refresh while waiting orphans the request (404): extension asks again, shows "Approve on your phone…", fills', async () => {
    const page = await d.newPage(login(A));
    const { pop } = await openPopupFor(page);
    await pop.click(fillBtn());
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    const [firstId] = pendingFills()[0];
    const mark = state.calls.length;
    expireAccessTokens(state); // the asking token dies mid-wait: 401 -> refresh -> redeem 404
    await waitText(pop, '#fill-msg', /Approve on your phone… \(new request/);
    const seqs = state.calls.slice(mark).map((c) => `${c.path} ${c.status}`);
    assert.ok(seqs.includes('/api/identity/refresh 200'), seqs.join(' | '));
    assert.ok(seqs.includes('/api/blindkey/fill/redeem 404'), seqs.join(' | '));
    const second = pendingFills().find(([id]) => id !== firstId);
    assert.ok(second, 'a second fill request was made');
    assert.equal(await inputValue(page, '#pass'), '', 'nothing filled yet');
    await phoneDecide(mock.apiBase, state, second[0], 'approve');
    await waitText(pop, '#fill-msg', /^Filled\.$/);
    assert.equal(await inputValue(page, '#pass'), SECRET_MANUAL);
    assert.equal(state.fills.get(firstId).status, 'pending', 'the orphaned request was never redeemed');
    await pop.close(); await page.close();
  });

  await step('refresh rotation: short-lived tokens rotate on each call without losing the session', async () => {
    state.accessTtlSec = 30; // inside the 60 s skew: every call refreshes
    expireAccessTokens(state);
    const before = state.calls.filter((c) => c.path === '/api/identity/refresh' && c.status === 200).length;
    for (let i = 0; i < 4; i++) {
      const { pop } = await openPopupFor(pageA);
      await waitVisible(pop, fillBtn());
      await pop.close();
    }
    const rotations = state.calls.filter((c) => c.path === '/api/identity/refresh' && c.status === 200).length - before;
    assert.ok(rotations >= 4, 'rotations: ' + rotations);
    assert.equal(state.calls.filter((c) => c.path === '/api/identity/refresh' && c.status !== 200).length, 0, 'no failed refresh');
    state.accessTtlSec = 3600;
  });

  if (gecko) {
    await step('Firefox: site access revoked for a frame\'s origin -> fill refused with the reason, no phone card', async () => {
      state.secrets.set('DP-PWD-frame-2', { name: 'frame-login-2', value: 'frame-secret-2', secret_type: 'password', login: 'g@example.com', origins: [B] });
      const page = await d.newPage(`${A}/top-frame.html?p=${++seq}`);
      await sleep(800);
      const { pop } = await openPopupFor(page);
      const btn = '#entry-list button[data-ref="DP-PWD-frame-2"]';
      await waitVisible(pop, btn);
      await d.extEval(async () => { await globalThis.browser.permissions.remove({ origins: ['<all_urls>', 'http://127.0.0.1/*'] }); return true; });
      const requests = () => state.calls.filter((c) => c.path === '/api/blindkey/fill/request').length;
      const before = requests();
      await pop.click(btn);
      await waitText(pop, '#fill-msg', /in a frame from 127\.0\.0\.1.*no access to that site.*Nothing was sent to your phone/);
      assert.equal(requests(), before, 'no fill request, so no phone card');
      await pop.close(); await page.close();
    });
  }

  await step('sign out revokes the refresh token', async () => {
    const pop = await d.newPage(ext('ui/popup.html'));
    await waitVisible(pop, '#signout');
    await pop.click('#signout');
    await waitVisible(pop, '#pair-btn');
    assert.ok(state.calls.some((c) => c.path === '/api/identity/refresh/revoke' && c.status === 200));
    assert.ok([...state.refresh.values()].filter((r) => r.sid !== 'sid_phone').every((r) => r.revoked), 'every extension refresh token revoked');
    const s = await storageDump();
    assert.equal('dp_refresh_sealed' in s.local, false);
    await pop.close();
  });
}

// ---- runner ------------------------------------------------------------------

async function runOne(name) {
  const work = mkdtempSync(path.join(process.env.SMOKE_TMP || tmpdir(), `dp-ext-smoke-${name}-`));
  const results = [];
  let d = null;
  let mock = null;
  try {
    d = await launch(name, work);
    if (d.skip) { console.log(`SKIP ${name}: ${d.skip}`); return { name, skipped: d.skip }; }
    console.log(`\n== ${name}: ${d.version}`);
    mock = await startMock({ state: createMockState({ accessTtlSec: 3600 }) });
    const step = async (title, fn) => {
      try { await fn(); results.push(['PASS', title]); console.log('PASS', title); }
      catch (e) { results.push(['FAIL', title]); console.log('FAIL', title, '\n   ', e && e.message); throw e; }
    };
    await scenario(d, mock, step);
  } catch (e) {
    if (!results.some((r) => r[0] === 'FAIL')) { results.push(['FAIL', 'harness']); console.log('FAIL harness', e && (e.stack || e.message)); }
  } finally {
    if (d && d.close) await d.close().catch(() => {});
    if (mock) await mock.close();
    if (!process.env.SMOKE_KEEP) rmSync(work, { recursive: true, force: true });
  }
  const pass = results.filter((r) => r[0] === 'PASS').length;
  const failed = results.some((r) => r[0] === 'FAIL');
  console.log(`${name}: ${pass}/${results.length} steps passed${failed ? ' (stopped at first failure)' : ''}`);
  return { name, pass, total: results.length, failed, version: d && d.version };
}

const arg = process.argv.find((a) => a.startsWith('--browser='));
const names = (arg ? arg.slice(10) : process.env.SMOKE_BROWSERS || 'chromium').split(',').map((s) => s.trim()).filter(Boolean);
const summary = [];
for (const n of names) summary.push(await runOne(n));
console.log('\nsummary:');
for (const r of summary) console.log(r.skipped ? `  ${r.name}: skipped (${r.skipped})` : `  ${r.name}: ${r.pass}/${r.total}${r.failed ? ' FAILED' : ''}  [${r.version}]`);
process.exit(summary.some((r) => r.failed) ? 1 : 0);
