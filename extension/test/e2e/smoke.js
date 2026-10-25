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

  await step('page navigates to another origin while waiting: request is never redeemed, nothing filled', async () => {
    const page = await d.newPage(login(A));
    const { pop } = await openPopupFor(page);
    await pop.click(fillBtn());
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    const [reqId] = [...state.fills].find(([, x]) => x.status === 'pending');
    await page.goto(login(B));
    await waitText(pop, '#fill-msg', /page changed/);
    await phoneDecide(mock.apiBase, state, reqId, 'approve');
    await sleep(2500);
    assert.equal(state.fills.get(reqId).status, 'approved', 'approved but never redeemed');
    assert.equal(await inputValue(page, '#pass'), '');
    await pop.close(); await page.close();
  });

  await step('page reloads (same origin, new document) while waiting: nothing filled', async () => {
    const page = await d.newPage(login(A));
    const { pop } = await openPopupFor(page);
    await pop.click(fillBtn());
    await waitText(pop, '#fill-msg', /Approve on your phone/);
    const [reqId] = [...state.fills].find(([, x]) => x.status === 'pending');
    await page.goto(await page.url()); // same URL, same origin: a new document
    await waitText(pop, '#fill-msg', /page changed/);
    await phoneDecide(mock.apiBase, state, reqId, 'approve');
    await sleep(2500);
    assert.notEqual(state.fills.get(reqId).status, 'redeemed');
    assert.equal(await inputValue(page, '#pass'), '');
    await pop.close(); await page.close();
  });

  async function saveOnSubmit(page, user, secret) {
    await page.fill('#user', user);
    await page.fill('#pass', secret);
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
