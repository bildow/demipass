// Gecko driver for the smoke test (Firefox, Zen). Talks W3C WebDriver to
// geckodriver over plain HTTP (no dependencies) and installs the built .xpi
// as a temporary add-on (geckodriver's /moz/addon/install, temporary: true —
// the same thing about:debugging "Load Temporary Add-on" does). Playwright's
// Firefox cannot load extensions.
//
// Console output from every context (pages, extension pages, the background
// event page) reaches Firefox's stdout through the devtools.console.stdout.*
// prefs; geckodriver forwards it, and the driver collects it in `logs`.

import { spawn } from 'node:child_process';
import { readFileSync, mkdirSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ELEMENT = 'element-6066-11e4-a52e-4f735466cecf';

export async function launchGecko({ xpi, addonId, binary, geckodriver, work, label, idleTimeoutMs, extraPrefs = {} }) {
  const port = await freePort();
  const tmp = path.join(work, 'gecko-tmp');
  mkdirSync(tmp, { recursive: true });
  const logs = [];
  // --allow-system-access: the chrome context, used only to open
  // moz-extension:// tabs (WebDriver "Navigate To" refuses those URLs).
  const gd = spawn(geckodriver, ['--port', String(port), '--log', 'info', '--allow-system-access'], { env: { ...process.env, TMPDIR: tmp, MOZ_HEADLESS: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let buf = '';
  const onData = (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf('\n')) >= 0) { logs.push(buf.slice(0, i)); buf = buf.slice(i + 1); }
  };
  gd.stdout.on('data', onData);
  gd.stderr.on('data', onData);
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) {
    try { await fetch(base + '/status'); break; } catch { await sleep(100); }
  }

  let sid = null;
  async function cmd(method, p, body) {
    const res = await fetch(base + (sid ? `/session/${sid}` : '') + p, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || (json.value && json.value.error)) {
      const e = new Error(`webdriver ${method} ${p}: ${json.value?.error} ${String(json.value?.message || '').slice(0, 300)}`);
      e.wd = json.value?.error;
      throw e;
    }
    return json.value;
  }

  const uuid = crypto.randomUUID();
  const prefs = {
    // Fixed moz-extension://<uuid> so the test can open extension pages.
    'extensions.webextensions.uuids': JSON.stringify({ [addonId]: uuid }),
    'devtools.console.stdout.content': true,
    'devtools.console.stdout.chrome': true,
    'browser.dom.window.dump.enabled': true,
    // Auto-accept permissions.request() (the click still has to happen).
    'extensions.webextOptionalPermissionPrompts': false,
    'browser.shell.checkDefaultBrowser': false,
    'datareporting.policy.dataSubmissionEnabled': false,
    'browser.aboutwelcome.enabled': false,
    'browser.startup.homepage_override.mstone': 'ignore',
    'zen.welcome-screen.seen': true,
    ...(idleTimeoutMs ? { 'extensions.background.idle.timeout': idleTimeoutMs } : {}),
    ...extraPrefs,
  };
  const session = await cmd('POST', '/session', {
    capabilities: { alwaysMatch: { browserName: 'firefox', 'moz:firefoxOptions': { binary, args: ['-headless'], prefs } } },
  });
  sid = session.sessionId;
  const caps = session.capabilities;
  await cmd('POST', '/timeouts', { script: 60000, pageLoad: 30000, implicit: 0 });
  const installedId = await cmd('POST', '/moz/addon/install', { addon: readFileSync(xpi).toString('base64'), temporary: true });
  if (installedId !== addonId) throw new Error(`installed ${installedId}, expected ${addonId}`);
  const extBase = `moz-extension://${uuid}/`;

  let current = (await cmd('GET', '/window'));
  async function use(handle) {
    if (current !== handle) { await cmd('POST', '/window', { handle }); current = handle; }
  }

  async function exec(handle, fn, arg) {
    await use(handle);
    const script = `const done = arguments[arguments.length - 1];
      Promise.resolve().then(() => (${fn.toString()})(arguments[0]))
        .then((v) => done({ v: v === undefined ? null : v }), (e) => done({ e: String((e && e.message) || e) }));`;
    const r = await cmd('POST', '/execute/async', { script, args: [arg === undefined ? null : arg] });
    if (r && r.e !== undefined) throw new Error('in page: ' + r.e);
    return r ? r.v : null;
  }

  async function find(handle, sel) {
    await use(handle);
    const el = await cmd('POST', '/element', { using: 'css selector', value: sel });
    return el[ELEMENT];
  }

  // Wait until sel exists and is rendered (same rule as the chromium driver's waitFn users).
  async function waitVisible(handle, sel, timeout = 15000) {
    const end = Date.now() + timeout;
    for (;;) {
      const ok = await exec(handle, (s) => { const el = document.querySelector(s); return !!(el && el.getClientRects().length); }, sel).catch(() => false);
      if (ok) return;
      if (Date.now() > end) throw new Error('timeout waiting for ' + sel);
      await sleep(100);
    }
  }

  function wrap(handle) {
    return {
      handle,
      url: async () => { await use(handle); return cmd('GET', '/url'); },
      goto: async (url) => { await use(handle); await cmd('POST', '/url', { url }); },
      async fill(sel, value) {
        await waitVisible(handle, sel);
        const id = await find(handle, sel);
        await cmd('POST', `/element/${id}/clear`, {});
        await cmd('POST', `/element/${id}/value`, { text: value });
      },
      async click(sel) {
        await waitVisible(handle, sel);
        const id = await find(handle, sel);
        await cmd('POST', `/element/${id}/click`, {});
      },
      async clickAndWaitUrl(sel, re) {
        await this.click(sel);
        const end = Date.now() + 15000;
        while (!re.test(await this.url())) { if (Date.now() > end) throw new Error('timeout waiting for url ' + re); await sleep(100); }
      },
      eval: (fn, arg) => exec(handle, fn, arg),
      async waitFn(fn, arg, timeout = 15000) {
        const end = Date.now() + timeout;
        for (;;) {
          if (await exec(handle, fn, arg).catch(() => false)) return;
          if (Date.now() > end) throw new Error(`timeout in waitFn ${fn.toString().slice(0, 120)} ${JSON.stringify(arg)}`);
          await sleep(100);
        }
      },
      content: async () => { await use(handle); return cmd('GET', '/source'); },
      async close() { await use(handle); await cmd('DELETE', '/window'); current = null; const hs = await cmd('GET', '/window/handles'); if (hs.length) await use(hs[0]); },
    };
  }

  async function openExtensionTab(url) {
    const before = new Set(await cmd('GET', '/window/handles'));
    await cmd('POST', '/moz/context', { context: 'chrome' });
    try {
      await cmd('POST', '/execute/sync', {
        script: `const win = Services.wm.getMostRecentWindow('navigator:browser');
          const tab = win.gBrowser.addTab(arguments[0], { triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal() });
          win.gBrowser.selectedTab = tab;`,
        args: [url],
      });
    } finally {
      await cmd('POST', '/moz/context', { context: 'content' });
    }
    for (let i = 0; i < 100; i++) {
      const added = (await cmd('GET', '/window/handles')).filter((h) => !before.has(h));
      if (added.length === 1) {
        const p = wrap(added[0]);
        await p.waitFn(() => document.readyState === 'complete', null, 15000);
        return p;
      }
      await sleep(50);
    }
    throw new Error('extension tab did not open');
  }

  // What a click on the toolbar button does for activeTab: grant it on the
  // selected tab. (Headless Firefox has no toolbar to click.)
  async function grantActiveTab(page) {
    await use(page.handle); // switching also selects the tab
    await cmd('POST', '/moz/context', { context: 'chrome' });
    try {
      await cmd('POST', '/execute/sync', {
        script: `const win = Services.wm.getMostRecentWindow('navigator:browser');
          WebExtensionPolicy.getByID(arguments[0]).extension.tabManager.addActiveTabPermission(win.gBrowser.selectedTab);`,
        args: [addonId],
      });
    } finally {
      await cmd('POST', '/moz/context', { context: 'content' });
    }
  }

  async function newPage(url) {
    if (url && url.startsWith('moz-extension:')) return openExtensionTab(url);
    const { handle } = await cmd('POST', '/window/new', { type: 'tab' });
    const p = wrap(handle);
    if (url) await p.goto(url);
    return p;
  }

  return {
    name: label || 'firefox',
    version: `${caps.browserName} ${caps.browserVersion}`,
    extBase,
    logs,
    supportsIdleControl: !!idleTimeoutMs,
    idleTimeoutMs,
    newPage,
    grantActiveTab,
    // fn runs in an extension page (Firefox has no handle on the event page
    // itself); the page is closed afterwards so it does not keep anything alive.
    async extEval(fn, arg) {
      const p = await newPage(extBase + 'ui/blank.html');
      try { return await p.eval(fn, arg); } finally { await p.close(); }
    },
    async close() {
      try { await cmd('DELETE', ''); } catch {}
      sid = null;
      gd.kill();
      await new Promise((r) => gd.once('exit', r).once('error', r));
    },
  };
}
