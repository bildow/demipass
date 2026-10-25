// Chromium-family driver for the smoke test (Playwright's Chromium, Chrome
// for Testing, Brave). Loads the unpacked dist/chromium build with
// --load-extension, which branded Google Chrome no longer honours (137+);
// Chrome for Testing and Brave still do.

import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);

export async function launchChromium({ extDir, work, executablePath, label }) {
  const pwPath = process.env.PLAYWRIGHT_CORE || 'playwright-core';
  let chromium;
  try { ({ chromium } = require(pwPath)); } catch { return { skip: 'playwright-core not found (set PLAYWRIGHT_CORE)' }; }

  const context = await chromium.launchPersistentContext(path.join(work, 'profile'), {
    ...(executablePath ? { executablePath } : { channel: 'chromium' }),
    headless: true,
    args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`, '--no-first-run', '--no-default-browser-check'],
  });
  const logs = [];
  const onConsole = (m) => logs.push(m.text());
  context.on('console', onConsole);
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 20000 });
  const extBase = `chrome-extension://${new URL(sw.url()).host}/`;
  sw.on?.('console', onConsole);
  // A stopped worker comes back as a new Worker object.
  context.on('serviceworker', (w) => { if (w.url().startsWith(extBase)) { sw = w; w.on?.('console', onConsole); } });
  async function wake() {
    const p = await context.newPage();
    const next = context.waitForEvent('serviceworker', { timeout: 10000 }).catch(() => null);
    await p.goto(extBase + 'ui/options.html'); // its messages start the worker
    await next;
    await p.close();
  }
  const ua = await sw.evaluate(() => navigator.userAgent);
  const version = `${label || 'chromium'} ${(/Chrome\/([\d.]+)/.exec(ua) || [])[1] || ua}`;

  function wrap(page) {
    return {
      raw: page,
      url: () => page.url(),
      goto: (url) => page.goto(url),
      fill: (sel, value) => page.fill(sel, value),
      // Real key presses (keydown/keyup per character), as a person typing.
      // Keys go to whatever has focus after the first one, as for a person.
      // (Cleared first only if it holds something: clearing sends key events of its own.)
      type: async (sel, value) => {
        if (await page.inputValue(sel)) await page.fill(sel, '');
        await page.focus(sel);
        await page.keyboard.type(value, { delay: 10 });
      },
      click: (sel) => page.click(sel),
      clickAndWaitUrl: (sel, re) => Promise.all([page.waitForURL(re), page.click(sel)]),
      eval: (fn, arg) => page.evaluate(fn, arg),
      waitFn: (fn, arg, timeout = 15000) => page.waitForFunction(fn, arg, { timeout, polling: 100 }),
      content: () => page.content(),
      close: () => page.close(),
    };
  }

  return {
    name: label || 'chromium',
    version,
    extBase,
    logs,
    supportsIdleControl: false,
    async newPage(url) {
      const p = await context.newPage();
      if (url) await p.goto(url);
      return wrap(p);
    },
    // fn runs in the extension's service worker (woken first if it was stopped).
    async extEval(fn, arg) {
      try { return await sw.evaluate(fn, arg); } catch {
        await wake();
        return sw.evaluate(fn, arg);
      }
    },
    // Value of an input inside the iframe element matched by frameSel.
    async frameInputValue(page, frameSel, sel) {
      const fr = await (await page.raw.$(frameSel)).contentFrame();
      return fr.evaluate((q) => document.querySelector(q).value, sel);
    },
    // What Chromium does to an idle worker (or on browser restart): stop it.
    async restartBackground() {
      const p = await context.newPage();
      const cdp = await context.newCDPSession(p);
      await cdp.send('ServiceWorker.enable');
      await cdp.send('ServiceWorker.stopAllWorkers');
      await cdp.detach();
      await p.close();
    },
    async close() { await context.close(); },
  };
}
