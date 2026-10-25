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
  const ua = await sw.evaluate(() => navigator.userAgent);
  const version = `${label || 'chromium'} ${(/Chrome\/([\d.]+)/.exec(ua) || [])[1] || ua}`;

  function wrap(page) {
    return {
      raw: page,
      url: () => page.url(),
      goto: (url) => page.goto(url),
      fill: (sel, value) => page.fill(sel, value),
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
    // fn runs in the extension's service worker.
    extEval: (fn, arg) => sw.evaluate(fn, arg),
    async close() { await context.close(); },
  };
}
