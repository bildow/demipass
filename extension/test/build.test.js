import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { applyOverlay, buildTarget, manifestFor, unzip, zipDir, SHIPPED, SRC } from '../build.mjs';

const work = mkdtempSync(path.join(tmpdir(), 'dp-ext-build-'));
test.after(() => rmSync(work, { recursive: true, force: true }));

function referencedFiles(m) {
  const files = [m.action.default_popup, m.options_ui.page];
  if (m.background.service_worker) files.push(m.background.service_worker);
  for (const s of m.background.scripts || []) files.push(s);
  for (const cs of m.content_scripts) files.push(...cs.js);
  return files;
}

test('chromium manifest: service worker, no Gecko keys', () => {
  const m = manifestFor('chromium');
  assert.equal(m.manifest_version, 3);
  assert.deepEqual(m.background, { service_worker: 'background.js', type: 'module' });
  assert.equal('browser_specific_settings' in m, false);
  assert.ok(m.minimum_chrome_version);
});

test('firefox manifest: event page (background.scripts), gecko id, no Chromium-only keys', () => {
  const m = manifestFor('firefox');
  assert.deepEqual(m.background, { scripts: ['background.js'], type: 'module' });
  assert.equal('service_worker' in m.background, false);
  assert.equal('minimum_chrome_version' in m, false);
  const g = m.browser_specific_settings.gecko;
  assert.match(g.id, /^[a-z0-9.-]+@[a-z0-9.-]+$/);
  // 153: first release with MessageSender.documentId and scripting documentIds (current ESR).
  assert.ok(Number(g.strict_min_version.split('.')[0]) >= 153, g.strict_min_version);
  assert.ok(Array.isArray(g.data_collection_permissions.required) && g.data_collection_permissions.required.length > 0);
  assert.equal(Object.keys(m).some((k) => k.startsWith('//')), false, 'overlay comments are not shipped');
});

test('both manifests ask for the same permissions and run the same code', () => {
  const c = manifestFor('chromium');
  const f = manifestFor('firefox');
  for (const k of ['permissions', 'host_permissions', 'optional_host_permissions', 'content_scripts', 'action', 'options_ui', 'content_security_policy', 'version', 'name']) {
    assert.deepEqual(f[k], c[k], k);
  }
  assert.equal(c.background.service_worker, f.background.scripts[0]);
  assert.ok(c.optional_host_permissions.includes('<all_urls>'), 'site access can be requested at runtime');
});

test('applyOverlay: null removes, comments skipped, base untouched', () => {
  const base = { a: 1, b: { c: 2 }, d: 3 };
  const out = applyOverlay(base, { '//': 'x', a: null, b: { e: 4 } });
  assert.deepEqual(out, { b: { e: 4 }, d: 3 });
  assert.deepEqual(base, { a: 1, b: { c: 2 }, d: 3 });
});

for (const target of ['chromium', 'firefox']) {
  test(`${target} build: every referenced file is present, nothing outside the shipped set`, () => {
    const { out, manifest } = buildTarget(target, { out: path.join(work, target) });
    for (const f of referencedFiles(manifest)) assert.ok(existsSync(path.join(out, f)), f);
    const zip = unzip(zipDir(out));
    const names = Object.keys(zip);
    assert.ok(names.includes('manifest.json'));
    for (const n of names) assert.ok(n === 'manifest.json' || SHIPPED.some((s) => n === s || n.startsWith(s + '/')), n);
    assert.equal(names.some((n) => n.includes('test/') || n.endsWith('.md') || n.includes('build.mjs')), false);
    assert.deepEqual(JSON.parse(zip['manifest.json']), manifest);
    assert.equal(zip['background.js'].toString(), readFileSync(path.join(SRC, 'background.js'), 'utf8'));
  });
}

test('packages are deterministic', () => {
  const { out } = buildTarget('firefox', { out: path.join(work, 'det') });
  assert.equal(Buffer.compare(zipDir(out), zipDir(out)), 0);
});

test('no extension code names chrome.* directly (lib/browser.js picks browser.* or chrome.*)', () => {
  for (const f of ['background.js', 'lib/api.js', 'lib/token-store.js', 'lib/compat.js', 'lib/origin.js', 'content/content.js', 'content/form-detect.js', 'ui/popup.js', 'ui/options.js', 'ui/save.js']) {
    const src = readFileSync(path.join(SRC, f), 'utf8').split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
    assert.equal(/(^|[^.\w])chrome\./.test(src), false, f);
  }
});
