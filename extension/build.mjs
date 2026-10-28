// Builds the extension for each browser family from the one source tree.
//
//   node extension/build.mjs              -> extension/dist/chromium/, extension/dist/firefox/
//   node extension/build.mjs --package    -> also dist/demipass-chromium-<v>.zip, dist/demipass-firefox-<v>.xpi
//
// The code is identical for every target; only manifest.json differs:
//   chromium: manifest.json as is (background.service_worker).
//   firefox:  manifest.json + manifest.firefox.json (background.scripts event
//             page, browser_specific_settings.gecko, no minimum_chrome_version).
// No dependencies. The archives are deterministic (sorted entries, fixed
// timestamps), so the same source gives byte-identical packages.

import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

const here = path.dirname(fileURLToPath(import.meta.url));
export const SRC = here;
export const DIST = path.join(here, 'dist');
// What ships. Everything else under extension/ (tests, docs, build files) does not.
export const SHIPPED = ['background.js', 'lib', 'content', 'ui'];
export const TARGETS = ['chromium', 'firefox'];

export function readJson(p) {
  return JSON.parse(readFileSync(p, 'utf8'));
}

// Shallow overlay; null removes a key; keys starting with "//" are comments.
export function applyOverlay(base, overlay) {
  const out = structuredClone(base);
  for (const [k, v] of Object.entries(overlay)) {
    if (k.startsWith('//')) continue;
    if (v === null) delete out[k];
    else out[k] = structuredClone(v);
  }
  return out;
}

export function manifestFor(target, src = SRC) {
  const base = readJson(path.join(src, 'manifest.json'));
  if (target === 'chromium') return base;
  if (target === 'firefox') return applyOverlay(base, readJson(path.join(src, 'manifest.firefox.json')));
  throw new Error('unknown target ' + target);
}

export function buildTarget(target, { src = SRC, out = path.join(DIST, target), manifestEdit } = {}) {
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  for (const entry of SHIPPED) cpSync(path.join(src, entry), path.join(out, entry), { recursive: true });
  let manifest = manifestFor(target, src);
  if (manifestEdit) manifest = manifestEdit(manifest) || manifest;
  writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return { out, manifest };
}

function listFiles(dir, prefix = '') {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const abs = path.join(dir, name);
    const rel = prefix ? `${prefix}/${name}` : name;
    if (statSync(abs).isDirectory()) out.push(...listFiles(abs, rel));
    else out.push(rel);
  }
  return out;
}

// Minimal deterministic ZIP (deflate, UTF-8 names, 1980-01-01 timestamps).
// An .xpi is the same format with manifest.json at the root.
export function zipDir(dir) {
  const DOS_TIME = 0;
  const DOS_DATE = (0 << 9) | (1 << 5) | 1;
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const rel of listFiles(dir)) {
    const data = readFileSync(path.join(dir, rel));
    const comp = zlib.deflateRawSync(data, { level: 9 });
    const crc = zlib.crc32(data);
    const name = Buffer.from(rel, 'utf8');
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(8, 8);
    lh.writeUInt16LE(DOS_TIME, 10); lh.writeUInt16LE(DOS_DATE, 12); lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26); lh.writeUInt16LE(0, 28);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(0x0314, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(8, 10);
    ch.writeUInt16LE(DOS_TIME, 12); ch.writeUInt16LE(DOS_DATE, 14); ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE((0o100644 << 16) >>> 0, 38); ch.writeUInt32LE(offset, 42);
    locals.push(lh, name, comp);
    centrals.push(ch, name);
    offset += lh.length + name.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(centrals.length / 2, 8); end.writeUInt16LE(centrals.length / 2, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

// Reads back what zipDir wrote (used by the tests): { name: Buffer }.
export function unzip(buf) {
  const eocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0) throw new Error('not a zip');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const files = {};
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('bad central directory');
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const csize = buf.readUInt32LE(p + 20);
    const nlen = buf.readUInt16LE(p + 28);
    const elen = buf.readUInt16LE(p + 30);
    const clen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nlen).toString('utf8');
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const raw = buf.subarray(start, start + csize);
    const data = method === 8 ? zlib.inflateRawSync(raw) : Buffer.from(raw);
    if (zlib.crc32(data) !== crc) throw new Error('crc mismatch: ' + name);
    files[name] = data;
    p += 46 + nlen + elen + clen;
  }
  return files;
}

export function packageName(target, version) {
  return target === 'firefox' ? `demipass-firefox-${version}.xpi` : `demipass-chromium-${version}.zip`;
}

function main(argv) {
  const pkg = argv.includes('--package');
  for (const target of TARGETS) {
    const { out, manifest } = buildTarget(target);
    console.log(`built ${target}: ${out}`);
    if (pkg) {
      const file = path.join(DIST, packageName(target, manifest.version));
      writeFileSync(file, zipDir(out));
      console.log(`packaged ${target}: ${file}`);
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
