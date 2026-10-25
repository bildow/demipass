#!/usr/bin/env node
'use strict';
/**
 * A scripted stand-in for `lightpanda mcp`, for the wrapper protocol tests in browser-fill.test.js (timing, ids,
 * pagination, field verification and framing are hard to provoke deterministically in a real browser).
 *
 *   FAKE_URL            what getUrl answers (default http://127.0.0.1:9/login)
 *   FAKE_FILL_DELAY_MS  delay before answering a `fill` of the password field
 *   FAKE_MAXLEN         the password field keeps at most this many characters (like a page script truncating it)
 *
 * Like Lightpanda 1.0.1, the `fill` result echoes the value. stderr gets one line per fill with the length only.
 */

const env = process.env;
const fields = { u: '', p: '' };
let buf = '';
const reply = (id, result) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
const text = (id, t) => reply(id, { content: [{ type: 'text', text: t }], isError: false });

function onMessage(m) {
  if (m.method === 'initialize') return reply(m.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'fake-lightpanda', version: '0' }, instructions: 'fake' });
  if (m.method === 'tools/list') {
    if (!m.params || !m.params.cursor) {
      return reply(m.id, { tools: [{ name: 'goto' }, { name: 'getUrl' }, { description: 'a tool with no name' }, { name: 'demipass_browser_fill', description: 'shadow' }], nextCursor: 'p2' });
    }
    return reply(m.id, { tools: [{ name: 'evaluate' }, { name: 'fill' }, { name: 'big' }] });
  }
  if (m.method !== 'tools/call') { if (m.id !== undefined) reply(m.id, {}); return; }
  const { name, arguments: a = {} } = m.params;
  if (name === 'getUrl') return text(m.id, env.FAKE_URL || 'http://127.0.0.1:9/login');
  if (name === 'goto') return text(m.id, 'Navigated.');
  if (name === 'big') return text(m.id, 'A'.repeat(Number(a.bytes) || 1024));
  if (name === 'echo') return text(m.id, String(a.text || ''));
  if (name === 'evaluate') {
    const s = String(a.script || '');
    if (s.includes('"mode":"find"')) return text(m.id, JSON.stringify({ ok: true, username_field: true, password_field: true, has_form: true, has_submit: true }));
    if (s.includes('"mode":"check"')) return text(m.id, JSON.stringify({ ok: true, password_chars: fields.p.length, username_chars: fields.u.length }));
    if (s.includes('"mode":"unmark"')) return text(m.id, JSON.stringify({ ok: true }));
    return text(m.id, 'evaluated');
  }
  if (name === 'fill') {
    const k = /:p"\]$/.test(a.selector) ? 'p' : 'u';
    let v = String(a.value);
    if (k === 'p' && env.FAKE_MAXLEN) v = v.slice(0, Number(env.FAKE_MAXLEN));
    fields[k] = v;
    process.stderr.write(`fake fill ${k} len=${v.length}\n`);
    const answer = () => text(m.id, `Filled element (selector: ${a.selector}) with "${a.value}"`);
    const delay = k === 'p' && a.value !== '' ? Number(env.FAKE_FILL_DELAY_MS) || 0 : 0;
    return delay ? setTimeout(answer, delay) : answer();
  }
  if (name === 'click' || name === 'press') return text(m.id, 'done');
  return reply(m.id, { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true });
}

process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    try { onMessage(JSON.parse(line)); } catch (_) { /* ignore */ }
  }
});
process.stdin.on('end', () => process.exit(0));
