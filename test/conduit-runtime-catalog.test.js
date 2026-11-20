'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { catalog, plan } = require('../conduit-runtime-catalog');

test('named products remain plans, never implicit runtime activation', () => {
  for (const name of ['claude-code','codex','goose','clawdbot','moltbot','cladbot','hermes','openfang','zerclaw','nanobot','nullclaw','manus-ai','chatgpt-operator','cowork','zapier-agents','agent-sdks','brain','other']) {
    const p = plan(name);
    assert.equal(p.automatic_reception_enabled, false, name);
    assert.equal(p.reception_verified, false, name);
    assert.equal(p.host_started, false, name);
    assert.deepEqual(p.externally_certified_versions, [], name);
    assert.ok(p.blockers.length, name);
  }
  assert.equal(plan('moltbot').id, 'openclaw');
  assert.equal(plan('brain').state, 'held_by_operator_policy');
  assert.equal(plan('agent').state, 'plan_only');
  assert.equal(plan('cowork').sealed_delivery, 'refuse_until_separate_explicit_policy');
});
test('unknown names fail instead of selecting a generic privileged driver', () => {
  for (const name of ['not-a-runtime','__proto__','constructor','',null,{},'a'.repeat(81)]) assert.throws(() => plan(name));
  const p = plan('brain'); p.blockers.length = 0;
  assert.ok(plan('brain').blockers.length);
  catalog().runtimes.length = 0; assert.ok(catalog().runtimes.length);
});
test('planning never promotes names into the operational receiver allowlist', () => {
  const { validate } = require('../conduit-receiver-profile');
  for (const runtime of ['brain','hermes','openfang','openclaw','manus','chatgpt','nullclaw','nanobot','zeroclaw','zapier-agents']) {
    assert.throws(() => validate({ version: 1, runtime, enabled: true, address: 'test', wallet: 'wallet', relay: 'https://conduit.dustroot.com' },
      { name: 'test', wallet: 'wallet', url: 'https://conduit.dustroot.com' }), /receiver_profile_binding_invalid/);
  }
});
test('actual CLI plans before identity or credential resolution, rejects enable/restart arguments', () => {
  const invoke = args => spawnSync(process.execPath, [path.join(__dirname, '../bin/conduit-receiver.js'), ...args], {
    encoding: 'utf8', timeout: 3000,
    env: { PATH: process.env.PATH, HOME: '/nonexistent/conduit-plan-test', CONDUIT_CONFIG: '/nonexistent/private', DEMIPASS_URL: 'http://100.64.0.1' },
  });
  for (const args of [['catalog'], ['plan','--runtime','hermes'], ['plan','--runtime','brain']]) {
    const p = invoke(args); assert.equal(p.status, 0, p.stderr); assert.ok(JSON.parse(p.stdout).schema);
  }
  for (const args of [['plan','--runtime','hermes','--enabled','true'], ['catalog','--family','opus'], ['plan','--runtime','unknown'], ['plan','--runtime','brain','--endpoint','https://example.com']]) {
    const p = invoke(args); assert.equal(p.status, 1); assert.equal(p.stdout, '');
  }
});
test('actual MCP offers planning tools but rejects activation arguments', () => {
  const requests = [
    { jsonrpc: '2.0', id: 1, method: 'tools/list' },
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'conduit_receiver_plan', arguments: { runtime: 'brain' } } },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'conduit_receiver_plan', arguments: { runtime: 'brain', enabled: true } } },
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'conduit_runtimes', arguments: {} } },
  ];
  const p = spawnSync(process.execPath, [path.join(__dirname, '../mcp-server.js')], {
    input: requests.map(x => JSON.stringify(x)).join('\n') + '\n', encoding: 'utf8', timeout: 3000,
    env: { PATH: process.env.PATH, HOME: '/nonexistent/conduit-plan-test', DEMIPASS_URL: 'http://100.64.0.1' },
  });
  assert.equal(p.status, 0, p.stderr);
  const rows = p.stdout.trim().split('\n').map(x => JSON.parse(x));
  assert.equal(rows.length, 4);
  assert.ok(rows[0].result.tools.some(x => x.name === 'conduit_receiver_plan'));
  assert.equal(JSON.parse(rows[1].result.content[0].text).state, 'held_by_operator_policy');
  assert.equal(rows[2].result.isError, true);
  assert.equal(JSON.parse(rows[3].result.content[0].text).schema, 'conduit-runtime-catalog/v1');
});
