#!/usr/bin/env node
/**
 * Regression tests for the use-token flow.
 *
 * These exist because a params-shape bug shipped silently: use() spread action
 * params to the top level while the server reads req.body.params for
 * http_body/git_clone/smtp_auth. body_template never arrived, the server fell
 * back to {key: secret}, and targets answered "username and password required"
 * — which reads as a wrong credential, not a client bug. It cost about a month.
 *
 * node --check cannot catch this. Only asserting on the actual request body can.
 * Runs against a throwaway local HTTP server; no network, no credentials.
 *
 *   node test/use-token-flow.test.js
 */

const http = require('http');
const assert = require('assert');
const demipass = require('../index.js');

let failures = 0;
function check(name, fn) {
  try { fn(); console.log(`  ok    ${name}`); }
  catch (e) { failures++; console.log(`  FAIL  ${name}\n        ${e.message}`); }
}

// Records every request body the SDK sends, replies with a canned use-token.
function startRecorder() {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', c => (raw += c));
    req.on('end', () => {
      let body = {};
      try { body = JSON.parse(raw || '{}'); } catch {}
      seen.push({ path: req.url, body });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(
        req.url.includes('request-token')
          ? { use_token: 'tok_test', expires_in_seconds: 30 }
          : { ok: true, result: { status: 200, body: { ok: true } } }
      ));
    });
  });
  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => resolve({ server, seen, port: server.address().port }));
  });
}

(async () => {
  const { server, seen, port } = await startRecorder();
  demipass.configure({ baseUrl: `http://127.0.0.1:${port}`, bearerToken: 'test' });

  const BODY_TEMPLATE = { username: 'x', password: '{{SECRET}}' };
  const PARAMS = { method: 'POST', body_template: BODY_TEMPLATE };

  console.log('\naction validation');

  check('document is rejected, and the reason names why', () => {
    let err;
    try { demipass.getToken({ ref: 'r', action: 'document' }); } catch (e) { err = e; }
    assert(err, 'expected a throw');
    assert(/not implemented/.test(err.message), 'should say it is not implemented');
    assert(/http_body/.test(err.message), 'should point at a working alternative');
  });

  check('env_inject is rejected — server mints a token then refuses redemption', () => {
    let err;
    try { demipass.getToken({ ref: 'r', action: 'env_inject' }); } catch (e) { err = e; }
    assert(err, 'expected a throw');
    assert(/DISABLED|disabled/.test(err.message), 'should say it is disabled');
    assert(/redaction/.test(err.message), 'should give the actual reason');
  });

  check('unknown actions are rejected with the valid set', () => {
    let err;
    try { demipass.getToken({ ref: 'r', action: 'teleport' }); } catch (e) { err = e; }
    assert(err && /unknown action/.test(err.message), 'expected unknown-action error');
    assert(/http_body/.test(err.message), 'should list valid actions');
  });

  // awaited, so these in-flight requests cannot land in `seen` after a later
  // clear and be mistaken for the call under test
  let validActionsOk = true, validActionsErr = '';
  for (const a of ['http_header', 'ssh_exec', 'http_body', 'git_clone', 'smtp_auth', 'database_connect']) {
    try { await demipass.getToken({ ref: 'r', action: a, target_url: 'https://example.com' }); }
    catch (e) { validActionsOk = false; validActionsErr = `${a}: ${e.message}`; }
  }
  check('valid actions pass validation', () => {
    assert(validActionsOk, validActionsErr);
  });

  console.log('\nparams shape — the regression this file exists for');

  seen.length = 0;
  await demipass.use({
    ref: 'r', action: 'http_body',
    target_url: 'https://example.com/auth', params: PARAMS,
  });
  const useCall = seen.filter(s => s.path.endsWith('/use')).pop();

  check('use() sends params NESTED (http_body reads req.body.params)', () => {
    assert(useCall, 'no /use request recorded');
    assert.deepStrictEqual(useCall.body.params, PARAMS, 'nested params missing or wrong');
    assert.deepStrictEqual(useCall.body.params.body_template, BODY_TEMPLATE);
  });

  check('use() ALSO sends params top-level (ssh_exec reads req.body)', () => {
    assert.strictEqual(useCall.body.method, 'POST', 'top-level params missing');
  });

  check('use() forwards target_url onto the token request', () => {
    const tokenCall = seen.filter(s => s.path.includes('request-token')).pop();
    assert.strictEqual(tokenCall.body.target_url, 'https://example.com/auth');
  });

  seen.length = 0;
  await demipass.execute({ use_token: 'tok_test', action: 'http_body', params: PARAMS });
  const execCall = seen.filter(s => s.path.endsWith('/use')).pop();

  check('execute() sends params NESTED — the two-step MCP flow', () => {
    assert(execCall, 'no /use request recorded');
    assert.deepStrictEqual(execCall.body.params, PARAMS,
      'execute() must nest params or http_body silently gets {key: secret}');
  });

  check('execute() ALSO sends params top-level', () => {
    assert.strictEqual(execCall.body.method, 'POST', 'top-level params missing');
  });

  check('execute() and use() send the SAME shape', () => {
    assert.deepStrictEqual(
      Object.keys(execCall.body).filter(k => k !== 'use_token' && k !== 'action').sort(),
      Object.keys(useCall.body).filter(k => k !== 'use_token' && k !== 'action').sort(),
      'the two documented routes must not diverge — that is how this bug hid'
    );
  });

  console.log('\ngetToken');

  seen.length = 0;
  await demipass.getToken({ ref: 'r', action: 'http_body', target_url: 'https://example.com/a' });

  check('getToken() forwards target_url (was dropped, breaking redemption)', () => {
    const t = seen.filter(s => s.path.includes('request-token')).pop();
    assert.strictEqual(t.body.target_url, 'https://example.com/a');
  });

  console.log('\naccount-binding override_reason — Shadow round #2 item 3');

  // use() forwards override_reason both top-level and inside params, so the
  // server's action_params-flatten picks it up regardless of which case handler
  // reads it. Dropping either would silently defeat the resolver's override rule.
  seen.length = 0;
  await demipass.use({
    ref: 'r', action: 'ssh_exec', target_host: '10.0.0.1',
    target_user: 'root', command: 'whoami',
    override_reason: 'rotating sudoers',
  });
  const useOR = seen.filter(s => s.path.endsWith('/use')).pop();

  check('use() forwards override_reason top-level', () => {
    assert.strictEqual(useOR.body.override_reason, 'rotating sudoers');
  });

  check('use() also nests override_reason inside params', () => {
    assert(useOR.body.params, 'params object missing');
    assert.strictEqual(useOR.body.params.override_reason, 'rotating sudoers');
  });

  // execute() must match use() exactly — see the earlier "SAME shape" invariant.
  seen.length = 0;
  await demipass.execute({
    use_token: 'tok_test', action: 'ssh_exec',
    target_user: 'root', command: 'whoami',
    override_reason: 'rotating sudoers',
  });
  const execOR = seen.filter(s => s.path.endsWith('/use')).pop();

  check('execute() forwards override_reason top-level', () => {
    assert.strictEqual(execOR.body.override_reason, 'rotating sudoers');
  });

  check('execute() also nests override_reason inside params', () => {
    assert.strictEqual(execOR.body.params.override_reason, 'rotating sudoers');
  });

  // ssh() no longer defaults target_user to 'root' (the SDK-layer default
  // silently overrode the server-side resolver). When target_user is omitted,
  // the body must NOT carry a 'target_user' field, so the server resolver decides.
  seen.length = 0;
  await demipass.ssh({ ref: 'r', target_host: '10.0.0.1', command: 'whoami' });
  const sshBody = seen.filter(s => s.path.endsWith('/use')).pop().body;

  check("ssh() no longer defaults target_user='root' — omitted stays omitted", () => {
    assert.strictEqual(sshBody.target_user, undefined,
      "SDK-side 'root' default would override the server-side resolver — kill it");
  });

  server.close();
  console.log(failures ? `\n${failures} FAILED\n` : '\nall passed\n');
  process.exit(failures ? 1 : 0);
})();
