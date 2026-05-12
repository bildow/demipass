#!/usr/bin/env node

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const demipass = require('../../index.js');

const DEFAULT_BASE_URL = 'https://api.dustforge.com';
const DEFAULT_SUCCESS_URL = 'https://api.github.com/meta';
const DEFAULT_DENY_URL = 'https://api.openai.com/v1/models';

function nowIso() {
  return new Date().toISOString();
}

function randomSuffix() {
  return crypto.randomBytes(4).toString('hex');
}

function envFlag(name) {
  const value = (process.env[name] || '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes';
}

function sanitizeError(error) {
  return {
    name: error && error.name ? error.name : 'Error',
    message: error && error.message ? error.message : String(error),
    stack: error && error.stack ? String(error.stack).split('\n').slice(0, 8) : [],
  };
}

function createReport(runId, baseUrl) {
  return {
    run_id: runId,
    started_at: nowIso(),
    finished_at: null,
    base_url: baseUrl,
    identities: {},
    surfaces: [],
    cleanup: [],
    summary: {
      passed: 0,
      failed: 0,
      blocked: 0,
    },
  };
}

function createSurface(name) {
  return {
    name,
    status: 'running',
    started_at: nowIso(),
    finished_at: null,
    steps: [],
    details: {},
  };
}

function finishSurface(report, surface, status, details = {}) {
  surface.status = status;
  surface.finished_at = nowIso();
  surface.details = { ...surface.details, ...details };
  report.surfaces.push(surface);
  if (status === 'pass') report.summary.passed += 1;
  if (status === 'fail') report.summary.failed += 1;
  if (status === 'blocked') report.summary.blocked += 1;
}

function pushStep(surface, step, status, detail) {
  surface.steps.push({
    at: nowIso(),
    step,
    status,
    detail,
  });
}

function configureClient(baseUrl, bearerToken) {
  demipass.configure({ baseUrl, bearerToken });
}

async function rawRequest(baseUrl, method, requestPath, { bearerToken, body, query } = {}) {
  const url = new URL(requestPath, baseUrl);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value));
      }
    }
  }

  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'X-DemiPass-Agent': 'demipass-live-harness/0.1',
  };
  if (bearerToken) {
    headers.Authorization = `Bearer ${bearerToken}`;
  }

  const response = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const raw = await response.text();
  let parsed = raw;
  try {
    parsed = JSON.parse(raw);
  } catch {}

  if (!response.ok) {
    const message = parsed && parsed.error ? parsed.error : `HTTP ${response.status}`;
    throw new Error(`${method} ${requestPath} failed: ${message}`);
  }

  return parsed;
}

async function lookupDid(baseUrl, username) {
  const data = await rawRequest(baseUrl, 'GET', '/api/identity/lookup', {
    query: { username },
  });
  return data.did;
}

async function authenticateOrCreate(baseUrl, spec, allowCreate) {
  const actor = {
    label: spec.label,
    username: spec.username || null,
    did: spec.did || null,
    token: spec.token || null,
    created: false,
    auth_mode: spec.token ? 'env_token' : null,
  };

  if (!actor.did && actor.username) {
    try {
      actor.did = await lookupDid(baseUrl, actor.username);
    } catch {}
  }

  if (actor.token) {
    if (!actor.did && actor.username) {
      actor.did = await lookupDid(baseUrl, actor.username);
    }
    return actor;
  }

  if (!spec.username || !spec.password) {
    throw new Error(`${spec.label} requires either token or username/password`);
  }

  try {
    configureClient(baseUrl, '');
    const auth = await demipass.authenticate({
      username: spec.username,
      password: spec.password,
      scope: 'transact',
      expiresIn: '2h',
    });
    actor.token = auth.token;
    actor.did = auth.did;
    actor.auth_mode = 'authenticate';
    return actor;
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    if (!allowCreate || !/identity not found|username already taken/i.test(message)) {
      throw error;
    }
  }

  if (!allowCreate) {
    throw new Error(`${spec.label} authentication failed and auto-create is disabled`);
  }

  try {
    configureClient(baseUrl, '');
    await demipass.create({
      username: spec.username,
      password: spec.password,
      referralCode: spec.referralCode,
    });
    actor.created = true;
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    if (!/username already taken/i.test(message)) {
      throw error;
    }
  }

  configureClient(baseUrl, '');
  const auth = await demipass.authenticate({
    username: spec.username,
    password: spec.password,
    scope: 'transact',
    expiresIn: '2h',
  });
  actor.token = auth.token;
  actor.did = auth.did;
  actor.auth_mode = actor.created ? 'create+authenticate' : 'authenticate';
  return actor;
}

function addCleanup(cleanup, fn) {
  cleanup.push(fn);
}

async function revokeSecret(baseUrl, actor, secretName) {
  return rawRequest(baseUrl, 'DELETE', '/api/demipass/revoke', {
    bearerToken: actor.token,
    body: { name: secretName },
  });
}

async function runBasicStoreUse(baseUrl, owner, report, cleanup, runId) {
  const surface = createSurface('basic_store_use');
  const secretName = `brain-live-basic-${runId}`;
  const secretValue = `dp-basic-${randomSuffix()}`;
  const contextName = 'brain-live-basic-context';

  try {
    configureClient(baseUrl, owner.token);
    const stored = await demipass.store({
      name: secretName,
      value: secretValue,
      description: `Brain live harness basic store/use ${runId}`,
      secretType: 'api_key',
    });
    pushStep(surface, 'store', 'pass', stored);

    addCleanup(cleanup, async () => revokeSecret(baseUrl, owner, secretName));

    const context = await demipass.addContext({
      secretName,
      contextName,
      actionType: 'http_header',
      targetUrlPattern: DEFAULT_SUCCESS_URL,
    });
    pushStep(surface, 'add_context', 'pass', context);

    const token = await demipass.requestToken({
      secretName,
      context: contextName,
      action: 'http_header',
      targetUrl: DEFAULT_SUCCESS_URL,
    });
    pushStep(surface, 'request_token', 'pass', {
      action: token.action,
      context: token.context,
      delegated: token.delegated,
      expires_in_seconds: token.expires_in_seconds,
    });

    const execution = await demipass.execute({
      token: token.use_token,
      params: {
        method: 'GET',
        header_name: 'X-DemiPass-Test',
        header_prefix: '',
      },
    });
    pushStep(surface, 'execute', 'pass', {
      ok: execution.ok,
      via: execution.via,
      status: execution.result && execution.result.status,
    });

    if (!execution.ok || !execution.result || execution.result.status !== 200) {
      throw new Error(`expected HTTP 200 from ${DEFAULT_SUCCESS_URL}`);
    }

    finishSurface(report, surface, 'pass', {
      secret_name: secretName,
      target_url: DEFAULT_SUCCESS_URL,
      result_status: execution.result.status,
    });
  } catch (error) {
    pushStep(surface, 'error', 'fail', sanitizeError(error));
    finishSurface(report, surface, 'fail', {
      error: sanitizeError(error),
      secret_name: secretName,
    });
  }
}

async function runContextEnforcement(baseUrl, owner, report, cleanup, runId) {
  const surface = createSurface('context_enforcement');
  const secretName = `brain-live-context-${runId}`;
  const secretValue = `dp-context-${randomSuffix()}`;
  const contextName = 'brain-live-enforced-context';

  try {
    configureClient(baseUrl, owner.token);
    const stored = await demipass.store({
      name: secretName,
      value: secretValue,
      description: `Brain live harness context enforcement ${runId}`,
      secretType: 'api_key',
    });
    pushStep(surface, 'store', 'pass', stored);

    addCleanup(cleanup, async () => revokeSecret(baseUrl, owner, secretName));

    const context = await demipass.addContext({
      secretName,
      contextName,
      actionType: 'http_header',
      targetUrlPattern: DEFAULT_SUCCESS_URL,
    });
    pushStep(surface, 'add_context', 'pass', context);

    let denied = null;
    try {
      await demipass.requestToken({
        secretName,
        context: contextName,
        action: 'http_header',
        targetUrl: DEFAULT_DENY_URL,
      });
    } catch (error) {
      denied = error;
    }

    if (!denied) {
      throw new Error('expected requestToken() denial for mismatched target URL');
    }

    const deniedMessage = denied.message || String(denied);
    pushStep(surface, 'request_token_wrong_target', 'pass', {
      denied_message: deniedMessage,
    });

    if (!/target URL does not match context pattern|not match context pattern/i.test(deniedMessage)) {
      throw new Error(`unexpected denial: ${deniedMessage}`);
    }

    finishSurface(report, surface, 'pass', {
      secret_name: secretName,
      allowed_target: DEFAULT_SUCCESS_URL,
      denied_target: DEFAULT_DENY_URL,
      denial: deniedMessage,
    });
  } catch (error) {
    pushStep(surface, 'error', 'fail', sanitizeError(error));
    finishSurface(report, surface, 'fail', {
      error: sanitizeError(error),
      secret_name: secretName,
    });
  }
}

async function runDelegation(baseUrl, owner, delegate, report, cleanup, runId) {
  const surface = createSurface('delegation');
  const secretName = `brain-live-delegation-${runId}`;
  const secretValue = `dp-delegation-${randomSuffix()}`;
  const contextName = 'brain-live-delegation-context';
  let delegationId = null;

  if (!delegate || !delegate.did || !delegate.token) {
    pushStep(surface, 'preflight', 'blocked', 'delegate identity unavailable');
    finishSurface(report, surface, 'blocked', {
      reason: 'delegate identity unavailable',
    });
    return;
  }

  try {
    configureClient(baseUrl, owner.token);
    const stored = await demipass.store({
      name: secretName,
      value: secretValue,
      description: `Brain live harness delegation ${runId}`,
      secretType: 'api_key',
    });
    pushStep(surface, 'store', 'pass', stored);

    addCleanup(cleanup, async () => revokeSecret(baseUrl, owner, secretName));

    const context = await demipass.addContext({
      secretName,
      contextName,
      actionType: 'http_header',
      targetUrlPattern: DEFAULT_SUCCESS_URL,
    });
    pushStep(surface, 'add_context', 'pass', context);

    const delegated = await demipass.delegate({
      secretName,
      delegateDid: delegate.did,
      contextName,
      maxUses: 1,
      expiresIn: 600,
    });
    delegationId = delegated.delegation_id;
    pushStep(surface, 'delegate', 'pass', delegated);

    addCleanup(cleanup, async () => {
      configureClient(baseUrl, owner.token);
      return demipass.revoke({ delegationId });
    });

    const ownerDelegationsBefore = await demipass.delegations();
    const beforeEntry = (ownerDelegationsBefore.delegations || []).find((item) => item.id === delegationId);
    pushStep(surface, 'delegations_before_use', 'pass', beforeEntry || ownerDelegationsBefore);

    configureClient(baseUrl, delegate.token);
    const token = await demipass.requestToken({
      secretName,
      context: contextName,
      action: 'http_header',
      targetUrl: DEFAULT_SUCCESS_URL,
      ownerDid: owner.did,
    });
    pushStep(surface, 'delegate_request_token', 'pass', {
      action: token.action,
      delegated: token.delegated,
      context: token.context,
    });

    const execution = await demipass.execute({
      token: token.use_token,
      params: {
        method: 'GET',
        header_name: 'X-DemiPass-Test',
        header_prefix: '',
      },
    });
    pushStep(surface, 'delegate_execute', 'pass', {
      ok: execution.ok,
      via: execution.via,
      status: execution.result && execution.result.status,
    });

    if (!execution.ok || !execution.result || execution.result.status !== 200) {
      throw new Error(`expected delegated HTTP 200 from ${DEFAULT_SUCCESS_URL}`);
    }

    configureClient(baseUrl, owner.token);
    const ownerDelegationsAfter = await demipass.delegations();
    const afterEntry = (ownerDelegationsAfter.delegations || []).find((item) => item.id === delegationId);
    pushStep(surface, 'delegations_after_use', 'pass', afterEntry || ownerDelegationsAfter);

    if (!afterEntry) {
      throw new Error(`delegation ${delegationId} not visible in list`);
    }
    if (Number(afterEntry.use_count) !== 1) {
      throw new Error(`expected delegation use_count=1, got ${afterEntry.use_count}`);
    }

    const history = await demipass.history({
      secretName,
      limit: 20,
    });
    const eventTypes = (history.events || []).map((event) => event.event_type);
    pushStep(surface, 'history_snapshot', 'pass', eventTypes);

    if (!eventTypes.includes('delegation_token_issued') || !eventTypes.includes('delegation_used')) {
      throw new Error(`delegation audit trail incomplete: ${eventTypes.join(', ')}`);
    }

    finishSurface(report, surface, 'pass', {
      secret_name: secretName,
      delegation_id: delegationId,
      delegate_did: delegate.did,
      result_status: 200,
      use_count: afterEntry.use_count,
      observed_events: eventTypes,
    });
  } catch (error) {
    pushStep(surface, 'error', 'fail', sanitizeError(error));
    finishSurface(report, surface, 'fail', {
      error: sanitizeError(error),
      secret_name: secretName,
      delegation_id: delegationId,
    });
  }
}

async function runCleanup(cleanup, report) {
  for (const task of cleanup.reverse()) {
    try {
      const result = await task();
      report.cleanup.push({
        at: nowIso(),
        status: 'pass',
        detail: result,
      });
    } catch (error) {
      report.cleanup.push({
        at: nowIso(),
        status: 'fail',
        error: sanitizeError(error),
      });
    }
  }
}

function writeReport(report, reportPath) {
  const json = JSON.stringify(report, null, 2);
  if (reportPath) {
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, json + '\n', 'utf8');
  }
  process.stdout.write(json + '\n');
}

async function main() {
  const runId = `${Date.now()}-${randomSuffix()}`;
  const baseUrl = process.env.DEMIPASS_BASE_URL || DEFAULT_BASE_URL;
  const allowCreate = envFlag('DEMIPASS_LIVE_ALLOW_CREATE');
  const reportPath = process.env.DEMIPASS_LIVE_REPORT_PATH || '';
  const report = createReport(runId, baseUrl);
  const cleanup = [];

  const ownerSpec = {
    label: 'owner',
    username: process.env.DEMIPASS_LIVE_OWNER_USERNAME || '',
    password: process.env.DEMIPASS_LIVE_OWNER_PASSWORD || '',
    token: process.env.DEMIPASS_LIVE_OWNER_TOKEN || '',
    did: process.env.DEMIPASS_LIVE_OWNER_DID || '',
    referralCode: process.env.DEMIPASS_LIVE_OWNER_REFERRAL_CODE || '',
  };
  const delegateSpec = {
    label: 'delegate',
    username: process.env.DEMIPASS_LIVE_DELEGATE_USERNAME || '',
    password: process.env.DEMIPASS_LIVE_DELEGATE_PASSWORD || '',
    token: process.env.DEMIPASS_LIVE_DELEGATE_TOKEN || '',
    did: process.env.DEMIPASS_LIVE_DELEGATE_DID || '',
    referralCode: process.env.DEMIPASS_LIVE_DELEGATE_REFERRAL_CODE || '',
  };

  let exitCode = 0;

  try {
    const owner = await authenticateOrCreate(baseUrl, ownerSpec, allowCreate);
    report.identities.owner = {
      username: owner.username,
      did: owner.did,
      auth_mode: owner.auth_mode,
      created: owner.created,
    };

    let delegate = null;
    if (delegateSpec.token || (delegateSpec.username && delegateSpec.password)) {
      delegate = await authenticateOrCreate(baseUrl, delegateSpec, allowCreate);
      report.identities.delegate = {
        username: delegate.username,
        did: delegate.did,
        auth_mode: delegate.auth_mode,
        created: delegate.created,
      };
    } else {
      report.identities.delegate = {
        skipped: true,
        reason: 'delegate credentials not provided',
      };
    }

    await runBasicStoreUse(baseUrl, owner, report, cleanup, runId);
    await runContextEnforcement(baseUrl, owner, report, cleanup, runId);
    await runDelegation(baseUrl, owner, delegate, report, cleanup, runId);
  } catch (error) {
    report.surfaces.push({
      name: 'preflight',
      status: 'blocked',
      started_at: report.started_at,
      finished_at: nowIso(),
      steps: [],
      details: {
        error: sanitizeError(error),
      },
    });
    report.summary.blocked += 1;
  } finally {
    await runCleanup(cleanup, report);
    report.finished_at = nowIso();
    writeReport(report, reportPath);
  }

  if (report.summary.failed > 0) {
    exitCode = 1;
  } else if (report.summary.blocked > 0) {
    exitCode = 2;
  }

  process.exitCode = exitCode;
}

if (!process.env.NODE_TEST_CONTEXT) {
  main().catch((error) => {
    const report = createReport(`fatal-${Date.now()}`, process.env.DEMIPASS_BASE_URL || DEFAULT_BASE_URL);
    report.finished_at = nowIso();
    report.summary.failed = 1;
    report.surfaces.push({
      name: 'fatal',
      status: 'fail',
      started_at: report.started_at,
      finished_at: report.finished_at,
      steps: [],
      details: { error: sanitizeError(error) },
    });
    writeReport(report, process.env.DEMIPASS_LIVE_REPORT_PATH || '');
    process.exitCode = 1;
  });
}

module.exports = {
  main,
};
