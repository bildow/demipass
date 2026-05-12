const test = require('node:test');
const assert = require('node:assert/strict');

process.env.NODE_TEST_CONTEXT = '1';

const {
  buildMarkdownReport,
  parseArgs,
  SUPPORTED_SURFACES,
  validateEnv,
} = require('./run.js');

test('parseArgs defaults to all supported surfaces', () => {
  const parsed = parseArgs([]);
  assert.deepEqual(parsed.surfaces, SUPPORTED_SURFACES);
});

test('parseArgs accepts explicit surface selection and report paths', () => {
  const parsed = parseArgs([
    '--surface',
    'basic_store_use,delegation',
    '--report',
    '/tmp/demipass-live.json',
    '--markdown',
    '/tmp/demipass-live.md',
  ]);

  assert.deepEqual(parsed.surfaces, ['basic_store_use', 'delegation']);
  assert.equal(parsed.reportPath, '/tmp/demipass-live.json');
  assert.equal(parsed.markdownPath, '/tmp/demipass-live.md');
});

test('parseArgs rejects unsupported surfaces', () => {
  assert.throws(
    () => parseArgs(['--surface', 'oracle_blindness']),
    /unsupported surface/,
  );
});

test('validateEnv requires owner credentials and delegate credentials for delegation', () => {
  const originalEnv = { ...process.env };
  try {
    delete process.env.DEMIPASS_LIVE_OWNER_TOKEN;
    delete process.env.DEMIPASS_LIVE_OWNER_USERNAME;
    delete process.env.DEMIPASS_LIVE_OWNER_PASSWORD;
    delete process.env.DEMIPASS_LIVE_DELEGATE_TOKEN;
    delete process.env.DEMIPASS_LIVE_DELEGATE_USERNAME;
    delete process.env.DEMIPASS_LIVE_DELEGATE_PASSWORD;

    const errors = validateEnv(['basic_store_use', 'delegation']);
    assert.equal(errors.length, 2);
    assert.match(errors[0], /owner identity requires/);
    assert.match(errors[1], /delegation surface requires/);
  } finally {
    process.env = originalEnv;
  }
});

test('buildMarkdownReport emits a compact summary and cleanup section', () => {
  const markdown = buildMarkdownReport({
    run_id: 'dpth_test',
    base_url: 'https://api.dustforge.com',
    started_at: '2026-05-12T00:00:00.000Z',
    finished_at: '2026-05-12T00:01:00.000Z',
    selected_surfaces: ['basic_store_use'],
    summary: { passed: 1, failed: 0, blocked: 0 },
    surfaces: [
      {
        name: 'basic_store_use',
        status: 'pass',
        steps: [
          { step: 'store', status: 'pass', detail: { ok: true } },
          { step: 'request_token', status: 'pass', detail: 'issued' },
        ],
      },
    ],
    cleanup: [
      { status: 'pass', detail: { revoked: true } },
    ],
  });

  assert.match(markdown, /# DemiPass Live Harness Report/);
  assert.match(markdown, /Summary: 1 passed, 0 failed, 0 blocked/);
  assert.match(markdown, /### basic_store_use \[pass\]/);
  assert.match(markdown, /## Cleanup/);
});
