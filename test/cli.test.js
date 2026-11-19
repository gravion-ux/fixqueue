import test from 'node:test';
import assert from 'node:assert/strict';

import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { main, parseArgs } from '../src/cli.js';
import { parseSuppressions } from '../src/suppress.js';

const NOW = 1_760_000_000_000;

const KEV_DOCUMENT = {
  catalogVersion: '2026.11.04',
  dateReleased: '2026-11-04T12:00:00.0000Z',
  vulnerabilities: [
    {
      cveID: 'CVE-2021-44228',
      vendorProject: 'Apache',
      vulnerabilityName: 'Apache Log4j2 JNDI issue',
      dueDate: '2021-12-24',
      knownRansomwareCampaignUse: 'Known',
    },
    {
      cveID: 'CVE-2020-11111',
      vendorProject: 'Example',
      vulnerabilityName: 'Example widget issue',
      dueDate: '2020-05-15',
      knownRansomwareCampaignUse: 'Unknown',
    },
  ],
};

const EPSS_DOCUMENT = {
  status: 'OK',
  data: [
    { cve: 'CVE-2021-44228', epss: '0.979630000', percentile: '0.998740000', date: '2026-11-04' },
    { cve: 'CVE-2020-11111', epss: '0.100000000', percentile: '0.400000000', date: '2026-11-04' },
  ],
};

/**
 * Build a fetch implementation that serves the canned feed documents.
 * @returns {Function} A fetch implementation.
 */
function fakeFetch() {
  return async (url) => {
    if (url.includes('known_exploited_vulnerabilities')) {
      return { statusCode: 200, body: JSON.stringify(KEV_DOCUMENT) };
    }
    if (url.includes('api.first.org')) {
      return { statusCode: 200, body: JSON.stringify(EPSS_DOCUMENT) };
    }
    return { statusCode: 404, body: '{}' };
  };
}

/**
 * Build a collecting output sink.
 * @returns {{ write: Function, text: string }} A sink that records everything written to it.
 */
function sink() {
  return {
    text: '',
    write(chunk) {
      this.text += chunk;
    },
  };
}

/**
 * Build an isolated runtime environment for a CLI test.
 * @returns {Promise<object>} A temporary working directory plus cache directory.
 */
async function sandbox() {
  const cwd = await mkdtemp(join(tmpdir(), 'fixqueue-cli-'));
  const cacheDir = join(cwd, '.cache');
  return { cwd, cacheDir };
}

/**
 * Resolve the path of a committed test fixture.
 * @param {string} name - Fixture file name.
 * @returns {string} The absolute fixture path.
 */
function fixture(name) {
  return fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
}

/**
 * Write two synthetic scanner documents that describe two distinct findings.
 * @param {string} cwd - Target directory.
 * @returns {Promise<string[]>} The written file paths.
 */
async function writeDistinctScans(cwd) {
  const sarifPath = join(cwd, 'a-sarif.json');
  const trivyPath = join(cwd, 'b-trivy.json');
  await writeFile(
    sarifPath,
    JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          results: [
            {
              ruleId: 'CVE-2021-44228',
              level: 'error',
              message: { text: 'Log4Shell' },
              properties: { 'security-severity': '9.8' },
              locations: [{ physicalLocation: { artifactLocation: { uri: 'a.json' } } }],
            },
          ],
        },
      ],
    }),
    'utf8',
  );
  await writeFile(
    trivyPath,
    JSON.stringify({
      Results: [
        {
          Target: 'b.json',
          Type: 'npm',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2020-11111',
              PkgName: 'lodash',
              InstalledVersion: '4.17.20',
              Severity: 'HIGH',
              Title: 'Example widget issue',
            },
          ],
        },
      ],
    }),
    'utf8',
  );
  return [sarifPath, trivyPath];
}

test('parseArgs reads the scan subcommand with its flags', () => {
  const parsed = parseArgs(['scan', 'a.json', '--format', 'json', '--offline', '--top', '5']);
  assert.equal(parsed.command, 'scan');
  assert.deepEqual(parsed.positionals, ['a.json']);
  assert.equal(parsed.options.format, 'json');
  assert.equal(parsed.options.offline, true);
  assert.equal(parsed.options.top, 5);
});

test('parseArgs supports the --flag=value form', () => {
  const parsed = parseArgs(['scan', '--format=sarif', '--fail-on=high']);
  assert.equal(parsed.options.format, 'sarif');
  assert.equal(parsed.options['fail-on'], 'high');
});

test('parseArgs collects unknown flags instead of throwing', () => {
  const parsed = parseArgs(['scan', '--verbose', '--experimental-mode', 'on']);
  assert.ok(parsed.options.unknown.includes('--verbose'));
  assert.ok(parsed.options.unknown.includes('--experimental-mode'));
  assert.equal(parsed.command, 'scan');
});

test('parseArgs converts --top to a number', () => {
  assert.equal(parseArgs(['scan', '--top', '3']).options.top, 3);
});

test('main scans two fixture files and writes Markdown to stdout', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    const stdout = sink();
    const stderr = sink();
    const code = await main(['scan', fixture('sarif.json'), fixture('trivy.json')], {
      stdout,
      stderr,
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 0);
    assert.ok(stdout.text.includes('# fixqueue'));
    assert.ok(stdout.text.includes('CVE-2021-44228'));
    assert.equal(stderr.text, '');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('main scans a directory of scanner outputs', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    const files = await writeDistinctScans(cwd);
    assert.equal(files.length, 2);
    const stdout = sink();
    const code = await main(['scan', cwd], {
      stdout,
      stderr: sink(),
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 0);
    assert.ok(stdout.text.includes('CVE-2021-44228'));
    assert.ok(stdout.text.includes('CVE-2020-11111'));
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('main emits parseable JSON with --format json', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    const stdout = sink();
    const code = await main(['scan', fixture('sarif.json'), '--format', 'json'], {
      stdout,
      stderr: sink(),
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 0);
    const parsed = JSON.parse(stdout.text);
    assert.equal(parsed.summary.total, 1);
    assert.equal(parsed.findings[0].id, 'CVE-2021-44228');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('main emits only the top N findings with --top', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    await writeDistinctScans(cwd);
    const stdout = sink();
    const code = await main(['scan', cwd, '--format', 'json', '--top', '1'], {
      stdout,
      stderr: sink(),
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 0);
    const parsed = JSON.parse(stdout.text);
    assert.equal(parsed.findings.length, 1);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('main returns 1 when a finding meets the --fail-on threshold', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    const stdout = sink();
    const code = await main(['scan', fixture('sarif.json'), '--fail-on', 'critical'], {
      stdout,
      stderr: sink(),
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 1);
    assert.ok(stdout.text.includes('CVE-2021-44228'));
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('main returns 0 when no finding meets the --fail-on threshold', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    await writeFile(
      join(cwd, 'medium.json'),
      JSON.stringify({
        version: '2.1.0',
        runs: [
          {
            results: [
              {
                ruleId: 'CVE-2020-11111',
                level: 'warning',
                message: { text: 'Medium severity finding' },
                properties: { 'security-severity': '4.0' },
                locations: [{ physicalLocation: { artifactLocation: { uri: 'a.json' } } }],
              },
            ],
          },
        ],
      }),
      'utf8',
    );
    const stdout = sink();
    const code = await main(['scan', cwd, '--fail-on', 'high'], {
      stdout,
      stderr: sink(),
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 0);
    assert.ok(stdout.text.includes('CVE-2020-11111'));
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('main returns 2 and writes to stderr for a nonexistent path', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    const stdout = sink();
    const stderr = sink();
    const code = await main(['scan', join(cwd, 'missing.json')], {
      stdout,
      stderr,
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 2);
    assert.ok(stderr.text.includes('path not found'));
    assert.equal(stdout.text, '');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('main suppresses findings that match the ignore file', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    await writeFile(join(cwd, '.fixqueueignore'), 'CVE-2021-44228 reason="accepted risk"\n', 'utf8');
    await writeDistinctScans(cwd);
    const stdout = sink();
    const code = await main(['scan', cwd, '--format', 'json'], {
      stdout,
      stderr: sink(),
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 0);
    const parsed = JSON.parse(stdout.text);
    assert.equal(parsed.summary.total, 1);
    assert.equal(parsed.findings[0].id, 'CVE-2020-11111');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('main names the findings it suppressed', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    await writeFile(join(cwd, '.fixqueueignore'), 'CVE-2021-44228 reason="accepted risk"\n', 'utf8');
    await writeDistinctScans(cwd);
    const stdout = sink();
    const code = await main(['scan', cwd, '--format', 'json'], {
      stdout,
      stderr: sink(),
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 0);
    const parsed = JSON.parse(stdout.text);
    assert.equal(parsed.suppressed.length, 1);
    assert.equal(parsed.suppressed[0].id, 'CVE-2021-44228');
    assert.equal(parsed.suppressed[0].matcher, 'CVE-2021-44228');
    assert.equal(parsed.suppressed[0].reason, 'accepted risk');
    assert.equal(parsed.findings.length, 1);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('main flags expired suppression rules and still reports the finding', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    await writeFile(join(cwd, '.fixqueueignore'), 'CVE-2021-44228 expires=2020-01-01\n', 'utf8');
    await writeDistinctScans(cwd);
    const stdout = sink();
    const stderr = sink();
    const code = await main(['scan', cwd, '--format', 'json'], {
      stdout,
      stderr,
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 0);
    assert.ok(stderr.text.includes('expired'));
    assert.ok(stderr.text.includes('CVE-2021-44228'));
    const parsed = JSON.parse(stdout.text);
    assert.equal(parsed.suppressed.length, 0);
    assert.equal(parsed.expiredRules.length, 1);
    assert.equal(parsed.expiredRules[0].matcher, 'CVE-2021-44228');
    assert.equal(parsed.findings.length, 2);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('main with the suppress subcommand appends a rule to the ignore file', async () => {
  const { cwd } = await sandbox();
  try {
    const stdout = sink();
    const code = await main(['suppress', 'CVE-2021-44228', '--reason', 'accepted risk', '--expires', '2026-12-01'], {
      stdout,
      stderr: sink(),
      cwd,
      now: NOW,
    });
    assert.equal(code, 0);
    const content = await readFile(join(cwd, '.fixqueueignore'), 'utf8');
    const rules = parseSuppressions(content);
    assert.deepEqual(rules, [
      { matcher: 'CVE-2021-44228', reason: 'accepted risk', expires: '2026-12-01' },
    ]);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('main with the demo subcommand writes output and returns 0', async () => {
  const stdout = sink();
  const code = await main(['demo'], { stdout, stderr: sink(), now: NOW });
  assert.equal(code, 0);
  assert.ok(stdout.text.includes('# fixqueue'));
  assert.ok(stdout.text.includes('CVE-2021-44228'));
});

test('main with no arguments prints usage and returns 2', async () => {
  const stdout = sink();
  const code = await main([], { stdout, stderr: sink() });
  assert.equal(code, 2);
  assert.ok(stdout.text.includes('fixqueue scan'));
});

test('main with an unknown command returns 2', async () => {
  const stderr = sink();
  const code = await main(['frobnicate'], { stdout: sink(), stderr });
  assert.equal(code, 2);
  assert.ok(stderr.text.includes('unknown command'));
});

test('main with the cache subcommand reports the cache status', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    const stdout = sink();
    const code = await main(['cache'], { stdout, stderr: sink(), cwd, now: NOW, cacheDir });
    assert.equal(code, 0);
    const parsed = JSON.parse(stdout.text);
    assert.ok(Array.isArray(parsed.entries));
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('the --fail-on gate considers every finding, not only the --top subset', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    await writeFile(
      join(cwd, 'mixed.json'),
      JSON.stringify({
        runs: [
          {
            results: [
              {
                ruleId: 'R-1',
                level: 'error',
                message: { text: 'high with intelligence' },
                properties: { tags: ['CVE-2021-44228'], 'security-severity': '7.5' },
              },
              {
                ruleId: 'R-2',
                level: 'error',
                message: { text: 'critical without intelligence' },
                properties: { tags: ['CVE-2026-99999'], 'security-severity': '9.9' },
              },
            ],
          },
        ],
      }),
      'utf8',
    );
    const stdout = sink();
    const code = await main(['scan', cwd, '--format', 'json', '--top', '1', '--fail-on', 'critical'], {
      stdout,
      stderr: sink(),
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 1, 'a critical finding below the --top cut must still fail the gate');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('a scan path is not swallowed by an unknown flag', async () => {
  const { cwd, cacheDir } = await sandbox();
  try {
    await writeFile(
      join(cwd, 'scan.json'),
      JSON.stringify({
        runs: [
          {
            results: [
              {
                ruleId: 'CVE-2021-44228',
                level: 'error',
                message: { text: 'Log4Shell' },
                properties: { 'security-severity': '9.8' },
              },
            ],
          },
        ],
      }),
      'utf8',
    );
    const stdout = sink();
    const stderr = sink();
    const code = await main(['scan', '--verbose', cwd, '--format', 'json'], {
      stdout,
      stderr,
      fetchImpl: fakeFetch(),
      cwd,
      now: NOW,
      cacheDir,
    });
    assert.equal(code, 0, stderr.text);
    const parsed = JSON.parse(stdout.text);
    assert.equal(parsed.findings.length, 1);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
