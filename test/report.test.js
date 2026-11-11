import test from 'node:test';
import assert from 'node:assert/strict';

import { toMarkdown, toJson, toSarif } from '../src/report.js';

/**
 * Build a ranked canonical finding for report tests.
 * @param {object} [overrides] - Fields overriding the defaults.
 * @returns {object} A canonical finding.
 */
function finding(overrides = {}) {
  return {
    id: 'CVE-2021-44228',
    aliases: ['GHSA-jfh8-c2jp-5v3q'],
    title: 'Apache Log4Shell',
    severity: 'critical',
    score: 95,
    scoreBreakdown: { epss: 40, kev: 35, severity: 20, occurrences: 0 },
    package: { ecosystem: 'npm', name: 'log4j-js', version: '2.0.0' },
    locations: ['app/package-lock.json:12'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
    tools: ['trivy', 'sarif'],
    occurrences: 2,
    epss: { score: 0.97, percentile: 1, date: '2026-11-04' },
    kev: { listed: true, dueDate: '2021-12-10', ransomware: true },
    ...overrides,
  };
}

const META = {
  generatedAt: '2026-11-05T10:00:00.000Z',
  tool: 'fixqueue',
  epssDate: '2026-11-04',
  kevVersion: '2026.11.04',
  cacheAge: 'fresh',
};

test('toMarkdown contains the title, timestamp and summary counts', () => {
  const markdown = toMarkdown([finding()], META);
  assert.ok(markdown.includes('# fixqueue'));
  assert.ok(markdown.includes('2026-11-05T10:00:00.000Z'));
  assert.ok(markdown.includes('| critical | 1 |'));
  assert.ok(markdown.includes('| **total** | **1** |'));
});

test('toMarkdown renders one row per finding with score, severity, id, package and tools', () => {
  const markdown = toMarkdown([finding()], META);
  assert.ok(markdown.includes('| 95 | critical | CVE-2021-44228 | npm:log4j-js@2.0.0 | app/package-lock.json:12 | trivy, sarif |'));
});

test('toMarkdown preserves the order of the supplied queue', () => {
  const markdown = toMarkdown(
    [finding({ id: 'CVE-2' }), finding({ id: 'CVE-1' })],
    META,
  );
  assert.ok(markdown.indexOf('CVE-2') < markdown.indexOf('CVE-1'));
});

test('toMarkdown escapes pipe characters inside cell values', () => {
  const markdown = toMarkdown([finding({ id: 'a|b' })], META);
  assert.ok(markdown.includes('a\\|b'));
});

test('toMarkdown renders an empty queue without throwing', () => {
  const markdown = toMarkdown([], META);
  assert.ok(markdown.includes('_No findings._'));
});

test('toMarkdown lists suppressed findings and expired rules', () => {
  const markdown = toMarkdown([], {
    ...META,
    suppressedList: [
      { id: 'CVE-2020-11111', severity: 'high', matcher: 'CVE-2020-11111', reason: 'accepted risk', expires: null },
    ],
    expiredRules: [{ matcher: 'CVE-2019-0001', expires: '2020-01-01', reason: null }],
  });
  assert.ok(markdown.includes('## Suppressed findings'));
  assert.ok(markdown.includes('| CVE-2020-11111 | high | CVE-2020-11111 | accepted risk |'));
  assert.ok(markdown.includes('## Expired suppression rules'));
  assert.ok(markdown.includes('| CVE-2019-0001 | 2020-01-01 |'));
});

test('toJson carries the suppressed findings and the expired rules', () => {
  const parsed = JSON.parse(
    toJson([], {
      ...META,
      suppressedList: [
        { id: 'CVE-2020-11111', severity: 'high', matcher: 'CVE-2020-11111', reason: 'accepted risk', expires: null },
      ],
      expiredRules: [{ matcher: 'CVE-2019-0001', expires: '2020-01-01', reason: null }],
    }),
  );
  assert.equal(parsed.suppressed.length, 1);
  assert.equal(parsed.suppressed[0].id, 'CVE-2020-11111');
  assert.equal(parsed.expiredRules.length, 1);
  assert.equal(parsed.expiredRules[0].matcher, 'CVE-2019-0001');
});

test('toJson parses as valid JSON with a summary object and the full findings array', () => {
  const parsed = JSON.parse(toJson([finding(), finding({ id: 'CVE-2020-11111' })], META));
  assert.equal(typeof parsed.summary, 'object');
  assert.equal(parsed.summary.total, 2);
  assert.equal(parsed.findings.length, 2);
  assert.equal(parsed.findings[0].id, 'CVE-2021-44228');
});

test('toJson is pretty-printed with two-space indentation', () => {
  const output = toJson([finding()], META);
  assert.ok(output.includes('\n  "tool": "fixqueue"'));
  assert.ok(output.includes('\n      "id": "CVE-2021-44228"'));
});

test('toJson renders an empty queue without throwing', () => {
  const parsed = JSON.parse(toJson([], META));
  assert.deepEqual(parsed.findings, []);
  assert.equal(parsed.summary.total, 0);
});

test('toSarif parses as valid SARIF with one run', () => {
  const parsed = JSON.parse(toSarif([finding()], META));
  assert.equal(parsed.version, '2.1.0');
  assert.equal(parsed.runs.length, 1);
  assert.equal(parsed.runs[0].tool.driver.name, 'fixqueue');
});

test('toSarif emits one result per finding keyed by the advisory id', () => {
  const parsed = JSON.parse(toSarif([finding(), finding({ id: 'CVE-2020-11111' })], META));
  const results = parsed.runs[0].results;
  assert.equal(results.length, 2);
  assert.equal(results[0].ruleId, 'CVE-2021-44228');
  assert.equal(results[1].ruleId, 'CVE-2020-11111');
});

test('toSarif maps severity onto SARIF levels', () => {
  const parsed = JSON.parse(
    toSarif(
      [
        finding({ id: 'A', severity: 'critical' }),
        finding({ id: 'B', severity: 'high' }),
        finding({ id: 'C', severity: 'medium' }),
        finding({ id: 'D', severity: 'low' }),
        finding({ id: 'E', severity: 'info' }),
      ],
      META,
    ),
  );
  assert.deepEqual(
    parsed.runs[0].results.map((result) => result.level),
    ['error', 'error', 'warning', 'note', 'note'],
  );
});

test('toSarif carries artifact locations with line numbers', () => {
  const parsed = JSON.parse(toSarif([finding()], META));
  const physical = parsed.runs[0].results[0].locations[0].physicalLocation;
  assert.equal(physical.artifactLocation.uri, 'app/package-lock.json');
  assert.equal(physical.region.startLine, 12);
});

test('toSarif renders an empty queue without throwing', () => {
  const parsed = JSON.parse(toSarif([], META));
  assert.deepEqual(parsed.runs[0].results, []);
});
