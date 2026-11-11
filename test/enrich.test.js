import test from 'node:test';
import assert from 'node:assert/strict';

import { mergeEpss, mergeKev, enrich } from '../src/enrich.js';

/**
 * Build a canonical finding for enrichment tests.
 * @param {object} [overrides] - Fields overriding the defaults.
 * @returns {object} A canonical finding.
 */
function finding(overrides = {}) {
  return {
    id: 'CVE-2021-44228',
    aliases: [],
    title: 'Apache Log4Shell',
    severity: 'critical',
    package: { ecosystem: 'npm', name: 'log4j-js', version: '2.0.0' },
    locations: ['app/package-lock.json:12'],
    references: [],
    tools: ['trivy'],
    occurrences: 1,
    ...overrides,
  };
}

const EPSS_MAP = {
  'CVE-2021-44228': { score: 0.97, percentile: 0.9946, date: '2026-11-04' },
};

const KEV_MAP = {
  'CVE-2021-44228': { dueDate: '2021-12-10', ransomware: true, vendor: 'Apache', name: 'Log4j2' },
};

test('mergeEpss attaches EPSS data when the CVE is present', () => {
  const result = mergeEpss(finding(), EPSS_MAP);
  assert.deepEqual(result.epss, { score: 0.97, percentile: 0.9946, date: '2026-11-04' });
});

test('mergeEpss leaves a finding without EPSS data untouched', () => {
  const result = mergeEpss(finding({ id: 'CVE-2020-11111' }), EPSS_MAP);
  assert.equal(result.epss, undefined);
});

test('mergeEpss does not mutate the input finding', () => {
  const input = finding();
  mergeEpss(input, EPSS_MAP);
  assert.equal(input.epss, undefined);
});

test('mergeEpss looks a finding up through its aliases', () => {
  const result = mergeEpss(finding({ id: 'GHSA-jfh8-c2jp-5v3q', aliases: ['CVE-2021-44228'] }), EPSS_MAP);
  assert.equal(result.epss.percentile, 0.9946);
});

test('mergeKev attaches the KEV record for a listed CVE', () => {
  const result = mergeKev(finding(), KEV_MAP);
  assert.equal(result.kev.listed, true);
  assert.equal(result.kev.dueDate, '2021-12-10');
  assert.equal(result.kev.ransomware, true);
});

test('mergeKev marks an unlisted CVE as not listed', () => {
  const result = mergeKev(finding({ id: 'CVE-2020-11111' }), KEV_MAP);
  assert.equal(result.kev.listed, false);
});

test('mergeKev does not mutate the input finding', () => {
  const input = finding();
  mergeKev(input, KEV_MAP);
  assert.equal(input.kev, undefined);
});

test('enrich applies both maps to every finding and returns a new array', () => {
  const input = [finding(), finding({ id: 'CVE-2020-11111' })];
  const result = enrich(input, { epss: EPSS_MAP, kev: KEV_MAP });
  assert.notEqual(result, input);
  assert.equal(result.length, 2);
  assert.equal(result[0].epss.percentile, 0.9946);
  assert.equal(result[0].kev.listed, true);
  assert.equal(result[1].epss, undefined);
  assert.equal(result[1].kev.listed, false);
});

test('enrich does not mutate its input array or its finding objects', () => {
  const input = [finding()];
  const before = JSON.stringify(input);
  enrich(input, { epss: EPSS_MAP, kev: KEV_MAP });
  assert.equal(JSON.stringify(input), before);
  assert.equal(input[0].epss, undefined);
  assert.equal(input[0].kev, undefined);
});

test('enrich tolerates missing maps', () => {
  const result = enrich([finding()], {});
  assert.equal(result.length, 1);
  assert.equal(result[0].kev.listed, false);
});
