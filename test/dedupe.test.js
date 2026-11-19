import test from 'node:test';
import assert from 'node:assert/strict';

import { findingKey, dedupe } from '../src/dedupe.js';

/**
 * Build a canonical finding for dedupe tests.
 * @param {object} [overrides] - Fields overriding the defaults.
 * @returns {object} A canonical finding.
 */
function finding(overrides = {}) {
  return {
    id: 'CVE-2021-44228',
    aliases: [],
    title: 'Apache Log4Shell',
    severity: 'high',
    package: { ecosystem: 'npm', name: 'log4j-js', version: '2.0.0' },
    locations: ['app/package-lock.json:12'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
    tools: ['trivy'],
    occurrences: 1,
    ...overrides,
  };
}

test('findingKey prefers an advisory-shaped id', () => {
  assert.equal(findingKey(finding({ id: 'CVE-2021-44228' })), 'CVE-2021-44228');
});

test('findingKey falls back to an advisory-shaped alias', () => {
  const key = findingKey(finding({ id: 'RULE-1', aliases: ['GHSA-jfh8-c2jp-5v3q'] }));
  assert.equal(key, 'GHSA-jfh8-c2jp-5v3q');
});

test('findingKey falls back to a package-scoped key', () => {
  const key = findingKey(finding({ id: 'RULE-1', aliases: [] }));
  assert.equal(key, 'pkg:npm:log4j-js@2.0.0|app/package-lock.json:12');
});

test('findingKey falls back to a lowercased title key', () => {
  const key = findingKey(finding({ id: 'RULE-1', aliases: [], package: null, title: 'Weird Thing' }));
  assert.equal(key, 'title:weird thing');
});

test('two findings sharing an advisory id merge into one', () => {
  const merged = dedupe([finding(), finding({ tools: ['sarif'] })]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].occurrences, 2);
});

test('two findings with intersecting aliases merge', () => {
  const merged = dedupe([
    finding({ id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2021-44228'] }),
    finding({ id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2020-11111'] }),
  ]);
  assert.equal(merged.length, 1);
});

test('alias expansion is symmetric: an id appearing in another alias list merges', () => {
  const merged = dedupe([
    finding({ id: 'CVE-2021-44228', aliases: [] }),
    finding({ id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2021-44228'] }),
  ]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].occurrences, 2);
});

test('a transitive alias chain collapses into a single group', () => {
  const merged = dedupe([
    finding({ id: 'CVE-2021-44228', aliases: [] }),
    finding({ id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2021-44228'] }),
    finding({ id: 'OSV-2021-44228', aliases: ['GHSA-aaaa-bbbb-cccc'] }),
  ]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].occurrences, 3);
});

test('findings with different ids and no shared alias do not merge', () => {
  const merged = dedupe([
    finding({ id: 'CVE-2021-44228' }),
    finding({ id: 'CVE-2020-11111' }),
  ]);
  assert.equal(merged.length, 2);
});

test('merged severity is the maximum across the group', () => {
  const merged = dedupe([
    finding({ severity: 'low' }),
    finding({ severity: 'critical' }),
    finding({ severity: 'medium' }),
  ]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].severity, 'critical');
});

test('merged tools are the sorted unique set', () => {
  const merged = dedupe([
    finding({ tools: ['trivy'] }),
    finding({ tools: ['sarif', 'trivy'] }),
    finding({ tools: ['osv'] }),
  ]);
  assert.deepEqual(merged[0].tools, ['osv', 'sarif', 'trivy']);
});

test('merged occurrences count every contributing report', () => {
  const merged = dedupe([finding({ occurrences: 1 }), finding({ occurrences: 3 })]);
  assert.equal(merged[0].occurrences, 4);
});

test('merged locations and references are the sorted unique union', () => {
  const merged = dedupe([
    finding({ locations: ['b.txt'], references: ['https://b.example'] }),
    finding({ locations: ['a.txt', 'b.txt'], references: ['https://a.example', 'https://b.example'] }),
  ]);
  assert.deepEqual(merged[0].locations, ['a.txt', 'b.txt']);
  assert.deepEqual(merged[0].references, ['https://a.example', 'https://b.example']);
});

test('the first-seen finding supplies the title', () => {
  const merged = dedupe([
    finding({ title: 'First title' }),
    finding({ title: 'Second title' }),
  ]);
  assert.equal(merged[0].title, 'First title');
});

test('the package is taken from the first finding that has one', () => {
  const merged = dedupe([
    finding({ package: null }),
    finding({ package: { ecosystem: 'pypi', name: 'requests', version: '2.0.0' } }),
  ]);
  assert.deepEqual(merged[0].package, { ecosystem: 'pypi', name: 'requests', version: '2.0.0' });
});

test('dedupe preserves first-seen group ordering', () => {
  const merged = dedupe([
    finding({ id: 'CVE-2021-44228' }),
    finding({ id: 'CVE-2020-11111' }),
    finding({ id: 'CVE-2021-44228' }),
  ]);
  assert.equal(merged.length, 2);
  assert.equal(merged[0].id, 'CVE-2021-44228');
  assert.equal(merged[1].id, 'CVE-2020-11111');
});

test('dedupe of an empty or invalid input returns an empty array', () => {
  assert.deepEqual(dedupe([]), []);
  assert.deepEqual(dedupe(undefined), []);
});

test('the merged finding never lists its own id as an alias', () => {
  const merged = dedupe([
    finding({ id: 'RULE-1', aliases: ['CVE-2021-44228'] }),
    finding({ id: 'CVE-2021-44228', aliases: [] }),
  ]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].id, 'CVE-2021-44228');
  assert.ok(!merged[0].aliases.includes(merged[0].id));
});

test('a member advisory id survives the merge as an alias', () => {
  const merged = dedupe([
    finding({ id: 'CVE-2021-44228', aliases: [] }),
    finding({ id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2021-44228'] }),
  ]);
  assert.equal(merged.length, 1);
  assert.ok(merged[0].aliases.includes('GHSA-aaaa-bbbb-cccc'));
});

test('every advisory identifier in a transitive chain survives the merge', () => {
  const merged = dedupe([
    finding({ id: 'CVE-2021-44228', aliases: [] }),
    finding({ id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2021-44228'] }),
    finding({ id: 'OSV-2021-44228', aliases: ['GHSA-aaaa-bbbb-cccc'] }),
  ]);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].aliases, ['GHSA-aaaa-bbbb-cccc', 'OSV-2021-44228']);
});

test('alias exclusion ignores letter case', () => {
  const merged = dedupe([
    finding({ id: 'RULE-1', aliases: ['cve-2021-44228'] }),
    finding({ id: 'CVE-2021-44228', aliases: [] }),
  ]);
  assert.equal(merged.length, 1);
  assert.ok(!merged[0].aliases.some((alias) => alias.toUpperCase() === 'CVE-2021-44228'));
});
