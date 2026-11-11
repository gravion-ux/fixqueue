import test from 'node:test';
import assert from 'node:assert/strict';

import { parseSuppressions, isSuppressed, isExpiredRule, formatSuppression } from '../src/suppress.js';

/**
 * Build a canonical finding for suppression tests.
 * @param {object} [overrides] - Fields overriding the defaults.
 * @returns {object} A canonical finding.
 */
function finding(overrides = {}) {
  return {
    id: 'CVE-2021-44228',
    aliases: ['GHSA-jfh8-c2jp-5v3q'],
    title: 'Apache Log4Shell',
    severity: 'critical',
    package: { ecosystem: 'npm', name: 'lodash', version: '4.17.20' },
    locations: ['app/package-lock.json:12'],
    references: [],
    tools: ['trivy'],
    occurrences: 1,
    ...overrides,
  };
}

test('comment lines are ignored', () => {
  assert.deepEqual(parseSuppressions('# just a comment\n'), []);
});

test('blank lines are ignored', () => {
  assert.deepEqual(parseSuppressions('\n\n   \n'), []);
});

test('a bare advisory id parses with no reason and no expiry', () => {
  assert.deepEqual(parseSuppressions('CVE-2021-44228\n'), [
    { matcher: 'CVE-2021-44228', reason: null, expires: null },
  ]);
});

test('a quoted reason is parsed', () => {
  const rules = parseSuppressions('CVE-2021-44228 reason="accepted risk"\n');
  assert.equal(rules[0].reason, 'accepted risk');
  assert.equal(rules[0].matcher, 'CVE-2021-44228');
});

test('an expiry date is parsed', () => {
  const rules = parseSuppressions('CVE-2021-44228 expires=2026-12-01\n');
  assert.equal(rules[0].expires, '2026-12-01');
});

test('a trailing comment does not break parsing', () => {
  const rules = parseSuppressions('CVE-2021-44228 # reviewed by the security team\n');
  assert.equal(rules.length, 1);
  assert.equal(rules[0].matcher, 'CVE-2021-44228');
});

test('isSuppressed matches the finding id', () => {
  const rules = parseSuppressions('CVE-2021-44228\n');
  assert.ok(isSuppressed(finding(), rules, Date.now()));
});

test('isSuppressed matches an alias of the finding', () => {
  const rules = parseSuppressions('GHSA-jfh8-c2jp-5v3q\n');
  assert.ok(isSuppressed(finding(), rules, Date.now()));
});

test('isSuppressed matches an ecosystem-qualified package matcher', () => {
  const rules = parseSuppressions('npm:lodash@4.17.20\n');
  assert.ok(isSuppressed(finding(), rules, Date.now()));
});

test('isSuppressed matches a bare package name and version matcher', () => {
  const rules = parseSuppressions('lodash@4.17.20\n');
  assert.ok(isSuppressed(finding(), rules, Date.now()));
});

test('isSuppressed does not match a package in a different ecosystem', () => {
  const rules = parseSuppressions('pypi:lodash@4.17.20\n');
  assert.equal(isSuppressed(finding(), rules, Date.now()), null);
});

test('isSuppressed returns null when no rule applies', () => {
  const rules = parseSuppressions('CVE-2020-11111\n');
  assert.equal(isSuppressed(finding(), rules, Date.now()), null);
});

test('an expired rule does not suppress', () => {
  const rules = parseSuppressions('CVE-2021-44228 expires=2020-01-01\n');
  assert.equal(isSuppressed(finding(), rules, Date.now()), null);
});

test('an expiry date is valid through the end of that day', () => {
  const rules = parseSuppressions('CVE-2021-44228 expires=2026-12-01\n');
  const endOfDay = Date.parse('2026-12-01T23:59:59.999Z');
  assert.ok(isSuppressed(finding(), rules, endOfDay));
  assert.equal(isSuppressed(finding(), rules, endOfDay + 1), null);
});

test('isExpiredRule reports a rule as expired after its expiry day', () => {
  const rule = { matcher: 'CVE-2021-44228', reason: null, expires: '2020-01-01' };
  assert.equal(isExpiredRule(rule, Date.parse('2020-01-02T00:00:00.000Z')), true);
});

test('isExpiredRule keeps a rule valid through the end of its expiry day', () => {
  const rule = { matcher: 'CVE-2021-44228', reason: null, expires: '2026-12-01' };
  assert.equal(isExpiredRule(rule, Date.parse('2026-12-01T23:59:59.999Z')), false);
  assert.equal(isExpiredRule(rule, Date.parse('2026-12-02T00:00:00.000Z')), true);
});

test('isExpiredRule never expires a rule without an expiry date', () => {
  assert.equal(isExpiredRule({ matcher: 'CVE-2021-44228', reason: null, expires: null }, Date.now()), false);
});

test('formatSuppression round-trips through parseSuppressions', () => {
  const rule = { matcher: 'CVE-2021-44228', reason: 'accepted risk', expires: '2026-12-01' };
  const parsed = parseSuppressions(`${formatSuppression(rule)}\n`);
  assert.deepEqual(parsed, [rule]);
});

test('formatSuppression omits absent reason and expiry', () => {
  assert.equal(formatSuppression({ matcher: 'CVE-2021-44228' }), 'CVE-2021-44228');
});
