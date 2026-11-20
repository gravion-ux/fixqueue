import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildSuppressionIndex,
  findSuppression,
  formatSuppression,
  isExpiredRule,
  isSuppressed,
  matchesSuppression,
  parseSuppressions,
} from '../src/suppress.js';

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

test('matchesSuppression matches an advisory id without regard to case', () => {
  assert.equal(matchesSuppression(finding(), 'cve-2021-44228'), true);
  assert.equal(matchesSuppression(finding(), 'CVE-2021-44228'), true);
  assert.equal(matchesSuppression(finding(), 'CVE-2020-11111'), false);
});

test('matchesSuppression matches an alias', () => {
  assert.equal(matchesSuppression(finding(), 'GHSA-jfh8-c2jp-5v3q'), true);
  assert.equal(matchesSuppression(finding(), 'ghsa-jfh8-c2jp-5v3q'), true);
});

test('matchesSuppression matches a package matcher exactly', () => {
  assert.equal(matchesSuppression(finding(), 'lodash@4.17.20'), true);
  assert.equal(matchesSuppression(finding(), 'lodash@4.17.21'), false);
  assert.equal(matchesSuppression(finding(), 'Lodash@4.17.20'), false);
});

test('matchesSuppression matches an ecosystem-qualified package matcher', () => {
  assert.equal(matchesSuppression(finding(), 'npm:lodash@4.17.20'), true);
  assert.equal(matchesSuppression(finding(), 'NPM:lodash@4.17.20'), true);
  assert.equal(matchesSuppression(finding(), 'pypi:lodash@4.17.20'), false);
});

test('matchesSuppression never matches a matcher that names neither an advisory nor a package', () => {
  assert.equal(matchesSuppression(finding(), 'lodash'), false);
});

test('the suppression index agrees with the single-matcher reference', () => {
  const matchers = [
    'CVE-2021-44228',
    'cve-2021-44228',
    'GHSA-jfh8-c2jp-5v3q',
    'npm:lodash@4.17.20',
    'NPM:lodash@4.17.20',
    'pypi:lodash@4.17.20',
    'lodash@4.17.20',
    'lodash@4.17.21',
    'lodash',
    'CVE-2020-11111',
  ];
  const findings = [
    finding(),
    finding({ id: 'CVE-2020-11111', aliases: [] }),
    finding({ id: 'SAFE-1', aliases: [] }),
    finding({ id: 'SAFE-1', aliases: [], package: null }),
    finding({ id: 'SAFE-1', aliases: [], package: { ecosystem: 'npm', name: 'lodash', version: '4.17.21' } }),
    finding({ id: 'SAFE-1', aliases: [], package: { ecosystem: 'pypi', name: 'lodash', version: '4.17.20' } }),
    finding({ id: 'SAFE-1', aliases: [], package: { ecosystem: 'npm', name: 'lodash' } }),
  ];

  for (const matcher of matchers) {
    for (const candidate of findings) {
      const rules = parseSuppressions(`${matcher}\n`);
      const expected = matchesSuppression(candidate, matcher) ? rules[0] : null;
      const index = buildSuppressionIndex(rules, Date.now());
      assert.deepEqual(
        findSuppression(candidate, index),
        expected,
        `index disagreed with the reference for ${matcher}`,
      );
    }
  }
});

test('the suppression index returns the rule that comes first in the file', () => {
  const rules = parseSuppressions(
    ['npm:lodash@4.17.20', 'CVE-2021-44228', 'lodash@4.17.20', ''].join('\n'),
  );
  const index = buildSuppressionIndex(rules, Date.now());
  assert.equal(findSuppression(finding(), index).matcher, 'npm:lodash@4.17.20');
});

test('the suppression index returns the first rule when several match', () => {
  const rules = parseSuppressions(
    ['CVE-2020-11111', 'npm:lodash@4.17.20', 'CVE-2021-44228'].join('\n'),
  );
  const index = buildSuppressionIndex(rules, Date.now());
  assert.equal(findSuppression(finding(), index).matcher, 'npm:lodash@4.17.20');
});

test('the suppression index drops an expired rule', () => {
  const rules = parseSuppressions('CVE-2021-44228 expires=2020-01-01\n');
  const index = buildSuppressionIndex(rules, Date.now());
  assert.equal(findSuppression(finding(), index), null);
});

test('the suppression index keeps a rule valid through the end of its expiry day', () => {
  const rules = parseSuppressions('CVE-2021-44228 expires=2026-12-01\n');
  const endOfDay = Date.parse('2026-12-01T23:59:59.999Z');
  const index = buildSuppressionIndex(rules, endOfDay);
  assert.ok(findSuppression(finding(), index));
  const expired = buildSuppressionIndex(rules, endOfDay + 1);
  assert.equal(findSuppression(finding(), expired), null);
});

test('the suppression index matches the same rules as the per-finding lookup', () => {
  const rules = parseSuppressions(
    [
      'CVE-2021-44228 reason="accepted risk"',
      'npm:lodash@4.17.20 reason="internal fork"',
      'lodash@4.17.20 reason="not reachable"',
      'CVE-2020-11111 expires=2020-01-01',
    ].join('\n'),
  );
  const index = buildSuppressionIndex(rules, Date.now());
  const candidates = [
    finding(),
    finding({ id: 'CVE-2020-11111', aliases: [] }),
    finding({ id: 'SAFE-1', aliases: [], package: null }),
  ];
  for (const candidate of candidates) {
    assert.deepEqual(
      findSuppression(candidate, index),
      isSuppressed(candidate, rules, Date.now()),
      'the index and the per-finding lookup disagreed',
    );
  }
});

/**
 * Walk the rules one by one, the way the tool did before the index existed.
 * @param {object} candidate - Canonical finding.
 * @param {object[]} rules - Parsed rules.
 * @param {number} now - Current time.
 * @returns {object|null} The first matching, unexpired rule, or null.
 */
function referenceSuppression(candidate, rules, now) {
  for (const rule of rules) {
    if (!rule || typeof rule.matcher !== 'string') continue;
    if (isExpiredRule(rule, now)) continue;
    if (matchesSuppression(candidate, rule.matcher)) return rule;
  }
  return null;
}

/**
 * Build a deterministic pseudo-random generator, so a failure can be replayed.
 * @param {number} seed - The seed.
 * @returns {() => number} A generator of numbers in [0, 1).
 */
function random(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test('the suppression index agrees with the rule-by-rule walk over random cases', () => {
  const next = random(20261119);
  const pick = (items) => items[Math.floor(next() * items.length)];
  const ecosystems = ['npm', 'pypi', 'go', 'cargo', 'NPM', ''];
  const names = ['lodash', 'requests', 'serde', 'left-pad', 'foo:bar', ''];
  const versions = ['4.17.20', '1.0.0', '2.3', ''];
  const advisoryIds = ['CVE-2021-44228', 'cve-2021-44228', 'GHSA-jfh8-c2jp-5v3q', 'OSV-2021-1'];
  const now = Date.parse('2026-11-19T00:00:00.000Z');

  for (let round = 0; round < 200; round += 1) {
    const lines = [];
    const ruleCount = 1 + Math.floor(next() * 12);
    for (let rule = 0; rule < ruleCount; rule += 1) {
      const kind = next();
      let matcher;
      if (kind < 0.4) {
        matcher = pick(advisoryIds);
      } else if (kind < 0.75) {
        matcher = `${pick(ecosystems)}:${pick(names)}@${pick(versions)}`;
      } else if (kind < 0.95) {
        matcher = `${pick(names)}@${pick(versions)}`;
      } else {
        matcher = pick(names);
      }
      const expiry = next() < 0.25 ? ' expires=2020-01-01' : '';
      lines.push(`${matcher}${expiry}`);
    }
    const rules = parseSuppressions(lines.join('\n'));
    const index = buildSuppressionIndex(rules, now);

    for (let candidateIndex = 0; candidateIndex < 12; candidateIndex += 1) {
      const hasPackage = next() > 0.2;
      const candidate = finding({
        id: next() < 0.6 ? pick(advisoryIds) : `SAFE-${Math.floor(next() * 1000)}`,
        aliases: next() < 0.5 ? [pick(advisoryIds)] : [],
        package: hasPackage
          ? { ecosystem: pick(ecosystems), name: pick(names), version: pick(versions) }
          : null,
      });
      const expected = referenceSuppression(candidate, rules, now);
      const actual = findSuppression(candidate, index);
      assert.deepEqual(
        actual,
        expected,
        `round ${round} candidate ${candidateIndex} disagreed: rules ${JSON.stringify(lines)}`,
      );
    }
  }
});
