import test from 'node:test';
import assert from 'node:assert/strict';

import { severityWeight, scoreFinding, rank } from '../src/score.js';

/**
 * Build a canonical finding for scoring tests.
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
    references: [],
    tools: ['trivy'],
    occurrences: 1,
    ...overrides,
  };
}

test('severityWeight returns the documented weight for each canonical severity', () => {
  assert.equal(severityWeight('critical'), 20);
  assert.equal(severityWeight('high'), 15);
  assert.equal(severityWeight('medium'), 10);
  assert.equal(severityWeight('low'), 5);
  assert.equal(severityWeight('info'), 0);
});

test('severityWeight returns 0 for an unknown severity', () => {
  assert.equal(severityWeight('catastrophic'), 0);
  assert.equal(severityWeight(undefined), 0);
  assert.equal(severityWeight(null), 0);
});

test('scoreFinding scores a finding that carries no enrichment', () => {
  const { score, breakdown } = scoreFinding(finding());
  assert.equal(breakdown.epss, 0);
  assert.equal(breakdown.kev, 0);
  assert.equal(breakdown.severity, 15);
  assert.equal(breakdown.occurrences, 0);
  assert.equal(score, 15);
});

test('EPSS contributes 40 times the percentile', () => {
  const { breakdown } = scoreFinding(finding({ epss: { score: 0.5, percentile: 0.5, date: '2026-11-04' } }));
  assert.equal(breakdown.epss, 20);
});

test('a KEV-listed finding gains 30 points', () => {
  const { breakdown } = scoreFinding(finding({ kev: { listed: true, ransomware: false } }));
  assert.equal(breakdown.kev, 30);
});

test('a KEV-listed ransomware finding gains 35 points', () => {
  const { breakdown } = scoreFinding(finding({ kev: { listed: true, ransomware: true } }));
  assert.equal(breakdown.kev, 35);
});

test('a finding not present in KEV gains no KEV points', () => {
  const { breakdown } = scoreFinding(finding({ kev: { listed: false } }));
  assert.equal(breakdown.kev, 0);
});

test('occurrences contribute at most 5 points beyond the first report', () => {
  assert.equal(scoreFinding(finding({ occurrences: 1 })).breakdown.occurrences, 0);
  assert.equal(scoreFinding(finding({ occurrences: 2 })).breakdown.occurrences, 1);
  assert.equal(scoreFinding(finding({ occurrences: 6 })).breakdown.occurrences, 5);
  assert.equal(scoreFinding(finding({ occurrences: 50 })).breakdown.occurrences, 5);
});

test('the maximum reachable score is exactly 100', () => {
  const { score, breakdown } = scoreFinding(
    finding({
      severity: 'critical',
      occurrences: 6,
      epss: { score: 0.99, percentile: 1, date: '2026-11-04' },
      kev: { listed: true, ransomware: true },
    }),
  );
  assert.equal(breakdown.epss, 40);
  assert.equal(breakdown.kev, 35);
  assert.equal(breakdown.severity, 20);
  assert.equal(breakdown.occurrences, 5);
  assert.equal(score, 100);
});

test('the breakdown sums exactly to the score', () => {
  const cases = [
    finding(),
    finding({ severity: 'critical', epss: { percentile: 0.9946, score: 0.97 }, kev: { listed: true, ransomware: true } }),
    finding({ severity: 'low', occurrences: 4, epss: { percentile: 0.123456, score: 0.02 } }),
  ];
  for (const item of cases) {
    const { score, breakdown } = scoreFinding(item);
    assert.equal(breakdown.epss + breakdown.kev + breakdown.severity + breakdown.occurrences, score);
  }
});

test('the score is never above 100', () => {
  for (const item of [
    finding({ severity: 'critical', occurrences: 99, epss: { percentile: 1 }, kev: { listed: true, ransomware: true } }),
    finding({ severity: 'critical', occurrences: 99, epss: { percentile: 1.5 }, kev: { listed: true, ransomware: true } }),
  ]) {
    assert.ok(scoreFinding(item).score <= 100);
  }
});

test('rank sorts findings by descending score', () => {
  const ranked = rank([
    finding({ id: 'A', severity: 'low' }),
    finding({ id: 'B', severity: 'critical' }),
    finding({ id: 'C', severity: 'medium' }),
  ]);
  assert.deepEqual(ranked.map((item) => item.id), ['B', 'C', 'A']);
});

test('rank preserves input order for equal scores', () => {
  const ranked = rank([
    finding({ id: 'A', severity: 'high' }),
    finding({ id: 'B', severity: 'high' }),
    finding({ id: 'C', severity: 'high' }),
  ]);
  assert.deepEqual(ranked.map((item) => item.id), ['A', 'B', 'C']);
});

test('rank attaches score and scoreBreakdown without mutating the input', () => {
  const input = [finding({ id: 'A' })];
  const ranked = rank(input);
  assert.equal(ranked[0].score, 15);
  assert.deepEqual(ranked[0].scoreBreakdown, { epss: 0, kev: 0, severity: 15, occurrences: 0 });
  assert.equal(input[0].score, undefined);
});
