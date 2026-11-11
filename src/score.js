/**
 * fixqueue — deterministic priority scoring and ranking.
 * @module fixqueue/score
 */

/**
 * Weight contributed by each canonical severity.
 * @type {Record<string, number>}
 */
const SEVERITY_WEIGHT = Object.freeze({
  critical: 20,
  high: 15,
  medium: 10,
  low: 5,
  info: 0,
});

/**
 * Return the scoring weight of a severity.
 * @param {unknown} severity - Canonical severity name.
 * @returns {number} Weight in points; 0 for an unknown severity.
 */
export function severityWeight(severity) {
  if (typeof severity !== 'string') return 0;
  return SEVERITY_WEIGHT[severity] ?? 0;
}

/**
 * Compute the priority score of a finding.
 *
 * The maximum reachable score is exactly 100: 40 EPSS points, 35 KEV points,
 * 20 severity points and 5 occurrence points.
 * @param {object} finding - Canonical finding, optionally carrying `epss` and `kev`.
 * @returns {{ score: number, breakdown: { epss: number, kev: number, severity: number, occurrences: number } }}
 *   The total score and its component breakdown.
 */
export function scoreFinding(finding) {
  const source = finding && typeof finding === 'object' ? finding : {};
  const rawPercentile = source.epss && Number.isFinite(Number(source.epss.percentile))
    ? Number(source.epss.percentile)
    : 0;
  const percentile = Math.min(1, Math.max(0, rawPercentile));
  const epss = Math.round(40 * percentile * 100) / 100;
  const kev = source.kev && source.kev.listed ? (source.kev.ransomware ? 35 : 30) : 0;
  const severity = severityWeight(source.severity);
  const reported = Number.isFinite(source.occurrences) ? source.occurrences : 1;
  const occurrences = Math.min(5, Math.max(0, reported - 1));
  const breakdown = { epss, kev, severity, occurrences };
  return { score: breakdown.epss + breakdown.kev + breakdown.severity + breakdown.occurrences, breakdown };
}

/**
 * Score and rank findings from most to least urgent.
 *
 * Ties preserve input order. The returned findings are copies that carry `score`
 * and `scoreBreakdown`; the input array and its findings are not mutated.
 * @param {object[]} findings - Canonical findings to rank.
 * @returns {object[]} A new array of scored findings sorted by descending score.
 */
export function rank(findings) {
  const list = Array.isArray(findings) ? findings : [];
  return list
    .map((finding, index) => {
      const { score, breakdown } = scoreFinding(finding);
      return { index, score, finding: { ...finding, score, scoreBreakdown: breakdown } };
    })
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .map((entry) => entry.finding);
}
