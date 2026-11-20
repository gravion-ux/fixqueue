/**
 * fixqueue — merge multiple security scanner outputs into one prioritized fix queue.
 * @module fixqueue
 */
export { normalizeSarif, normalizeTrivy, normalizeGrype, normalizeOsv, detectFormat, normalizeAny } from './normalize.js';
export { findingKey, dedupe } from './dedupe.js';
export { enrich, mergeEpss, mergeKev } from './enrich.js';
export { scoreFinding, rank, severityWeight } from './score.js';
export { toMarkdown, toJson, toSarif } from './report.js';
export {
  buildSuppressionIndex,
  findSuppression,
  formatSuppression,
  isExpiredRule,
  isSuppressed,
  matchesSuppression,
  parseSuppressions,
} from './suppress.js';
export { readCache, writeCache, cacheStatus } from './cache.js';
export { fetchKev, fetchEpss, loadEnrichment } from './feeds.js';
