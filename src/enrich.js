/**
 * fixqueue — attachment of EPSS and CISA KEV intelligence to findings.
 * @module fixqueue/enrich
 */

/**
 * Normalise an identifier for case-insensitive comparison.
 * @param {unknown} value - Identifier to normalise.
 * @returns {string} The uppercased identifier, or an empty string.
 */
function normalizeKey(value) {
  return typeof value === 'string' ? value.toUpperCase() : '';
}

/**
 * Build a case-insensitive index of an enrichment map.
 *
 * The index is built once per enrichment pass so that every finding is matched
 * with a single lookup, regardless of the letter case used by the feed.
 * @param {Record<string, object>|undefined} map - Enrichment records keyed by identifier.
 * @returns {Map<string, object>} Records keyed by their uppercased identifier.
 */
function normalizeIndex(map) {
  const index = new Map();
  if (!map || typeof map !== 'object') return index;
  for (const [key, value] of Object.entries(map)) {
    if (!value || typeof value !== 'object') continue;
    const normalized = normalizeKey(key);
    if (!normalized || index.has(normalized)) continue;
    index.set(normalized, value);
  }
  return index;
}

/**
 * Collect every identity token a finding can be looked up by.
 * @param {object} finding - Canonical finding.
 * @returns {string[]} The finding id followed by its aliases, uppercased.
 */
function lookupKeys(finding) {
  const keys = [];
  const push = (value) => {
    if (typeof value !== 'string' || !value) return;
    const key = value.toUpperCase();
    if (!keys.includes(key)) keys.push(key);
  };
  push(finding.id);
  for (const alias of Array.isArray(finding.aliases) ? finding.aliases : []) {
    push(alias);
  }
  return keys;
}

/**
 * Attach EPSS probability data to a finding using a prebuilt index.
 * @param {object} finding - Canonical finding.
 * @param {Map<string, object>} index - EPSS records keyed by uppercased identifier.
 * @returns {object} A finding copy carrying an `epss` property when data is available.
 */
function mergeEpssWithIndex(finding, index) {
  const source = finding && typeof finding === 'object' ? finding : {};
  for (const key of lookupKeys(source)) {
    const record = index.get(key);
    if (record && typeof record === 'object') {
      return {
        ...source,
        epss: {
          score: Number(record.score) || 0,
          percentile: Number(record.percentile) || 0,
          date: record.date ?? null,
        },
      };
    }
  }
  return { ...source };
}

/**
 * Attach CISA KEV catalogue status to a finding using a prebuilt index.
 * @param {object} finding - Canonical finding.
 * @param {Map<string, object>} index - KEV records keyed by uppercased identifier.
 * @returns {object} A finding copy carrying a `kev` property.
 */
function mergeKevWithIndex(finding, index) {
  const source = finding && typeof finding === 'object' ? finding : {};
  for (const key of lookupKeys(source)) {
    const record = index.get(key);
    if (record && typeof record === 'object') {
      return {
        ...source,
        kev: {
          listed: true,
          dueDate: record.dueDate ?? null,
          ransomware: Boolean(record.ransomware),
          vendor: record.vendor ?? null,
          name: record.name ?? null,
        },
      };
    }
  }
  return { ...source, kev: { listed: false, dueDate: null, ransomware: false, vendor: null, name: null } };
}

/**
 * Attach EPSS probability data to a finding.
 *
 * The input finding is never mutated; a new object is returned. When no EPSS
 * record exists the finding is returned unchanged. Identifiers are matched
 * without regard to letter case, because the feeds publish uppercased CVE ids
 * while scanners frequently emit lowercase ones.
 * @param {object} finding - Canonical finding.
 * @param {Record<string, { score: number, percentile: number, date: string }>} epssMap - EPSS records keyed by CVE.
 * @returns {object} A finding copy carrying an `epss` property when data is available.
 */
export function mergeEpss(finding, epssMap) {
  return mergeEpssWithIndex(finding, normalizeIndex(epssMap));
}

/**
 * Attach CISA KEV catalogue status to a finding.
 *
 * The input finding is never mutated. Findings that are not listed receive
 * `kev.listed === false` so callers can distinguish "not known exploited" from
 * "never checked". Identifiers are matched without regard to letter case.
 * @param {object} finding - Canonical finding.
 * @param {Record<string, { dueDate: string|null, ransomware: boolean, vendor: string|null, name: string|null }>} kevMap
 *   KEV records keyed by CVE.
 * @returns {object} A finding copy carrying a `kev` property.
 */
export function mergeKev(finding, kevMap) {
  return mergeKevWithIndex(finding, normalizeIndex(kevMap));
}

/**
 * Apply EPSS and KEV intelligence to every finding in a list.
 *
 * Neither the input array nor the findings inside it are mutated. Both maps are
 * indexed once, so the cost per finding stays constant no matter how many
 * records the feeds carry.
 * @param {object[]} findings - Canonical findings.
 * @param {{ epss?: object, kev?: object }} [maps] - Enrichment maps.
 * @returns {object[]} A new array of enriched findings.
 */
export function enrich(findings, maps = {}) {
  const list = Array.isArray(findings) ? findings : [];
  const source = maps && typeof maps === 'object' ? maps : {};
  const epssIndex = normalizeIndex(source.epss);
  const kevIndex = normalizeIndex(source.kev);
  return list.map((finding) => mergeKevWithIndex(mergeEpssWithIndex(finding, epssIndex), kevIndex));
}
