/**
 * fixqueue — attachment of EPSS and CISA KEV intelligence to findings.
 * @module fixqueue/enrich
 */

/**
 * Collect the advisory identifiers a finding can be looked up by.
 * @param {object} finding - Canonical finding.
 * @returns {string[]} The finding id followed by its aliases.
 */
function lookupKeys(finding) {
  const keys = [];
  if (typeof finding.id === 'string' && finding.id) keys.push(finding.id);
  for (const alias of Array.isArray(finding.aliases) ? finding.aliases : []) {
    if (typeof alias === 'string' && alias && !keys.includes(alias)) keys.push(alias);
  }
  return keys;
}

/**
 * Attach EPSS probability data to a finding.
 *
 * The input finding is never mutated; a new object is returned. When no EPSS
 * record exists the finding is returned unchanged.
 * @param {object} finding - Canonical finding.
 * @param {Record<string, { score: number, percentile: number, date: string }>} epssMap - EPSS records keyed by CVE.
 * @returns {object} A finding copy carrying an `epss` property when data is available.
 */
export function mergeEpss(finding, epssMap) {
  const source = finding && typeof finding === 'object' ? finding : {};
  const map = epssMap && typeof epssMap === 'object' ? epssMap : {};
  for (const key of lookupKeys(source)) {
    const record = map[key];
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
 * Attach CISA KEV catalogue status to a finding.
 *
 * The input finding is never mutated. Findings that are not listed receive
 * `kev.listed === false` so callers can distinguish "not known exploited" from
 * "never checked".
 * @param {object} finding - Canonical finding.
 * @param {Record<string, { dueDate: string|null, ransomware: boolean, vendor: string|null, name: string|null }>} kevMap
 *   KEV records keyed by CVE.
 * @returns {object} A finding copy carrying a `kev` property.
 */
export function mergeKev(finding, kevMap) {
  const source = finding && typeof finding === 'object' ? finding : {};
  const map = kevMap && typeof kevMap === 'object' ? kevMap : {};
  for (const key of lookupKeys(source)) {
    const record = map[key];
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
 * Apply EPSS and KEV intelligence to every finding in a list.
 *
 * Neither the input array nor the findings inside it are mutated.
 * @param {object[]} findings - Canonical findings.
 * @param {{ epss?: object, kev?: object }} [maps] - Enrichment maps.
 * @returns {object[]} A new array of enriched findings.
 */
export function enrich(findings, maps = {}) {
  const list = Array.isArray(findings) ? findings : [];
  const epssMap = maps.epss && typeof maps.epss === 'object' ? maps.epss : {};
  const kevMap = maps.kev && typeof maps.kev === 'object' ? maps.kev : {};
  return list.map((finding) => mergeKev(mergeEpss(finding, epssMap), kevMap));
}
