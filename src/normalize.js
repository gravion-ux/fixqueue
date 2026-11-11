/**
 * fixqueue — format adapters that normalize scanner output into the canonical Finding shape.
 * @module fixqueue/normalize
 */

/**
 * Canonical severity vocabulary, ordered from most to least severe.
 * @type {readonly string[]}
 */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

/** Severity table shared by tools that report uppercase severity words. */
const WORD_SEVERITY = Object.freeze({
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  unknown: 'info',
  none: 'info',
  negligible: 'info',
});

/** Severity table for SARIF result levels. */
const SARIF_LEVEL = Object.freeze({
  error: 'high',
  warning: 'medium',
  note: 'low',
  none: 'info',
});

/** Advisory identifier prefixes recognised across ecosystems. */
const ADVISORY_PREFIX = /^(?:CVE|GHSA|OSV|PYSEC|RUSTSEC|GO|USN|DSA)-/i;

/**
 * Determine whether a value is a plain object.
 * @param {unknown} value - Value to inspect.
 * @returns {boolean} True when the value is a non-null object.
 */
function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Determine whether a string looks like an advisory identifier.
 * @param {unknown} value - Candidate identifier.
 * @returns {boolean} True when the value carries a known advisory prefix.
 */
function isAdvisoryId(value) {
  return typeof value === 'string' && ADVISORY_PREFIX.test(value);
}

/**
 * Map a tool-specific severity word onto the canonical vocabulary.
 * @param {unknown} value - Raw severity word from the source document.
 * @param {Record<string, string>} [table] - Lookup table keyed by lowercase word.
 * @returns {string} One of critical, high, medium, low, info.
 */
function mapSeverity(value, table = WORD_SEVERITY) {
  if (typeof value !== 'string') return 'info';
  return table[value.toLowerCase()] ?? 'info';
}

/**
 * Map a SARIF `security-severity` numeric string onto the canonical vocabulary.
 * @param {unknown} value - Raw numeric score.
 * @returns {string|null} Canonical severity, or null when the score is not numeric.
 */
function severityFromScore(value) {
  if (value === undefined || value === null || value === '') return null;
  const score = Number(value);
  if (!Number.isFinite(score)) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

/**
 * Build a canonical Finding, filling every field the shape requires.
 * @param {object} fields - Partial finding fields.
 * @returns {object} A complete canonical Finding.
 */
function makeFinding(fields) {
  return {
    id: fields.id,
    aliases: fields.aliases ?? [],
    title: fields.title ?? '',
    severity: fields.severity ?? 'info',
    package: fields.package ?? null,
    locations: fields.locations ?? [],
    references: fields.references ?? [],
    tools: fields.tools ?? [],
    occurrences: fields.occurrences ?? 1,
  };
}

/**
 * Normalize a SARIF 2.1.0 document into canonical findings.
 * @param {unknown} doc - Parsed SARIF document.
 * @param {{ tool?: string }} [opts] - Options; `tool` overrides the reported tool name.
 * @returns {object[]} Canonical findings, empty when the document is not SARIF.
 */
export function normalizeSarif(doc, opts = {}) {
  const tool = opts.tool ?? 'sarif';
  if (!isObject(doc) || !Array.isArray(doc.runs)) return [];
  const findings = [];
  for (const run of doc.runs) {
    if (!isObject(run) || !Array.isArray(run.results)) continue;
    for (const result of run.results) {
      if (!isObject(result)) continue;
      const props = isObject(result.properties) ? result.properties : {};
      const tags = Array.isArray(props.tags) ? props.tags.filter((t) => typeof t === 'string') : [];
      const advisories = tags.filter(isAdvisoryId);
      const preferred = advisories.find((t) => /^CVE-/i.test(t)) ?? advisories[0] ?? null;
      const id = preferred ?? (typeof result.ruleId === 'string' && result.ruleId ? result.ruleId : 'unknown');
      const aliases = advisories.filter((t) => t !== id);

      const scored = severityFromScore(props['security-severity']);
      const level = mapSeverity(result.level, SARIF_LEVEL);
      const severity = scored ?? level;

      let title = '';
      if (isObject(result.message) && typeof result.message.text === 'string') {
        title = result.message.text;
      } else if (typeof result.message === 'string') {
        title = result.message;
      }

      const pkg = isObject(props.package) ? props.package : null;
      const packageField =
        pkg && typeof pkg.name === 'string' && pkg.name
          ? {
              ecosystem: typeof pkg.ecosystem === 'string' ? pkg.ecosystem : 'unknown',
              name: pkg.name,
              version: typeof pkg.version === 'string' ? pkg.version : '',
            }
          : null;

      const locations = [];
      const rawLocations = Array.isArray(result.locations) ? result.locations : [];
      for (const location of rawLocations) {
        const physical = isObject(location) && isObject(location.physicalLocation) ? location.physicalLocation : null;
        if (!physical) continue;
        const artifact = isObject(physical.artifactLocation) ? physical.artifactLocation : null;
        const uri = artifact && typeof artifact.uri === 'string' ? artifact.uri : null;
        if (!uri) continue;
        const region = isObject(physical.region) ? physical.region : null;
        const line = region ? Number(region.startLine) : NaN;
        locations.push(Number.isFinite(line) ? `${uri}:${line}` : uri);
      }

      const references = Array.isArray(props.references)
        ? props.references.filter((r) => typeof r === 'string')
        : [];

      findings.push(
        makeFinding({ id, aliases, title, severity, package: packageField, locations, references, tools: [tool] }),
      );
    }
  }
  return findings;
}

/**
 * Normalize a Trivy JSON report into canonical findings.
 * @param {unknown} doc - Parsed Trivy report.
 * @param {{ tool?: string }} [opts] - Options; `tool` overrides the reported tool name.
 * @returns {object[]} Canonical findings, empty when the document is not a Trivy report.
 */
export function normalizeTrivy(doc, opts = {}) {
  const tool = opts.tool ?? 'trivy';
  if (!isObject(doc) || !Array.isArray(doc.Results)) return [];
  const findings = [];
  for (const result of doc.Results) {
    if (!isObject(result) || !Array.isArray(result.Vulnerabilities)) continue;
    const ecosystem = typeof result.Type === 'string' && result.Type ? result.Type : 'unknown';
    const target = typeof result.Target === 'string' ? result.Target : '';
    for (const vulnerability of result.Vulnerabilities) {
      if (!isObject(vulnerability)) continue;
      const id =
        typeof vulnerability.VulnerabilityID === 'string' && vulnerability.VulnerabilityID
          ? vulnerability.VulnerabilityID
          : 'unknown';
      const name = typeof vulnerability.PkgName === 'string' ? vulnerability.PkgName : '';
      const version = typeof vulnerability.InstalledVersion === 'string' ? vulnerability.InstalledVersion : '';
      const packageField = name ? { ecosystem, name, version } : null;

      const locations = [];
      if (target) {
        const pkgId = typeof vulnerability.PkgID === 'string' && vulnerability.PkgID ? vulnerability.PkgID : null;
        locations.push(pkgId ? `${target}:${pkgId}` : target);
      }

      const references = [];
      if (typeof vulnerability.PrimaryURL === 'string' && vulnerability.PrimaryURL) {
        references.push(vulnerability.PrimaryURL);
      }
      if (Array.isArray(vulnerability.References)) {
        for (const reference of vulnerability.References) {
          if (typeof reference === 'string') references.push(reference);
        }
      }

      findings.push(
        makeFinding({
          id,
          title: typeof vulnerability.Title === 'string' ? vulnerability.Title : '',
          severity: mapSeverity(vulnerability.Severity, WORD_SEVERITY),
          package: packageField,
          locations,
          references,
          tools: [tool],
        }),
      );
    }
  }
  return findings;
}

/**
 * Normalize a Grype JSON report into canonical findings.
 * @param {unknown} doc - Parsed Grype report.
 * @param {{ tool?: string }} [opts] - Options; `tool` overrides the reported tool name.
 * @returns {object[]} Canonical findings, empty when the document is not a Grype report.
 */
export function normalizeGrype(doc, opts = {}) {
  const tool = opts.tool ?? 'grype';
  if (!isObject(doc) || !Array.isArray(doc.matches)) return [];
  const findings = [];
  for (const match of doc.matches) {
    if (!isObject(match)) continue;
    const vulnerability = isObject(match.vulnerability) ? match.vulnerability : null;
    if (!vulnerability) continue;
    const artifact = isObject(match.artifact) ? match.artifact : null;
    const id = typeof vulnerability.id === 'string' && vulnerability.id ? vulnerability.id : 'unknown';

    const name = artifact && typeof artifact.name === 'string' ? artifact.name : '';
    const version = artifact && typeof artifact.version === 'string' ? artifact.version : '';
    const ecosystem = artifact && typeof artifact.type === 'string' && artifact.type ? artifact.type : 'unknown';
    const packageField = name ? { ecosystem, name, version } : null;

    const locations = [];
    const artifactLocations = artifact && Array.isArray(artifact.locations) ? artifact.locations : [];
    for (const location of artifactLocations) {
      if (isObject(location) && typeof location.path === 'string' && location.path) {
        locations.push(location.path);
      }
    }

    const references = Array.isArray(vulnerability.urls)
      ? vulnerability.urls.filter((u) => typeof u === 'string')
      : [];

    findings.push(
      makeFinding({
        id,
        severity: mapSeverity(vulnerability.severity, WORD_SEVERITY),
        package: packageField,
        locations,
        references,
        tools: [tool],
      }),
    );
  }
  return findings;
}

/**
 * Normalize an OSV scan document into canonical findings.
 * @param {unknown} doc - Parsed OSV document.
 * @param {{ tool?: string }} [opts] - Options; `tool` overrides the reported tool name.
 * @returns {object[]} Canonical findings, empty when the document is not an OSV document.
 */
export function normalizeOsv(doc, opts = {}) {
  const tool = opts.tool ?? 'osv';
  if (!isObject(doc) || !Array.isArray(doc.results)) return [];
  const findings = [];
  for (const result of doc.results) {
    if (!isObject(result)) continue;
    const source = isObject(result.source) ? result.source : null;
    const sourcePath = source && typeof source.path === 'string' && source.path ? source.path : null;
    const packages = Array.isArray(result.packages) ? result.packages : [];
    for (const entry of packages) {
      if (!isObject(entry)) continue;
      const pkg = isObject(entry.package) ? entry.package : null;
      const version = typeof entry.version === 'string' ? entry.version : '';
      const vulnerabilities = Array.isArray(entry.vulnerabilities) ? entry.vulnerabilities : [];
      for (const vulnerability of vulnerabilities) {
        if (!isObject(vulnerability)) continue;
        const id = typeof vulnerability.id === 'string' && vulnerability.id ? vulnerability.id : 'unknown';
        const aliases = Array.isArray(vulnerability.aliases)
          ? vulnerability.aliases.filter((a) => typeof a === 'string')
          : [];
        const databaseSpecific = isObject(vulnerability.database_specific) ? vulnerability.database_specific : null;
        const severity =
          databaseSpecific && databaseSpecific.severity !== undefined
            ? mapSeverity(databaseSpecific.severity, WORD_SEVERITY)
            : 'info';
        const name = pkg && typeof pkg.name === 'string' ? pkg.name : '';
        const ecosystem = pkg && typeof pkg.ecosystem === 'string' && pkg.ecosystem ? pkg.ecosystem : 'unknown';
        const packageField = name ? { ecosystem, name, version } : null;
        const references = Array.isArray(vulnerability.references)
          ? vulnerability.references.filter((r) => typeof r === 'string')
          : [];
        findings.push(
          makeFinding({
            id,
            aliases,
            severity,
            package: packageField,
            locations: sourcePath ? [sourcePath] : [],
            references,
            tools: [tool],
          }),
        );
      }
    }
  }
  return findings;
}

/**
 * Detect which supported scanner format a parsed document uses.
 * @param {unknown} doc - Parsed document.
 * @returns {string|null} One of sarif, trivy, grype, osv, or null when unrecognized.
 */
export function detectFormat(doc) {
  if (!isObject(doc)) return null;
  if (Array.isArray(doc.runs)) return 'sarif';
  if (Array.isArray(doc.Results)) return 'trivy';
  if (Array.isArray(doc.matches)) return 'grype';
  if (Array.isArray(doc.results)) return 'osv';
  return null;
}

/**
 * Normalize any supported scanner document, dispatching on the detected format.
 * @param {unknown} doc - Parsed document.
 * @param {{ tool?: string }} [opts] - Options; `tool` overrides the reported tool name.
 * @returns {object[]} Canonical findings, empty when the format is unrecognized.
 */
export function normalizeAny(doc, opts = {}) {
  switch (detectFormat(doc)) {
    case 'sarif':
      return normalizeSarif(doc, opts);
    case 'trivy':
      return normalizeTrivy(doc, opts);
    case 'grype':
      return normalizeGrype(doc, opts);
    case 'osv':
      return normalizeOsv(doc, opts);
    default:
      return [];
  }
}
