/**
 * fixqueue — identity resolution and merging of duplicate findings.
 * @module fixqueue/dedupe
 */

/**
 * Advisory identifier prefixes recognised across ecosystems.
 * @type {RegExp}
 */
const ADVISORY_PREFIX = /^(?:CVE|GHSA|OSV|PYSEC|RUSTSEC|GO|USN|DSA)-/i;

/**
 * Canonical severity order from most to least severe.
 * @type {readonly string[]}
 */
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Determine whether a string looks like an advisory identifier.
 * @param {unknown} value - Candidate identifier.
 * @returns {boolean} True when the value carries a known advisory prefix.
 */
function isAdvisoryId(value) {
  return typeof value === 'string' && ADVISORY_PREFIX.test(value);
}

/**
 * Build the fallback identity key for a finding without an advisory identifier.
 * @param {object} finding - Canonical finding.
 * @returns {string} A package-scoped or title-scoped identity key.
 */
function fallbackKey(finding) {
  const pkg = finding.package;
  if (pkg && typeof pkg.name === 'string' && pkg.name) {
    const location = Array.isArray(finding.locations) && finding.locations.length ? finding.locations[0] : '';
    return `pkg:${pkg.ecosystem ?? 'unknown'}:${pkg.name}@${pkg.version ?? ''}|${location}`;
  }
  const title = typeof finding.title === 'string' ? finding.title.trim() : '';
  return `title:${title.toLowerCase()}`;
}

/**
 * Resolve the primary identity key of a finding.
 *
 * Resolution order: an advisory-shaped id, then an advisory-shaped alias, then a
 * package-scoped key, then a lowercased title key.
 * @param {object} finding - Canonical finding.
 * @returns {string} The identity key for the finding.
 */
export function findingKey(finding) {
  const source = finding && typeof finding === 'object' ? finding : {};
  if (isAdvisoryId(source.id)) return source.id;
  const aliases = Array.isArray(source.aliases) ? source.aliases : [];
  for (const alias of aliases) {
    if (isAdvisoryId(alias)) return alias;
  }
  return fallbackKey(source);
}

/**
 * Collect every identity token that belongs to a finding.
 * @param {object} finding - Canonical finding.
 * @returns {string[]} Advisory tokens when available, otherwise the fallback key.
 */
function identityTokens(finding) {
  const source = finding && typeof finding === 'object' ? finding : {};
  const candidates = [source.id, ...(Array.isArray(source.aliases) ? source.aliases : [])];
  const tokens = candidates.filter(isAdvisoryId).map((token) => token.toUpperCase());
  if (tokens.length > 0) return [...new Set(tokens)];
  return [fallbackKey(source)];
}

/**
 * Merge a group of duplicate findings into a single canonical finding.
 *
 * The first-seen finding supplies the title; severity is the maximum across the
 * group so the most pessimistic report survives the merge.
 * @param {object[]} group - Findings known to describe the same issue.
 * @returns {object} The merged canonical finding.
 */
function mergeGroup(group) {
  const first = group[0];
  const aliases = new Set();
  const locations = new Set();
  const references = new Set();
  const tools = new Set();
  let severity = 'info';
  let severityRank = SEVERITY_ORDER.length;
  let packageField = null;
  let id = first.id;
  let idIsAdvisory = isAdvisoryId(first.id);
  let occurrences = 0;

  for (const finding of group) {
    if (!idIsAdvisory && isAdvisoryId(finding.id)) {
      id = finding.id;
      idIsAdvisory = true;
    }
    for (const alias of Array.isArray(finding.aliases) ? finding.aliases : []) {
      if (typeof alias === 'string' && alias !== id) aliases.add(alias);
    }
    for (const location of Array.isArray(finding.locations) ? finding.locations : []) {
      if (typeof location === 'string') locations.add(location);
    }
    for (const reference of Array.isArray(finding.references) ? finding.references : []) {
      if (typeof reference === 'string') references.add(reference);
    }
    for (const tool of Array.isArray(finding.tools) ? finding.tools : []) {
      if (typeof tool === 'string') tools.add(tool);
    }
    const rank = SEVERITY_ORDER.indexOf(finding.severity);
    if (rank >= 0 && rank < severityRank) {
      severityRank = rank;
      severity = finding.severity;
    }
    if (!packageField && finding.package) packageField = finding.package;
    occurrences += Number.isFinite(finding.occurrences) ? finding.occurrences : 1;
  }

  return {
    id,
    aliases: [...aliases].sort(),
    title: typeof first.title === 'string' ? first.title : '',
    severity,
    package: packageField,
    locations: [...locations].sort(),
    references: [...references].sort(),
    tools: [...tools].sort(),
    occurrences,
  };
}

/**
 * Merge findings that describe the same issue.
 *
 * Identity is resolved through advisory ids and aliases; overlapping identity sets
 * are merged transitively, so a chain A-B-C collapses into a single group.
 * @param {object[]} findings - Canonical findings to deduplicate.
 * @returns {object[]} Deduplicated findings in first-seen order.
 */
export function dedupe(findings) {
  const list = Array.isArray(findings) ? findings.filter((f) => f && typeof f === 'object') : [];
  if (list.length === 0) return [];

  const parent = list.map((_, index) => index);
  const find = (index) => {
    let root = index;
    while (parent[root] !== root) root = parent[root];
    let cursor = index;
    while (parent[cursor] !== root) {
      const next = parent[cursor];
      parent[cursor] = root;
      cursor = next;
    }
    return root;
  };
  const union = (a, b) => {
    const rootA = find(a);
    const rootB = find(b);
    if (rootA !== rootB) parent[rootB] = rootA;
  };

  const owner = new Map();
  list.forEach((finding, index) => {
    for (const token of identityTokens(finding)) {
      if (owner.has(token)) {
        union(owner.get(token), index);
      } else {
        owner.set(token, index);
      }
    }
  });

  const groups = new Map();
  list.forEach((finding, index) => {
    const root = find(index);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(finding);
  });

  const merged = [];
  for (const group of groups.values()) merged.push(mergeGroup(group));
  return merged;
}
