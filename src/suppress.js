/**
 * fixqueue — accepted-risk suppression rules.
 * @module fixqueue/suppress
 */

/**
 * Advisory identifier prefixes recognised across ecosystems.
 * @type {RegExp}
 */
const ADVISORY_PREFIX = /^(?:CVE|GHSA|OSV|PYSEC|RUSTSEC|GO|USN|DSA)-/i;

/**
 * Remove a trailing `#` comment that is not inside a quoted string.
 * @param {string} line - Raw line.
 * @returns {string} The line without its comment.
 */
function stripComment(line) {
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === '"') quoted = !quoted;
    if (character === '#' && !quoted) return line.slice(0, index);
  }
  return line;
}

/**
 * Parse a single suppression line.
 * @param {string} raw - Raw line from the ignore file.
 * @returns {{ matcher: string, reason: string|null, expires: string|null }|null}
 *   The parsed rule, or null when the line carries no matcher.
 */
function parseLine(raw) {
  let line = String(raw);
  let reason = null;
  let expires = null;

  const reasonMatch = line.match(/reason\s*=\s*"([^"]*)"/);
  if (reasonMatch) {
    reason = reasonMatch[1];
    line = line.replace(reasonMatch[0], ' ');
  }
  const expiresMatch = line.match(/expires\s*=\s*(\S+)/);
  if (expiresMatch) {
    expires = expiresMatch[1];
    line = line.replace(expiresMatch[0], ' ');
  }

  const matcher = stripComment(line).trim();
  if (!matcher) return null;
  return { matcher, reason, expires };
}

/**
 * Parse the contents of a suppression file.
 * @param {string} text - Raw file contents.
 * @returns {Array<{ matcher: string, reason: string|null, expires: string|null }>} The parsed rules.
 */
export function parseSuppressions(text) {
  if (typeof text !== 'string' || !text) return [];
  const rules = [];
  for (const raw of text.split(/\r?\n/)) {
    const rule = parseLine(raw);
    if (rule) rules.push(rule);
  }
  return rules;
}

/**
 * Determine whether a suppression rule has expired at the given moment.
 *
 * An expiry date is valid through the end of that day. A rule that carries no
 * expiry date never expires.
 * @param {{ expires?: string|null }} rule - The suppression rule.
 * @param {number|Date} [now] - Current time.
 * @returns {boolean} True when the rule has expired.
 */
export function isExpiredRule(rule, now = Date.now()) {
  const expires = rule && typeof rule === 'object' ? rule.expires : null;
  if (!expires) return false;
  const current = now instanceof Date ? now.getTime() : Number(now);
  const endOfDay = Date.parse(`${expires}T23:59:59.999Z`);
  if (!Number.isFinite(endOfDay)) return true;
  return current > endOfDay;
}

/**
 * Determine whether a suppression rule matches a finding.
 * @param {object} finding - Canonical finding.
 * @param {string} matcher - The rule matcher.
 * @returns {boolean} True when the rule applies to the finding.
 */
export function matchesSuppression(finding, matcher) {
  const source = finding && typeof finding === 'object' ? finding : {};
  if (ADVISORY_PREFIX.test(matcher)) {
    const candidates = [source.id, ...(Array.isArray(source.aliases) ? source.aliases : [])];
    return candidates.some(
      (candidate) => typeof candidate === 'string' && candidate.toUpperCase() === matcher.toUpperCase(),
    );
  }

  const pkg = source.package;
  if (!pkg || typeof pkg.name !== 'string') return false;

  if (matcher.includes(':')) {
    const separator = matcher.indexOf(':');
    const ecosystem = matcher.slice(0, separator).trim();
    const coordinates = matcher.slice(separator + 1).trim();
    return (
      String(pkg.ecosystem ?? '').toLowerCase() === ecosystem.toLowerCase() &&
      coordinates === `${pkg.name}@${pkg.version ?? ''}`
    );
  }

  if (matcher.includes('@')) {
    return matcher === `${pkg.name}@${pkg.version ?? ''}`;
  }

  return false;
}

/**
 * Build the lookup tables that make suppression matching cheap.
 *
 * Every rule is examined once: a rule that has expired is dropped, and every
 * remaining rule is filed under the key it can match. A finding is then
 * matched with a handful of lookups instead of a walk over every rule, which
 * matters because a scan tests every finding against the whole ignore file.
 *
 * The position of each rule in the file is kept, so the rule that matches
 * first is still the one that wins when a finding matches several rules.
 * @param {Array<{ matcher: string, reason: string|null, expires: string|null }>} rules - Parsed rules.
 * @param {number|Date} [now] - Current time, used to evaluate expiry.
 * @returns {{ advisory: Map<string, object>, ecosystems: Map<string, object>, packages: Map<string, object> }}
 *   The lookup tables, each mapping a key to the rule that owns it and its position.
 */
export function buildSuppressionIndex(rules, now = Date.now()) {
  const advisory = new Map();
  const ecosystems = new Map();
  const packages = new Map();
  if (!Array.isArray(rules)) return { advisory, ecosystems, packages };
  const current = now instanceof Date ? now.getTime() : Number(now);

  rules.forEach((rule, order) => {
    if (!rule || typeof rule.matcher !== 'string') return;
    if (isExpiredRule(rule, current)) return;
    const matcher = rule.matcher;

    if (ADVISORY_PREFIX.test(matcher)) {
      const key = matcher.toUpperCase();
      if (!advisory.has(key)) advisory.set(key, { rule, order });
      return;
    }
    if (matcher.includes(':')) {
      const separator = matcher.indexOf(':');
      const ecosystem = matcher.slice(0, separator).trim().toLowerCase();
      const coordinates = matcher.slice(separator + 1).trim();
      const key = `${ecosystem}|${coordinates}`;
      if (!ecosystems.has(key)) ecosystems.set(key, { rule, order });
      return;
    }
    if (matcher.includes('@') && !packages.has(matcher)) {
      packages.set(matcher, { rule, order });
    }
  });

  return { advisory, ecosystems, packages };
}

/**
 * Find the suppression rule that applies to a finding, using a prebuilt index.
 *
 * The rule that matches first in the ignore file wins, exactly as it does when
 * the rules are walked one by one.
 * @param {object} finding - Canonical finding.
 * @param {{ advisory: Map<string, object>, ecosystems: Map<string, object>, packages: Map<string, object> }} index
 *   The tables built by {@link buildSuppressionIndex}.
 * @returns {{ matcher: string, reason: string|null, expires: string|null }|null}
 *   The first matching rule, or null.
 */
export function findSuppression(finding, index) {
  const source = finding && typeof finding === 'object' ? finding : {};
  if (!index || typeof index !== 'object') return null;
  let best = null;

  /**
   * Keep the rule that comes first in the ignore file.
   * @param {object|undefined} entry - The indexed rule and its position.
   * @returns {void}
   */
  const consider = (entry) => {
    if (!entry) return;
    if (best === null || entry.order < best.order) best = entry;
  };

  if (typeof source.id === 'string') {
    consider(index.advisory.get(source.id.toUpperCase()));
  }
  if (Array.isArray(source.aliases)) {
    for (const alias of source.aliases) {
      if (typeof alias === 'string') consider(index.advisory.get(alias.toUpperCase()));
    }
  }

  const pkg = source.package;
  if (pkg && typeof pkg.name === 'string') {
    const coordinates = `${pkg.name}@${pkg.version ?? ''}`;
    consider(index.packages.get(coordinates));
    const ecosystem = String(pkg.ecosystem ?? '').toLowerCase();
    consider(index.ecosystems.get(`${ecosystem}|${coordinates}`));
  }

  return best ? best.rule : null;
}

/**
 * Find the suppression rule that applies to a finding.
 *
 * This is the convenience form for a single finding. When many findings are
 * tested against the same rules, build the index once with
 * {@link buildSuppressionIndex} and use {@link findSuppression} instead.
 * @param {object} finding - Canonical finding.
 * @param {Array<{ matcher: string, reason: string|null, expires: string|null }>} rules - Parsed rules.
 * @param {number|Date} [now] - Current time, used to evaluate expiry.
 * @returns {{ matcher: string, reason: string|null, expires: string|null }|null}
 *   The first matching, unexpired rule, or null.
 */
export function isSuppressed(finding, rules, now = Date.now()) {
  if (!Array.isArray(rules)) return null;
  return findSuppression(finding, buildSuppressionIndex(rules, now));
}

/**
 * Render a suppression rule back into its file representation.
 * @param {{ matcher: string, reason?: string|null, expires?: string|null }} rule - Rule to render.
 * @returns {string} The serialized rule.
 */
export function formatSuppression(rule) {
  const source = rule && typeof rule === 'object' ? rule : {};
  const parts = [String(source.matcher ?? '')];
  if (source.reason) parts.push(`reason="${source.reason}"`);
  if (source.expires) parts.push(`expires=${source.expires}`);
  return parts.join(' ');
}
