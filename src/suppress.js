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
function matches(finding, matcher) {
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
 * Find the suppression rule that applies to a finding.
 * @param {object} finding - Canonical finding.
 * @param {Array<{ matcher: string, reason: string|null, expires: string|null }>} rules - Parsed rules.
 * @param {number|Date} [now] - Current time, used to evaluate expiry.
 * @returns {{ matcher: string, reason: string|null, expires: string|null }|null}
 *   The first matching, unexpired rule, or null.
 */
export function isSuppressed(finding, rules, now = Date.now()) {
  if (!Array.isArray(rules)) return null;
  for (const rule of rules) {
    if (!rule || typeof rule.matcher !== 'string') continue;
    if (isExpiredRule(rule, now)) continue;
    if (matches(finding, rule.matcher)) return rule;
  }
  return null;
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
