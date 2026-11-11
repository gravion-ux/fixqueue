/**
 * fixqueue — Markdown, JSON and SARIF report emitters.
 * @module fixqueue/report
 */

import { SEVERITIES } from './normalize.js';

/**
 * Escape pipe characters so a value cannot break a Markdown table cell.
 * @param {unknown} value - Raw cell value.
 * @returns {string} The escaped cell value.
 */
function escapeCell(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/**
 * Render a package as `ecosystem:name@version`.
 * @param {object|null} pkg - Package descriptor.
 * @returns {string} The rendered package, or an em dash when absent.
 */
function renderPackage(pkg) {
  if (!pkg || typeof pkg.name !== 'string' || !pkg.name) return '—';
  return `${pkg.ecosystem ?? 'unknown'}:${pkg.name}@${pkg.version ?? ''}`;
}

/**
 * Count findings per canonical severity.
 * @param {object[]} queue - Ranked findings.
 * @returns {Record<string, number>} Counts keyed by severity, plus a `total` entry.
 */
function summarize(queue) {
  const counts = { total: queue.length };
  for (const severity of SEVERITIES) counts[severity] = 0;
  for (const finding of queue) {
    if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
  }
  return counts;
}

/**
 * Render the fix queue as a Markdown report.
 * @param {object[]} queue - Ranked findings.
 * @param {object} [meta] - Report metadata.
 * @returns {string} The Markdown report.
 */
export function toMarkdown(queue, meta = {}) {
  const items = Array.isArray(queue) ? queue : [];
  const info = meta && typeof meta === 'object' ? meta : {};
  const counts = summarize(items);
  const lines = [];

  lines.push('# fixqueue — prioritized fix queue');
  lines.push('');
  lines.push(`- Generated: ${info.generatedAt ?? 'unknown'}`);
  lines.push(`- Tool: ${info.tool ?? 'fixqueue'}`);
  if (info.epssDate) lines.push(`- EPSS date: ${info.epssDate}`);
  if (info.kevVersion) lines.push(`- KEV catalog: ${info.kevVersion}`);
  if (info.cacheAge !== undefined && info.cacheAge !== null) lines.push(`- Cache age: ${info.cacheAge}`);
  if (info.suppressed) lines.push(`- Suppressed: ${info.suppressed}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | --- |');
  for (const severity of SEVERITIES) {
    lines.push(`| ${severity} | ${counts[severity]} |`);
  }
  lines.push(`| **total** | **${counts.total}** |`);
  lines.push('');
  lines.push('## Findings');
  lines.push('');
  if (items.length === 0) {
    lines.push('_No findings._');
    lines.push('');
  } else {
    lines.push('| Score | Severity | Advisory | Package | Location | Tools |');
    lines.push('| --- | --- | --- | --- | --- | --- |');
    for (const finding of items) {
      const score = Number.isFinite(finding.score) ? finding.score : 0;
      const locations = Array.isArray(finding.locations) ? finding.locations : [];
      const tools = Array.isArray(finding.tools) ? finding.tools : [];
      lines.push(
        `| ${escapeCell(score)} | ${escapeCell(finding.severity)} | ${escapeCell(finding.id)} | ${escapeCell(
          renderPackage(finding.package),
        )} | ${escapeCell(locations[0] ?? '—')} | ${escapeCell(tools.join(', ') || '—')} |`,
      );
    }
    lines.push('');
  }

  const suppressedList = Array.isArray(info.suppressedList) ? info.suppressedList : [];
  if (suppressedList.length > 0) {
    lines.push('## Suppressed findings');
    lines.push('');
    lines.push('| Advisory | Severity | Matcher | Reason | Expires |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const item of suppressedList) {
      lines.push(
        `| ${escapeCell(item.id)} | ${escapeCell(item.severity)} | ${escapeCell(item.matcher)} | ${escapeCell(
          item.reason ?? '—',
        )} | ${escapeCell(item.expires ?? '—')} |`,
      );
    }
    lines.push('');
  }

  const expiredRules = Array.isArray(info.expiredRules) ? info.expiredRules : [];
  if (expiredRules.length > 0) {
    lines.push('## Expired suppression rules');
    lines.push('');
    lines.push('| Matcher | Expired | Reason |');
    lines.push('| --- | --- | --- |');
    for (const rule of expiredRules) {
      lines.push(
        `| ${escapeCell(rule.matcher)} | ${escapeCell(rule.expires ?? '—')} | ${escapeCell(rule.reason ?? '—')} |`,
      );
    }
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Render the fix queue as a JSON document.
 * @param {object[]} queue - Ranked findings.
 * @param {object} [meta] - Report metadata.
 * @returns {string} Pretty-printed JSON with two-space indentation.
 */
export function toJson(queue, meta = {}) {
  const items = Array.isArray(queue) ? queue : [];
  const info = meta && typeof meta === 'object' ? meta : {};
  const document = {
    tool: info.tool ?? 'fixqueue',
    generatedAt: info.generatedAt ?? null,
    summary: {
      ...summarize(items),
      ...(info.counts && typeof info.counts === 'object' ? info.counts : {}),
    },
    findings: items.map((finding) => ({
      id: finding.id,
      aliases: Array.isArray(finding.aliases) ? finding.aliases : [],
      title: finding.title ?? '',
      severity: finding.severity,
      score: Number.isFinite(finding.score) ? finding.score : 0,
      scoreBreakdown: finding.scoreBreakdown ?? null,
      package: finding.package ?? null,
      locations: Array.isArray(finding.locations) ? finding.locations : [],
      references: Array.isArray(finding.references) ? finding.references : [],
      tools: Array.isArray(finding.tools) ? finding.tools : [],
      occurrences: finding.occurrences ?? 1,
      epss: finding.epss ?? null,
      kev: finding.kev ?? null,
    })),
    suppressed: Array.isArray(info.suppressedList) ? info.suppressedList : [],
    expiredRules: Array.isArray(info.expiredRules) ? info.expiredRules : [],
  };
  return JSON.stringify(document, null, 2);
}

/**
 * Split a location string into an artifact URI and an optional line number.
 * @param {string} location - Raw location string.
 * @returns {{ uri: string, startLine: number|null }} The parsed location.
 */
function splitLocation(location) {
  const text = String(location);
  const match = text.match(/^(.*):(\d+)$/);
  if (match) return { uri: match[1], startLine: Number(match[2]) };
  return { uri: text, startLine: null };
}

/**
 * Map a canonical severity onto a SARIF result level.
 * @param {string} severity - Canonical severity.
 * @returns {string} A SARIF level: error, warning or note.
 */
function sarifLevel(severity) {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

/**
 * Render the fix queue as a SARIF 2.1.0 document.
 * @param {object[]} queue - Ranked findings.
 * @param {object} [meta] - Report metadata.
 * @returns {string} Pretty-printed SARIF JSON.
 */
export function toSarif(queue, meta = {}) {
  const items = Array.isArray(queue) ? queue : [];
  const info = meta && typeof meta === 'object' ? meta : {};
  const results = items.map((finding) => {
    const locations = (Array.isArray(finding.locations) ? finding.locations : []).map((location) => {
      const parsed = splitLocation(location);
      const physicalLocation = { artifactLocation: { uri: parsed.uri } };
      if (parsed.startLine !== null) physicalLocation.region = { startLine: parsed.startLine };
      return { physicalLocation };
    });
    const result = {
      ruleId: finding.id,
      level: sarifLevel(finding.severity),
      message: { text: finding.title ? `${finding.title} (score ${finding.score ?? 0})` : `Finding ${finding.id}` },
      locations,
      properties: {
        severity: finding.severity,
        score: finding.score ?? 0,
        tools: Array.isArray(finding.tools) ? finding.tools : [],
      },
    };
    return result;
  });
  const document = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'fixqueue',
            informationUri: 'https://github.com/gravion-ux/fixqueue',
            rules: [],
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(document, null, 2);
}
