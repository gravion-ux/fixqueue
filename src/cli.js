#!/usr/bin/env node
/**
 * fixqueue — command line interface.
 * @module fixqueue/cli
 */

import { appendFile, mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { cacheStatus, resolveCacheRoot } from './cache.js';
import { dedupe } from './dedupe.js';
import { enrich } from './enrich.js';
import { loadEnrichment } from './feeds.js';
import { normalizeAny, normalizeGrype, normalizeOsv, normalizeSarif, normalizeTrivy } from './normalize.js';
import { toJson, toMarkdown, toSarif } from './report.js';
import { rank } from './score.js';
import { formatSuppression, isExpiredRule, isSuppressed, parseSuppressions } from './suppress.js';

/**
 * Format adapters keyed by their canonical format name.
 * @type {Record<string, Function>}
 */
const ADAPTERS = {
  sarif: normalizeSarif,
  trivy: normalizeTrivy,
  grype: normalizeGrype,
  osv: normalizeOsv,
};

/**
 * Flags that consume a value.
 * @type {Set<string>}
 */
const VALUE_FLAGS = new Set([
  'format',
  'tool',
  'top',
  'fail-on',
  'cache-dir',
  'ignore-file',
  'out',
  'reason',
  'expires',
]);

/**
 * Flags that stand alone.
 * @type {Set<string>}
 */
const BOOLEAN_FLAGS = new Set(['offline', 'refresh', 'help']);

/**
 * Severity order from most to least severe.
 * @type {readonly string[]}
 */
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Write text to an output sink, which may be a stream or a function.
 * @param {object|Function|undefined} target - Output sink.
 * @param {string} text - Text to write.
 * @returns {void}
 */
function writeTo(target, text) {
  if (!target) return;
  if (typeof target === 'function') {
    target(text);
    return;
  }
  if (typeof target.write === 'function') target.write(text);
}

/**
 * Render the usage banner.
 * @returns {string} The usage text.
 */
function usage() {
  return [
    'fixqueue — merge multiple security scanner outputs into one prioritized fix queue',
    '',
    'Usage:',
    '  fixqueue scan <paths...> [--format md|json|sarif] [--tool sarif|trivy|grype|osv]',
    '                   [--offline] [--refresh] [--top <n>] [--fail-on <severity>]',
    '                   [--cache-dir <path>] [--ignore-file <path>] [--out <path>]',
    '  fixqueue suppress <advisory-id> --reason "<text>" [--expires YYYY-MM-DD] [--ignore-file <path>]',
    '  fixqueue cache [--cache-dir <path>]',
    '  fixqueue demo',
    '  fixqueue help',
    '',
    'Exit codes: 0 success, 1 findings met the --fail-on threshold, 2 usage or input error.',
  ].join('\n');
}

/**
 * Parse command line arguments.
 *
 * The first bare token is the subcommand. Unknown flags are collected rather
 * than rejected so that new flags never break older scripts.
 * @param {string[]} argv - Raw arguments, excluding the node executable and script.
 * @returns {{ command: string|null, options: object, positionals: string[] }}
 *   The parsed command, options and positional arguments.
 */
export function parseArgs(argv) {
  const args = Array.isArray(argv) ? argv.slice() : [];
  let command = null;
  const positionals = [];
  const options = {};
  const unknown = [];
  const unknownValues = [];

  let index = 0;
  while (index < args.length) {
    const token = args[index];
    if (token.startsWith('--')) {
      const body = token.slice(2);
      const separator = body.indexOf('=');
      const name = separator >= 0 ? body.slice(0, separator) : body;
      let value = separator >= 0 ? body.slice(separator + 1) : undefined;
      if (VALUE_FLAGS.has(name)) {
        if (value === undefined) {
          index += 1;
          value = args[index];
          if (value === undefined) {
            unknown.push(`--${name}`);
            continue;
          }
        }
        if (name === 'top') {
          const parsed = Number(value);
          options.top = Number.isFinite(parsed) ? parsed : undefined;
        } else {
          options[name] = value;
        }
      } else if (BOOLEAN_FLAGS.has(name)) {
        options[name] = value === undefined ? true : value !== 'false';
      } else {
        unknown.push(`--${name}`);
        if (value === undefined && index + 1 < args.length && !args[index + 1].startsWith('--')) {
          unknownValues.push(args[index + 1]);
          index += 1;
        }
      }
    } else if (token === '-h') {
      options.help = true;
    } else if (token.startsWith('-') && token.length > 1) {
      unknown.push(token);
    } else if (command === null) {
      command = token;
    } else {
      positionals.push(token);
    }
    index += 1;
  }

  options.unknown = unknown;
  options.unknownValues = unknownValues;
  return { command, options, positionals };
}

/**
 * Normalize a parsed document, honouring an explicit tool selection.
 * @param {unknown} doc - Parsed document.
 * @param {string|undefined} tool - Forced format name.
 * @returns {object[]} Canonical findings.
 */
function normalizeDocument(doc, tool) {
  if (tool && ADAPTERS[tool]) return ADAPTERS[tool](doc);
  return normalizeAny(doc);
}

/**
 * Collect every JSON file below a directory path.
 * @param {string} directory - Absolute directory path.
 * @returns {Promise<string[]>} Absolute file paths.
 */
async function jsonFilesIn(directory) {
  const files = [];
  let entries = [];
  try {
    entries = await readdir(directory);
  } catch {
    return files;
  }
  for (const entry of entries.sort()) {
    if (!entry.endsWith('.json')) continue;
    files.push(join(directory, entry));
  }
  return files;
}

/**
 * Resolve the cache root used by a command.
 * @param {object} options - Parsed options.
 * @param {object} io - Runtime dependencies.
 * @returns {string} The resolved cache root.
 */
function resolveCache(options, io) {
  if (io.cacheDir) return io.cacheDir;
  const cwd = io.cwd ?? process.cwd();
  if (options['cache-dir']) return resolve(cwd, options['cache-dir']);
  return resolveCacheRoot(undefined, cwd);
}

/**
 * Run the `scan` subcommand.
 * @param {string[]} positionals - Paths to scan.
 * @param {object} options - Parsed options.
 * @param {object} io - Runtime dependencies.
 * @returns {Promise<number>} The process exit code.
 */
async function scanCommand(positionals, options, io) {
  const cwd = io.cwd ?? process.cwd();

  // An unknown flag swallows the token that follows it. When that token turns
  // out to be a real path it is recovered here, so a typo or a flag from a
  // newer release never silently drops the directory the user asked to scan.
  const candidates = [...positionals];
  for (const swallowed of Array.isArray(options.unknownValues) ? options.unknownValues : []) {
    if (candidates.includes(swallowed)) continue;
    try {
      await stat(resolve(cwd, swallowed));
      candidates.push(swallowed);
    } catch {
      // Not a path on disk, so it stays an unknown flag value.
    }
  }

  if (candidates.length === 0) {
    writeTo(io.stderr, 'error: scan requires at least one path\n');
    return 2;
  }

  const files = [];
  for (const candidate of candidates) {
    const absolute = resolve(cwd, candidate);
    let info;
    try {
      info = await stat(absolute);
    } catch {
      writeTo(io.stderr, `error: path not found: ${candidate}\n`);
      return 2;
    }
    if (info.isDirectory()) {
      files.push(...(await jsonFilesIn(absolute)));
    } else {
      files.push(absolute);
    }
  }

  let findings = [];
  for (const file of files) {
    let doc;
    try {
      doc = JSON.parse(await readFile(file, 'utf8'));
    } catch (error) {
      writeTo(io.stderr, `error: could not read ${file}: ${error.message}\n`);
      return 2;
    }
    findings.push(...normalizeDocument(doc, options.tool));
  }
  findings = dedupe(findings);

  const cves = [
    ...new Set(
      findings
        .flatMap((finding) => [finding.id, ...(finding.aliases ?? [])])
        .filter((id) => typeof id === 'string' && /^CVE-/i.test(id)),
    ),
  ];

  let enrichment;
  try {
    enrichment = await loadEnrichment(resolveCache(options, io), {
      cves,
      offline: Boolean(options.offline),
      refresh: Boolean(options.refresh),
      now: io.now,
      fetchImpl: io.fetchImpl,
    });
  } catch (error) {
    writeTo(io.stderr, `error: ${error.message}\n`);
    return 2;
  }

  const ignorePath = resolve(cwd, options['ignore-file'] ?? '.fixqueueignore');
  let rules = [];
  try {
    rules = parseSuppressions(await readFile(ignorePath, 'utf8'));
  } catch {
    rules = [];
  }

  const now = io.now ?? Date.now();
  const expiredRules = rules.filter((rule) => isExpiredRule(rule, now));
  for (const rule of expiredRules) {
    writeTo(
      io.stderr,
      `warning: suppression rule expired and was ignored: ${rule.matcher} (expired ${rule.expires})\n`,
    );
  }

  const kept = [];
  const suppressed = [];
  for (const finding of findings) {
    const rule = isSuppressed(finding, rules, now);
    if (rule) {
      suppressed.push({
        id: finding.id,
        severity: finding.severity,
        matcher: rule.matcher,
        reason: rule.reason ?? null,
        expires: rule.expires ?? null,
      });
    } else {
      kept.push(finding);
    }
  }

  const ranked = rank(enrich(kept, { epss: enrichment.epss, kev: enrichment.kev?.cves ?? {} }));
  const limited = Number.isFinite(options.top) && options.top >= 0 ? ranked.slice(0, options.top) : ranked;

  const epssDates = Object.values(enrichment.epss ?? {})
    .map((record) => record?.date)
    .filter(Boolean)
    .sort();
  const meta = {
    generatedAt: new Date(now).toISOString(),
    tool: 'fixqueue',
    epssDate: epssDates.length > 0 ? epssDates[epssDates.length - 1] : null,
    kevVersion: enrichment.kev?.catalogVersion ?? null,
    cacheAge: enrichment.fromCache ? 'cached' : 'fresh',
    suppressed: suppressed.length,
    suppressedList: suppressed,
    expiredRules: expiredRules.map((rule) => ({
      matcher: rule.matcher,
      expires: rule.expires ?? null,
      reason: rule.reason ?? null,
    })),
  };

  const output =
    options.format === 'json'
      ? toJson(limited, meta)
      : options.format === 'sarif'
        ? toSarif(limited, meta)
        : toMarkdown(limited, meta);

  if (options.out) {
    const outPath = resolve(cwd, options.out);
    await mkdir(dirname(outPath), { recursive: true });
    await writeFile(outPath, `${output}\n`, 'utf8');
  } else {
    writeTo(io.stdout, output);
  }

  if (options['fail-on']) {
    const threshold = SEVERITY_ORDER.indexOf(options['fail-on']);
    // The gate inspects every ranked finding: limiting the report with --top
    // must never hide a finding that should fail the build.
    if (threshold >= 0 && ranked.some((finding) => SEVERITY_ORDER.indexOf(finding.severity) <= threshold)) {
      return 1;
    }
  }
  return 0;
}

/**
 * Run the `suppress` subcommand.
 * @param {string[]} positionals - The advisory id or package matcher to suppress.
 * @param {object} options - Parsed options.
 * @param {object} io - Runtime dependencies.
 * @returns {Promise<number>} The process exit code.
 */
async function suppressCommand(positionals, options, io) {
  const matcher = positionals[0];
  if (!matcher) {
    writeTo(io.stderr, 'error: suppress requires an advisory id or package matcher\n');
    return 2;
  }
  const cwd = io.cwd ?? process.cwd();
  const ignorePath = resolve(cwd, options['ignore-file'] ?? '.fixqueueignore');
  const rule = { matcher, reason: options.reason ?? null, expires: options.expires ?? null };
  await mkdir(dirname(ignorePath), { recursive: true });
  await appendFile(ignorePath, `${formatSuppression(rule)}\n`, 'utf8');
  writeTo(io.stdout, `suppressed ${matcher}\n`);
  return 0;
}

/**
 * Run the `cache` subcommand.
 * @param {object} options - Parsed options.
 * @param {object} io - Runtime dependencies.
 * @returns {Promise<number>} The process exit code.
 */
async function cacheCommand(options, io) {
  const root = resolveCache(options, io);
  const status = await cacheStatus(root, io.now ?? Date.now());
  writeTo(io.stdout, `${JSON.stringify({ cacheRoot: root, entries: status.entries }, null, 2)}\n`);
  return 0;
}

/**
 * Run the `demo` subcommand, which is fully deterministic and needs no network.
 * @param {object} io - Runtime dependencies.
 * @returns {Promise<number>} The process exit code.
 */
async function demoCommand(io) {
  const examplesDir = fileURLToPath(new URL('../examples/', import.meta.url));
  const samples = ['sample-sarif.json', 'sample-trivy.json'];
  let findings = [];
  for (const sample of samples) {
    findings.push(...normalizeAny(JSON.parse(await readFile(join(examplesDir, sample), 'utf8'))));
  }
  const enrichment = JSON.parse(await readFile(join(examplesDir, 'demo-enrichment.json'), 'utf8'));
  const ranked = rank(
    enrich(dedupe(findings), { epss: enrichment.epss ?? {}, kev: enrichment.kev ?? {} }),
  );
  const meta = {
    generatedAt: enrichment.generatedAt ?? '2026-01-01T00:00:00.000Z',
    tool: 'fixqueue',
    epssDate: enrichment.epssDate ?? null,
    kevVersion: enrichment.kevVersion ?? null,
    cacheAge: 'demo',
  };
  writeTo(io.stdout, toMarkdown(ranked, meta));
  return 0;
}

/**
 * Execute the command line interface.
 * @param {string[]} argv - Raw arguments, excluding the node executable and script.
 * @param {{ stdout?: object, stderr?: object, fetchImpl?: Function, cwd?: string, now?: number|Date, cacheDir?: string }} [io]
 *   Runtime dependencies, all injectable so tests never touch the network.
 * @returns {Promise<number>} The process exit code.
 */
export async function main(argv, io = {}) {
  const { command, options, positionals } = parseArgs(argv);

  if (command === null) {
    writeTo(io.stdout ?? process.stdout, `${usage()}\n`);
    return 2;
  }
  if (command === 'help' || options.help) {
    writeTo(io.stdout ?? process.stdout, `${usage()}\n`);
    return 0;
  }

  try {
    switch (command) {
      case 'scan':
        return await scanCommand(positionals, options, io);
      case 'suppress':
        return await suppressCommand(positionals, options, io);
      case 'cache':
        return await cacheCommand(options, io);
      case 'demo':
        return await demoCommand(io);
      default:
        writeTo(io.stderr ?? process.stderr, `error: unknown command: ${command}\n${usage()}\n`);
        return 2;
    }
  } catch (error) {
    writeTo(io.stderr ?? process.stderr, `error: ${error.message}\n`);
    return 2;
  }
}

const invokedDirectly =
  process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  main(process.argv.slice(2), {
    stdout: process.stdout,
    stderr: process.stderr,
    cwd: process.cwd(),
  })
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      process.stderr.write(`error: ${error.message}\n`);
      process.exitCode = 2;
    });
}
