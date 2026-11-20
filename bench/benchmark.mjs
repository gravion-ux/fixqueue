// Measure the fixqueue scan pipeline.
//
// Run it from a checkout:
//
//     node bench/benchmark.mjs
//
// The workload is the whole scan pipeline: four scanner documents are
// normalized, deduplicated, matched against an ignore file, enriched from the
// EPSS and KEV feeds, ranked and reported. Each stage is timed on its own as
// well as the pipeline as a whole.
//
// Every workload is timed several times and the fastest run is reported,
// because the slowest run is usually the one that caught a stray background
// process rather than the one that measured the code. The numbers are only
// comparable against each other on the same machine and the same Node build.
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(HERE, '..', 'src');
const load = (name) => import(pathToFileURL(path.join(SRC, name)).href);

const { normalizeAny } = await load('normalize.js');
const { dedupe } = await load('dedupe.js');
const { enrich } = await load('enrich.js');
const { rank } = await load('score.js');
const { toMarkdown } = await load('report.js');
const { parseSuppressions, buildSuppressionIndex, findSuppression } = await load('suppress.js');

/** How many findings each scanner document holds. */
const FINDINGS_PER_TOOL = 2500;

/** How many rules the ignore file holds. */
const SUPPRESSION_RULES = 400;

/** How many records each intelligence feed holds. */
const FEED_RECORDS = 20000;

/** How many times each workload is timed. The fastest run wins. */
const TRIALS = 7;

const ECOSYSTEMS = ['npm', 'pypi', 'go', 'cargo'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

function buildSarif() {
  const results = [];
  for (let i = 0; i < FINDINGS_PER_TOOL; i++) {
    const cve = `CVE-2024-${String(10000 + (i % 9000)).padStart(5, '0')}`;
    results.push({
      ruleId: cve,
      level: ['error', 'warning', 'note'][i % 3],
      message: { text: `Vulnerability in component ${i % 400}` },
      properties: {
        tags: [cve, `GHSA-${(i % 9000).toString(36)}xxxx`],
        'security-severity': String((i % 10) + 0.5),
        package: {
          ecosystem: ECOSYSTEMS[i % ECOSYSTEMS.length],
          name: `component-${i % 400}`,
          version: `${(i % 9) + 1}.${i % 13}.${i % 7}`,
        },
        references: [`https://example.test/advisory/${i % 9000}`],
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: `src/module-${i % 120}/file-${i % 60}.js` },
            region: { startLine: (i % 400) + 1 },
          },
        },
      ],
    });
  }
  return { runs: [{ results }] };
}

function buildTrivy() {
  const Vulnerabilities = [];
  for (let i = 0; i < FINDINGS_PER_TOOL; i++) {
    Vulnerabilities.push({
      VulnerabilityID: `CVE-2024-${String(10000 + (i % 9000)).padStart(5, '0')}`,
      PkgName: `component-${i % 400}`,
      PkgID: `pkg-${i % 400}`,
      InstalledVersion: `${(i % 9) + 1}.${i % 13}.${i % 7}`,
      Severity: SEVERITIES[i % SEVERITIES.length],
      Title: `Vulnerability in component ${i % 400}`,
      PrimaryURL: `https://example.test/advisory/${i % 9000}`,
      References: [`https://example.test/advisory/${i % 9000}`],
    });
  }
  return { Results: [{ Type: 'npm', Target: 'package-lock.json', Vulnerabilities }] };
}

function buildGrype() {
  const matches = [];
  for (let i = 0; i < FINDINGS_PER_TOOL; i++) {
    matches.push({
      vulnerability: {
        id: `CVE-2024-${String(10000 + (i % 9000)).padStart(5, '0')}`,
        severity: SEVERITIES[i % SEVERITIES.length],
        urls: [`https://example.test/advisory/${i % 9000}`],
      },
      artifact: {
        name: `component-${i % 400}`,
        version: `${(i % 9) + 1}.${i % 13}.${i % 7}`,
        type: 'npm',
        locations: [{ path: `src/module-${i % 120}/file-${i % 60}.js` }],
      },
    });
  }
  return { matches };
}

function buildOsv() {
  const results = [];
  for (let i = 0; i < FINDINGS_PER_TOOL; i++) {
    const cve = `CVE-2024-${String(10000 + (i % 9000)).padStart(5, '0')}`;
    results.push({
      source: { path: 'src/module-1/file-1.js' },
      packages: [
        {
          package: { ecosystem: 'npm', name: `component-${i % 400}` },
          version: `${(i % 9) + 1}.${i % 13}.${i % 7}`,
          vulnerabilities: [
            {
              id: cve,
              aliases: [`GHSA-${(i % 9000).toString(36)}xxxx`],
              database_specific: { severity: 'HIGH' },
              references: [{ type: 'WEB', url: `https://example.test/advisory/${i % 9000}` }],
            },
          ],
        },
      ],
    });
  }
  return { results };
}

function buildFeeds() {
  const epss = {};
  const kev = {};
  for (let i = 0; i < FEED_RECORDS; i++) {
    const cve = `CVE-2024-${String(10000 + (i % 9000)).padStart(5, '0')}`;
    epss[cve] = { score: (i % 100) / 10, percentile: (i % 100) / 100, date: '2026-11-19' };
    if (i % 50 === 0) {
      kev[cve] = {
        dueDate: '2026-12-01',
        ransomware: i % 100 === 0,
        vendor: 'example',
        name: `Advisory ${i}`,
      };
    }
  }
  return { epss, kev };
}

function buildSuppressions() {
  const lines = [];
  for (let i = 0; i < SUPPRESSION_RULES; i++) {
    if (i % 3 === 0) {
      lines.push(`CVE-2024-${String(10000 + i).padStart(5, '0')} reason="accepted risk" expires=2027-01-01`);
    } else if (i % 3 === 1) {
      lines.push(`npm:component-${i}@1.2.3 reason="internal fork"`);
    } else {
      lines.push(`component-${i}@1.2.3 reason="not reachable"`);
    }
  }
  return lines.join('\n');
}

const documents = [buildSarif(), buildTrivy(), buildGrype(), buildOsv()];
const feeds = buildFeeds();
const suppressionText = buildSuppressions();
const rules = parseSuppressions(suppressionText);
const now = Date.parse('2026-11-19T00:00:00.000Z');

function timeIt(label, fn, trials = TRIALS) {
  let best = Infinity;
  let result;
  for (let i = 0; i < trials; i += 1) {
    const start = performance.now();
    result = fn();
    const elapsed = performance.now() - start;
    if (elapsed < best) best = elapsed;
  }
  console.log(`${label.padEnd(46)} ${best.toFixed(1).padStart(9)} ms (min of ${trials})   -> ${result}`);
  return best;
}

const allFindings = [];
for (const doc of documents) allFindings.push(...normalizeAny(doc));
const deduped = dedupe(allFindings);

console.log(`findings per tool: ${FINDINGS_PER_TOOL}`);
console.log(`suppression rules: ${SUPPRESSION_RULES}`);
console.log(`feed records: ${FEED_RECORDS}`);
console.log(`normalized findings: ${allFindings.length}`);
console.log(`deduped findings: ${deduped.length}`);
console.log();

timeIt('normalizeAny x 4 documents', () => {
  let count = 0;
  for (const doc of documents) count += normalizeAny(doc).length;
  return count;
});

timeIt('dedupe', () => dedupe(allFindings).length);

timeIt('parseSuppressions', () => parseSuppressions(suppressionText).length);

timeIt('suppress every finding', () => {
  const index = buildSuppressionIndex(rules, now);
  let count = 0;
  for (const finding of deduped) if (findSuppression(finding, index)) count += 1;
  return count;
});

timeIt('enrich', () => enrich(deduped, { epss: feeds.epss, kev: feeds.kev }).length);

const enriched = enrich(deduped, { epss: feeds.epss, kev: feeds.kev });

timeIt('rank', () => rank(enriched).length);

timeIt('the whole scan pipeline', () => {
  let findings = [];
  for (const doc of documents) findings.push(...normalizeAny(doc));
  findings = dedupe(findings);
  const index = buildSuppressionIndex(rules, now);
  const kept = [];
  for (const finding of findings) if (!findSuppression(finding, index)) kept.push(finding);
  const scored = rank(enrich(kept, { epss: feeds.epss, kev: feeds.kev }));
  return toMarkdown(scored, {}).length;
});
