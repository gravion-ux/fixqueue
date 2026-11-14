# fixqueue

Merge multiple security scanner outputs into one deduplicated, EPSS/KEV-enriched, prioritized fix queue.

[![CI](https://github.com/gravion-ux/fixqueue/actions/workflows/ci.yml/badge.svg)](https://github.com/gravion-ux/fixqueue/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-43853d.svg)](https://nodejs.org)

## The problem

A single codebase produces the same vulnerability in several places. Trivy reports it in the
lockfile, a SAST tool reports it as a SARIF result, OSV reports it with a GitHub advisory alias,
and Grype reports it against the image layer. By the time all four land in a ticket tracker they
are four tickets, ranked by whichever tool the engineer opened first — not by actual risk.

The intelligence needed to rank them properly already exists and is free: the [EPSS](https://www.first.org/epss/)
probability of exploitation and the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalogue of vulnerabilities known to be exploited in the wild. What is missing is a tool that
joins the scanner output to that intelligence and tells you what to fix first.

## Why this exists

The incumbents solve different problems:

| Tool | What it does | What it does not do |
| --- | --- | --- |
| [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | Full vulnerability management with a server and a database | Heavyweight for a single engineer; no EPSS/KEV-driven prioritization out of the box |
| [Dependency-Track](https://github.com/DependencyTrack/dependency-track) | Continuous dependency monitoring with a server and a database | Same |
| [osv.dev](https://github.com/google/osv.dev) | Authoritative vulnerability database and API | A database, not a triage queue |
| [sarif-tools](https://github.com/microsoft/sarif-tools) | Low-level manipulation of SARIF documents | No multi-tool merge, no threat intelligence, no ranking |

`fixqueue` is deliberately the opposite: a single-file CLI with **zero runtime dependencies**, no
server, no database, no account. It reads scanner JSON you already have on disk, and writes a
prioritized queue you can paste into a ticket tracker.

## Scoring

The priority score is deterministic and fully explainable. Every point is accounted for in the
`scoreBreakdown` of each finding, and the maximum is exactly **100**.

| Component | Points | Rule |
| --- | --- | --- |
| EPSS | 0–40 | `40 x percentile`, rounded to two decimals |
| CISA KEV | 0 or 30 | Listed in the KEV catalogue |
| CISA KEV ransomware | +5 | On top of the 30 above, when `knownRansomwareCampaignUse` is `Known` |
| Severity | 0–20 | critical 20, high 15, medium 10, low 5, info 0 |
| Occurrences | 0–5 | `min(5, times reported - 1)` — how many tools saw it |

Deduplication happens before scoring, so a finding reported by four tools is one finding with four
occurrences, not four findings. When the same issue is reported with different severities the
**most pessimistic** severity survives the merge; the **first-seen** title is kept.

## Install

```bash
npm install -g fixqueue
```

Or run it without installing:

```bash
npx fixqueue scan ./scan-results/
```

## 30-second quick start

```bash
# 1. Scan whatever your tools produced (files or directories).
fixqueue scan ./scan-results/ --format md

# 2. Fail CI when something critical appears.
fixqueue scan ./scan-results/ --format json --fail-on critical

# 3. See the queue as SARIF for code-scanning upload.
fixqueue scan ./scan-results/ --format sarif --out results.sarif
```

A complete, deterministic example ships with the repository:

```bash
npm run demo
```

## Supported input formats

| Format | Detection | Notes |
| --- | --- | --- |
| SARIF 2.1.0 | `runs` array | `CVE-`/`GHSA-` tags become the advisory id and aliases; `security-severity` bands override `level` |
| Trivy JSON | `Results` array | Ecosystem is derived from `Results[].Type` |
| Grype JSON | `matches` array | Package from `artifact`, locations from `artifact.locations` |
| OSV | `results` array | `aliases` are preserved; severity comes from `database_specific.severity` |

Format detection is automatic. Force it with `--tool sarif|trivy|grype|osv` when a file is
ambiguous.

## CLI

```
fixqueue scan <paths...> [--format md|json|sarif] [--tool sarif|trivy|grype|osv]
                 [--offline] [--refresh] [--top <n>] [--fail-on <severity>]
                 [--cache-dir <path>] [--ignore-file <path>] [--out <path>]
fixqueue suppress <advisory-id> --reason "<text>" [--expires YYYY-MM-DD] [--ignore-file <path>]
fixqueue cache [--cache-dir <path>]
fixqueue demo
fixqueue help
```

Exit codes: `0` success, `1` findings met the `--fail-on` threshold, `2` usage or input error.

### Offline mode

`fixqueue` caches the EPSS and KEV feeds on disk for 24 hours. In an air-gapped or rate-limited
environment:

```bash
fixqueue scan ./scan-results/ --offline
```

Offline mode uses the cache only, and **fails loudly** when a required cache entry is missing
rather than silently producing an un-enriched queue. Populate the cache first with one online run,
or use `--refresh` to force a fresh fetch.

### Suppressing accepted risk

`fixqueue suppress` appends a rule to `.fixqueueignore` (override with `--ignore-file`):

```bash
fixqueue suppress CVE-2021-44228 --reason "accepted risk, mitigated at the edge" --expires 2026-12-01
```

Matcher syntax:

| Matcher | Matches |
| --- | --- |
| `CVE-2021-44228`, `GHSA-...` | The finding's advisory id or any of its aliases |
| `npm:lodash@4.17.20` | The package in a specific ecosystem |
| `lodash@4.17.20` | The package name and version, in any ecosystem |

An expiry date is valid through the end of that day. Expired rules are reported, not silently
applied.

## Library use

```js
import { dedupe, enrich, rank, toMarkdown } from 'fixqueue';

const queue = rank(enrich(dedupe(findings), { epss, kev }));
console.log(toMarkdown(queue, { generatedAt: new Date().toISOString() }));
```

## Development

```bash
npm test          # node --test with an explicit test file list
npm run demo      # deterministic offline demo
```

Requires Node.js 18 or newer. The test suite has no network access and no runtime dependencies.

## Scope and legal

`fixqueue` reads scanner output that you already produced. It does not scan targets, probe
services, or send traffic to any host other than the public EPSS and CISA feeds, and only when
you ask it to.

Use it on systems you own or are explicitly authorized to test. Generated queues may contain
sensitive details about your code and dependencies — review before sharing.

## Author

Priyanshu Kumar Thakur (Gravion)

## Sponsors

Sponsorship pays for the maintenance, triage and release time behind this tool. Sponsors are
listed here by name, and name placement starts at the $25 a month tier.

- [Sponsor on GitHub](https://github.com/sponsors/gravion-ux)

## License

[MIT](LICENSE)
