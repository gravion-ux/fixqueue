# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-05

### Added

- Format adapters for SARIF 2.1.0, Trivy JSON, Grype JSON and OSV, with automatic format
  detection and an explicit `--tool` override.
- Canonical finding model with normalized severity vocabulary
  (`critical`, `high`, `medium`, `low`, `info`).
- Transitive deduplication across advisory ids and aliases, including CVE/GHSA/OSV/PYSEC/RUSTSEC
  prefixes.
- EPSS and CISA KEV enrichment with an injectable HTTP client and a 24-hour on-disk cache.
- Deterministic 0-100 priority scoring with a full `scoreBreakdown`, capped at exactly 100.
- Accepted-risk suppression rules with advisory-id, ecosystem-qualified and package matchers,
  plus expiry dates.
- Markdown, JSON and SARIF 2.1.0 report emitters.
- `scan`, `suppress`, `cache`, `demo` and `help` CLI subcommands with exit codes 0, 1 and 2.
- Offline mode that fails loudly when a required cache entry is missing.

[0.1.0]: https://github.com/gravion-ux/fixqueue/releases/tag/v0.1.0
