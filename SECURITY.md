# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting a vulnerability

Please report suspected vulnerabilities privately by opening a GitHub Security Advisory on the
repository rather than a public issue. Include the affected version, reproduction steps, and the
impact you observed.

You can expect an acknowledgement within a few days. Fixes are released as a new patch version.

Maintainer: Priyanshu Kumar Thakur (Gravion).

## Scope and authorized use

`fixqueue` is a defensive triage tool. It processes scanner output that you already have and
enriches it with public threat-intelligence data.

- `fixqueue` does not scan, probe, or exploit any target.
- The only outbound requests it makes are to the public EPSS API and the CISA KEV catalogue, and
  only when you run a scan without `--offline`.
- The cache directory (`.fixqueue/` by default) stores downloaded feed snapshots. Review it before
  sharing a workspace.
- Feed snapshots are public data, but your scan results may contain confidential information about
  your code and dependencies.

Only use `fixqueue` on systems you own or are explicitly authorized to assess.
