import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  normalizeSarif,
  normalizeTrivy,
  normalizeGrype,
  normalizeOsv,
  detectFormat,
  normalizeAny,
} from '../src/normalize.js';

async function fixture(name) {
  const url = new URL(`./fixtures/${name}`, import.meta.url);
  return JSON.parse(await readFile(url, 'utf8'));
}

test('SARIF adapter produces exactly one canonical finding', async () => {
  const findings = normalizeSarif(await fixture('sarif.json'));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'CVE-2021-44228');
  assert.deepEqual(findings[0].aliases, ['GHSA-jfh8-c2jp-5v3q']);
  assert.equal(findings[0].title, 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints');
  assert.equal(findings[0].severity, 'critical');
  assert.deepEqual(findings[0].package, { ecosystem: 'npm', name: 'log4j-js', version: '2.0.0' });
  assert.deepEqual(findings[0].locations, ['app/package-lock.json:12']);
  assert.deepEqual(findings[0].tools, ['sarif']);
  assert.equal(findings[0].occurrences, 1);
  assert.ok(findings[0].references.includes('https://nvd.nist.gov/vuln/detail/CVE-2021-44228'));
});

test('SARIF adapter prefers a CVE tag as the id and keeps other advisory tags as aliases', async () => {
  const doc = {
    version: '2.1.0',
    runs: [
      {
        results: [
          {
            ruleId: 'RULE-1',
            message: { text: 'title' },
            properties: { tags: ['GHSA-jfh8-c2jp-5v3q', 'CVE-2021-44228'] },
          },
        ],
      },
    ],
  };
  const [finding] = normalizeSarif(doc);
  assert.equal(finding.id, 'CVE-2021-44228');
  assert.deepEqual(finding.aliases, ['GHSA-jfh8-c2jp-5v3q']);
});

test('SARIF adapter falls back to ruleId when no advisory tag is present', async () => {
  const doc = {
    version: '2.1.0',
    runs: [{ results: [{ ruleId: 'EXAMPLE-RULE', level: 'warning', message: { text: 't' } }] }],
  };
  const [finding] = normalizeSarif(doc);
  assert.equal(finding.id, 'EXAMPLE-RULE');
  assert.equal(finding.severity, 'medium');
  assert.deepEqual(finding.aliases, []);
});

test('SARIF adapter maps SARIF levels to the canonical severity vocabulary', () => {
  const levels = { error: 'high', warning: 'medium', note: 'low', none: 'info' };
  for (const [level, expected] of Object.entries(levels)) {
    const doc = { version: '2.1.0', runs: [{ results: [{ ruleId: 'R', level, message: { text: 't' } }] }] };
    assert.equal(normalizeSarif(doc)[0].severity, expected);
  }
});

test('SARIF adapter maps security-severity score bands and overrides level', () => {
  const bands = { '9.8': 'critical', '7.0': 'high', '4.0': 'medium', '0.1': 'low', '0': 'info' };
  for (const [value, expected] of Object.entries(bands)) {
    const doc = {
      version: '2.1.0',
      runs: [{ results: [{ ruleId: 'R', level: 'note', properties: { 'security-severity': value } }] }],
    };
    assert.equal(normalizeSarif(doc)[0].severity, expected);
  }
});

test('Trivy adapter extracts id, severity, package, location and references', async () => {
  const findings = normalizeTrivy(await fixture('trivy.json'));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'CVE-2021-44228');
  assert.equal(findings[0].severity, 'critical');
  assert.deepEqual(findings[0].package, { ecosystem: 'npm', name: 'log4j-js', version: '2.0.0' });
  assert.ok(findings[0].locations[0].startsWith('app/package-lock.json'));
  assert.ok(findings[0].locations[0].includes('log4j-js@2.0.0'));
  assert.ok(findings[0].references.includes('https://nvd.nist.gov/vuln/detail/CVE-2021-44228'));
  assert.ok(findings[0].references.includes('https://github.com/advisories/GHSA-jfh8-c2jp-5v3q'));
  assert.deepEqual(findings[0].tools, ['trivy']);
});

test('Trivy adapter maps UNKNOWN severity to info', () => {
  const doc = {
    Results: [{ Target: 'app/x', Type: 'npm', Vulnerabilities: [{ VulnerabilityID: 'V-1', Severity: 'UNKNOWN' }] }],
  };
  assert.equal(normalizeTrivy(doc)[0].severity, 'info');
});

test('Grype adapter extracts id, severity, package, location and references', async () => {
  const findings = normalizeGrype(await fixture('grype.json'));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'CVE-2021-44228');
  assert.equal(findings[0].severity, 'critical');
  assert.deepEqual(findings[0].package, { ecosystem: 'npm', name: 'log4j-js', version: '2.0.0' });
  assert.deepEqual(findings[0].locations, ['app/package-lock.json']);
  assert.ok(findings[0].references.includes('https://nvd.nist.gov/vuln/detail/CVE-2021-44228'));
  assert.deepEqual(findings[0].tools, ['grype']);
});

test('Grype adapter maps Negligible severity to info', () => {
  const doc = {
    matches: [{ vulnerability: { id: 'G-1', severity: 'Negligible' }, artifact: { name: 'x', version: '1', type: 'npm' } }],
  };
  assert.equal(normalizeGrype(doc)[0].severity, 'info');
});

test('OSV adapter extracts id, aliases, severity, package and source path', async () => {
  const findings = normalizeOsv(await fixture('osv.json'));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'CVE-2021-44228');
  assert.deepEqual(findings[0].aliases, ['GHSA-jfh8-c2jp-5v3q']);
  assert.equal(findings[0].severity, 'critical');
  assert.deepEqual(findings[0].package, { ecosystem: 'npm', name: 'log4j-js', version: '2.0.0' });
  assert.deepEqual(findings[0].locations, ['app/package-lock.json']);
  assert.deepEqual(findings[0].tools, ['osv']);
});

test('OSV adapter falls back to info severity when database_specific.severity is absent', () => {
  const doc = {
    results: [
      {
        source: { path: 'app/package-lock.json' },
        packages: [
          {
            package: { name: 'x', ecosystem: 'npm' },
            version: '1.0.0',
            vulnerabilities: [{ id: 'OSV-1', aliases: [] }],
          },
        ],
      },
    ],
  };
  assert.equal(normalizeOsv(doc)[0].severity, 'info');
});

test('detectFormat identifies each supported format', async () => {
  assert.equal(detectFormat(await fixture('sarif.json')), 'sarif');
  assert.equal(detectFormat(await fixture('trivy.json')), 'trivy');
  assert.equal(detectFormat(await fixture('grype.json')), 'grype');
  assert.equal(detectFormat(await fixture('osv.json')), 'osv');
  assert.equal(detectFormat({}), null);
  assert.equal(detectFormat(null), null);
});

test('normalizeAny dispatches on the detected format', async () => {
  const findings = normalizeAny(await fixture('grype.json'));
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].tools, ['grype']);
});

test('normalizeAny honours an explicit tool override', async () => {
  const findings = normalizeAny(await fixture('grype.json'), { tool: 'custom' });
  assert.deepEqual(findings[0].tools, ['custom']);
});

test('normalizeAny returns an empty array for an unknown document', () => {
  assert.deepEqual(normalizeAny({ hello: 'world' }), []);
});

test('malformed documents yield an empty array rather than throwing', () => {
  assert.deepEqual(normalizeSarif({}), []);
  assert.deepEqual(normalizeTrivy({}), []);
  assert.deepEqual(normalizeGrype({}), []);
  assert.deepEqual(normalizeOsv({}), []);
  assert.deepEqual(normalizeSarif(null), []);
  assert.deepEqual(normalizeTrivy(null), []);
  assert.deepEqual(normalizeGrype(undefined), []);
  assert.deepEqual(normalizeOsv('not-a-document'), []);
});
