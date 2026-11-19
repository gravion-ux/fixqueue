import test from 'node:test';
import assert from 'node:assert/strict';

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { fetchKev, fetchEpss, loadEnrichment, KEV_URL } from '../src/feeds.js';
import { readCache, writeCache } from '../src/cache.js';

const NOW = 1_760_000_000_000;

const KEV_DOCUMENT = {
  catalogVersion: '2026.11.04',
  dateReleased: '2026-11-04T12:00:00.0000Z',
  vulnerabilities: [
    {
      cveID: 'CVE-2021-44228',
      vendorProject: 'Apache',
      product: 'Log4j2',
      vulnerabilityName: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints',
      dateAdded: '2021-12-10',
      dueDate: '2021-12-24',
      knownRansomwareCampaignUse: 'Known',
    },
    {
      cveID: 'CVE-2020-11111',
      vendorProject: 'Example',
      product: 'Widget',
      vulnerabilityName: 'Example widget issue',
      dateAdded: '2020-05-01',
      dueDate: '2020-05-15',
      knownRansomwareCampaignUse: 'Unknown',
    },
  ],
};

const EPSS_DOCUMENT = {
  status: 'OK',
  data: [
    { cve: 'CVE-2021-44228', epss: '0.979630000', percentile: '0.998740000', date: '2026-11-04' },
    { cve: 'CVE-2020-11111', epss: '0.100000000', percentile: '0.400000000', date: '2026-11-04' },
  ],
};

/**
 * Build a recording fetch implementation that returns canned documents.
 * @param {object} responses - Map of URL substring to the response body.
 * @returns {Function} A fetch implementation that records the URLs it was called with.
 */
function recordingFetch(responses) {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    for (const [needle, body] of Object.entries(responses)) {
      if (url.includes(needle)) return { statusCode: 200, body: JSON.stringify(body) };
    }
    return { statusCode: 404, body: '{}' };
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

test('fetchKev requests the CISA KEV catalogue URL', async () => {
  const fetchImpl = recordingFetch({ 'known_exploited_vulnerabilities': KEV_DOCUMENT });
  await fetchKev({ fetchImpl });
  assert.equal(fetchImpl.calls[0], KEV_URL);
});

test('fetchKev parses vulnerabilities into a map keyed by cveID', async () => {
  const fetchImpl = recordingFetch({ 'known_exploited_vulnerabilities': KEV_DOCUMENT });
  const result = await fetchKev({ fetchImpl });
  assert.equal(result.catalogVersion, '2026.11.04');
  assert.equal(Object.keys(result.cves).length, 2);
  assert.ok(result.cves['CVE-2021-44228']);
});

test('fetchKev flags ransomware use and carries the due date', async () => {
  const fetchImpl = recordingFetch({ 'known_exploited_vulnerabilities': KEV_DOCUMENT });
  const result = await fetchKev({ fetchImpl });
  assert.equal(result.cves['CVE-2021-44228'].ransomware, true);
  assert.equal(result.cves['CVE-2021-44228'].dueDate, '2021-12-24');
  assert.equal(result.cves['CVE-2020-11111'].ransomware, false);
});

test('fetchEpss requests the EPSS API with comma-joined CVEs', async () => {
  const fetchImpl = recordingFetch({ 'api.first.org': EPSS_DOCUMENT });
  await fetchEpss(['CVE-2021-44228', 'CVE-2020-11111'], { fetchImpl });
  assert.equal(fetchImpl.calls[0], 'https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2020-11111');
});

test('fetchEpss parses data entries into a map with numeric conversion', async () => {
  const fetchImpl = recordingFetch({ 'api.first.org': EPSS_DOCUMENT });
  const result = await fetchEpss(['CVE-2021-44228', 'CVE-2020-11111'], { fetchImpl });
  assert.deepEqual(result['CVE-2021-44228'], {
    score: 0.97963,
    percentile: 0.99874,
    date: '2026-11-04',
  });
  assert.equal(typeof result['CVE-2020-11111'].score, 'number');
});

test('fetchEpss with an empty CVE list performs no request', async () => {
  const fetchImpl = recordingFetch({ 'api.first.org': EPSS_DOCUMENT });
  const result = await fetchEpss([], { fetchImpl });
  assert.deepEqual(result, {});
  assert.equal(fetchImpl.calls.length, 0);
});

test('loadEnrichment in offline mode uses only the cache', async () => {
  const root = await mkdtemp(join(tmpdir(), 'fixqueue-feeds-'));
  try {
    await writeCache(root, 'kev', { catalogVersion: '2026.11.04', cves: {} }, NOW);
    await writeCache(root, 'epss', { cves: { 'CVE-2021-44228': { score: 0.9, percentile: 0.9, date: '2026-11-04' } } }, NOW);
    const fetchImpl = recordingFetch({});
    const result = await loadEnrichment(root, { offline: true, now: NOW, fetchImpl });
    assert.equal(result.fromCache, true);
    assert.equal(result.kev.catalogVersion, '2026.11.04');
    assert.equal(fetchImpl.calls.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('loadEnrichment in offline mode without a KEV cache entry fails loudly', async () => {
  const root = await mkdtemp(join(tmpdir(), 'fixqueue-feeds-'));
  try {
    await assert.rejects(
      () => loadEnrichment(root, { offline: true, now: NOW, fetchImpl: recordingFetch({}) }),
      /cache/i,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('loadEnrichment with refresh bypasses a fresh cache and writes the new snapshot', async () => {
  const root = await mkdtemp(join(tmpdir(), 'fixqueue-feeds-'));
  try {
    await writeCache(root, 'kev', { catalogVersion: 'stale', cves: {} }, NOW);
    const fetchImpl = recordingFetch({
      'known_exploited_vulnerabilities': KEV_DOCUMENT,
      'api.first.org': EPSS_DOCUMENT,
    });
    const result = await loadEnrichment(root, {
      cves: ['CVE-2021-44228'],
      refresh: true,
      now: NOW,
      fetchImpl,
    });
    assert.equal(result.fromCache, false);
    assert.equal(result.kev.catalogVersion, '2026.11.04');
    const cached = await readCache(root, 'kev', 60_000, NOW);
    assert.equal(cached.catalogVersion, '2026.11.04');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('loadEnrichment reuses a fresh cache without touching the network', async () => {
  const root = await mkdtemp(join(tmpdir(), 'fixqueue-feeds-'));
  try {
    await writeCache(root, 'kev', { catalogVersion: '2026.11.04', cves: {} }, NOW);
    await writeCache(root, 'epss', { cves: { 'CVE-2021-44228': { score: 0.9, percentile: 0.9, date: '2026-11-04' } } }, NOW);
    const fetchImpl = recordingFetch({});
    const result = await loadEnrichment(root, { cves: ['CVE-2021-44228'], now: NOW, fetchImpl });
    assert.equal(result.fromCache, true);
    assert.equal(fetchImpl.calls.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('loadEnrichment fetches EPSS data for CVEs missing from the cache', async () => {
  const root = await mkdtemp(join(tmpdir(), 'fixqueue-feeds-'));
  try {
    await writeCache(root, 'kev', { catalogVersion: '2026.11.04', cves: {} }, NOW);
    await writeCache(root, 'epss', { cves: { 'CVE-2021-44228': { score: 0.9, percentile: 0.9, date: '2026-11-04' } } }, NOW);
    const fetchImpl = recordingFetch({ 'api.first.org': EPSS_DOCUMENT });
    const result = await loadEnrichment(root, { cves: ['CVE-2020-11111'], now: NOW, fetchImpl });
    assert.equal(fetchImpl.calls.length, 1);
    assert.ok(result.epss['CVE-2020-11111']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('fetchEpss splits a large CVE list into bounded requests', async () => {
  const cves = Array.from({ length: 250 }, (_, index) => `CVE-2026-${String(index).padStart(4, '0')}`);
  const fetchImpl = recordingFetch({ 'api.first.org': { data: [] } });
  await fetchEpss(cves, { fetchImpl });
  assert.ok(fetchImpl.calls.length > 1, 'expected the request to be split');
  for (const call of fetchImpl.calls) {
    assert.ok(call.length < 2_000, `request URL is ${call.length} characters`);
  }
});

test('fetchEpss deduplicates the requested CVE list', async () => {
  const fetchImpl = recordingFetch({ 'api.first.org': EPSS_DOCUMENT });
  await fetchEpss(['CVE-2021-44228', 'CVE-2021-44228'], { fetchImpl });
  assert.equal(fetchImpl.calls.length, 1);
  assert.ok(fetchImpl.calls[0].endsWith('?cve=CVE-2021-44228'));
});

test('loadEnrichment normalizes CVE case so a lowercase request hits the cache', async () => {
  const root = await mkdtemp(join(tmpdir(), 'fixqueue-feeds-'));
  try {
    await writeCache(root, 'kev', { catalogVersion: '2026.11.04', cves: {} }, NOW);
    await writeCache(root, 'epss', { cves: { 'CVE-2021-44228': { score: 0.9, percentile: 0.9, date: '2026-11-04' } } }, NOW);
    const fetchImpl = recordingFetch({});
    const result = await loadEnrichment(root, { cves: ['cve-2021-44228'], now: NOW, fetchImpl });
    assert.equal(result.fromCache, true);
    assert.equal(fetchImpl.calls.length, 0);
    assert.ok(result.epss['CVE-2021-44228']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('loadEnrichment caches fetched EPSS records under a normalized key', async () => {
  const root = await mkdtemp(join(tmpdir(), 'fixqueue-feeds-'));
  try {
    await writeCache(root, 'kev', { catalogVersion: '2026.11.04', cves: {} }, NOW);
    const fetchImpl = recordingFetch({ 'api.first.org': EPSS_DOCUMENT });
    await loadEnrichment(root, { cves: ['cve-2021-44228'], now: NOW, fetchImpl });
    const second = await loadEnrichment(root, { cves: ['cve-2021-44228'], now: NOW, fetchImpl });
    assert.equal(second.fromCache, true);
    assert.equal(fetchImpl.calls.filter((call) => call.includes('api.first.org')).length, 1);
    assert.ok(second.epss['CVE-2021-44228']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
