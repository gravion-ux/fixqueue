import test from 'node:test';
import assert from 'node:assert/strict';

import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { readCache, writeCache, cacheStatus } from '../src/cache.js';

const NOW = 1_760_000_000_000;

/**
 * Create a temporary directory for a test.
 * @returns {Promise<string>} The temporary directory path.
 */
async function tempDir() {
  return mkdtemp(join(tmpdir(), 'fixqueue-cache-'));
}

test('writeCache then readCache within the TTL returns the payload', async () => {
  const root = await tempDir();
  try {
    await writeCache(root, 'kev', { catalogVersion: '2026.11.04' }, NOW);
    const data = await readCache(root, 'kev', 60_000, NOW + 1_000);
    assert.deepEqual(data, { catalogVersion: '2026.11.04' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('readCache returns null once the TTL has elapsed', async () => {
  const root = await tempDir();
  try {
    await writeCache(root, 'kev', { catalogVersion: '2026.11.04' }, NOW);
    const data = await readCache(root, 'kev', 60_000, NOW + 120_000);
    assert.equal(data, null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('readCache returns null for a missing entry', async () => {
  const root = await tempDir();
  try {
    assert.equal(await readCache(root, 'absent', 60_000, NOW), null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('writeCache creates the directory tree when it is absent', async () => {
  const root = join(await tempDir(), 'nested', 'cache');
  try {
    await writeCache(root, 'kev', { ok: true }, NOW);
    assert.deepEqual(await readCache(root, 'kev', 60_000, NOW), { ok: true });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('cacheStatus reports each entry age and staleness', async () => {
  const root = await tempDir();
  try {
    await writeCache(root, 'kev', { ok: true }, NOW);
    await writeCache(root, 'epss', { cves: {} }, NOW - 120_000);
    const status = await cacheStatus(root, NOW, 60_000);
    assert.equal(status.entries.length, 2);
    const kev = status.entries.find((entry) => entry.name === 'kev');
    const epss = status.entries.find((entry) => entry.name === 'epss');
    assert.equal(kev.ageMs, 0);
    assert.equal(kev.stale, false);
    assert.equal(epss.ageMs, 120_000);
    assert.equal(epss.stale, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('cacheStatus on a missing directory reports no entries', async () => {
  const root = join(await tempDir(), 'absent');
  const status = await cacheStatus(root, NOW);
  assert.deepEqual(status.entries, []);
});

test('a corrupt JSON cache file is treated as a miss rather than throwing', async () => {
  const root = await tempDir();
  try {
    await mkdir(root, { recursive: true });
    await writeFile(join(root, 'kev.json'), '{not valid json', 'utf8');
    assert.equal(await readCache(root, 'kev', 60_000, NOW), null);
    const status = await cacheStatus(root, NOW);
    assert.equal(status.entries.length, 1);
    assert.equal(status.entries[0].corrupt, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('readCache rejects an entry whose fetchedAt is not a number', async () => {
  const root = await tempDir();
  try {
    await mkdir(root, { recursive: true });
    await writeFile(join(root, 'kev.json'), JSON.stringify({ fetchedAt: 'soon', data: {} }), 'utf8');
    assert.equal(await readCache(root, 'kev', 60_000, NOW), null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
