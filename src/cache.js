/**
 * fixqueue — on-disk feed cache with a time-to-live policy.
 * @module fixqueue/cache
 */

import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Default cache lifetime: 24 hours.
 * @type {number}
 */
export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Normalize a timestamp argument into epoch milliseconds.
 * @param {number|Date|undefined} value - Epoch milliseconds, a Date, or undefined.
 * @returns {number} Epoch milliseconds, defaulting to the current time.
 */
function toMs(value) {
  if (value instanceof Date) return value.getTime();
  if (Number.isFinite(value)) return Number(value);
  return Date.now();
}

/**
 * Resolve the directory that holds cache entries.
 * @param {string} [root] - Explicit cache root.
 * @param {string} [cwd] - Working directory used when no root is supplied.
 * @returns {string} Absolute or relative cache root directory.
 */
export function resolveCacheRoot(root, cwd = process.cwd()) {
  if (typeof root === 'string' && root) return root;
  return join(cwd, '.fixqueue', 'cache');
}

/**
 * Read a cached payload, honouring the time-to-live policy.
 *
 * A missing entry, an expired entry, or an unreadable/corrupt file all resolve to
 * null — a cache problem is never an error.
 * @param {string} root - Cache root directory.
 * @param {string} name - Entry name (without the `.json` suffix).
 * @param {number} ttlMs - Entry lifetime in milliseconds.
 * @param {number|Date} [now] - Current time.
 * @returns {Promise<unknown|null>} The cached payload, or null on a miss.
 */
export async function readCache(root, name, ttlMs, now) {
  const current = toMs(now);
  const path = join(root, `${name}.json`);
  let raw;
  try {
    raw = await readFile(path, 'utf8');
  } catch {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const fetchedAt = Number(parsed.fetchedAt);
  if (!Number.isFinite(fetchedAt)) return null;
  if (current - fetchedAt > ttlMs) return null;
  return parsed.data ?? null;
}

/**
 * Write a payload into the cache, creating the directory tree when needed.
 * @param {string} root - Cache root directory.
 * @param {string} name - Entry name (without the `.json` suffix).
 * @param {unknown} data - Payload to store.
 * @param {number|Date} [now] - Timestamp recorded as the fetch time.
 * @returns {Promise<void>} Resolves once the entry has been written.
 */
export async function writeCache(root, name, data, now) {
  await mkdir(root, { recursive: true });
  const payload = JSON.stringify({ fetchedAt: toMs(now), data }, null, 2);
  await writeFile(join(root, `${name}.json`), `${payload}\n`, 'utf8');
}

/**
 * Describe every entry currently held in the cache.
 * @param {string} root - Cache root directory.
 * @param {number|Date} [now] - Current time.
 * @param {number} [ttlMs] - Entry lifetime used to decide staleness.
 * @returns {Promise<{ entries: object[] }>} One descriptor per cache entry.
 */
export async function cacheStatus(root, now, ttlMs = DEFAULT_TTL_MS) {
  const current = toMs(now);
  const entries = [];
  let names = [];
  try {
    names = await readdir(root);
  } catch {
    return { entries };
  }
  for (const name of names.sort()) {
    if (!name.endsWith('.json')) continue;
    const path = join(root, name);
    let parsed = null;
    try {
      parsed = JSON.parse(await readFile(path, 'utf8'));
    } catch {
      entries.push({ name: name.replace(/\.json$/, ''), path, fetchedAt: null, ageMs: null, stale: true, corrupt: true });
      continue;
    }
    const fetchedAt = parsed && Number.isFinite(Number(parsed.fetchedAt)) ? Number(parsed.fetchedAt) : null;
    const ageMs = fetchedAt === null ? null : current - fetchedAt;
    entries.push({
      name: name.replace(/\.json$/, ''),
      path,
      fetchedAt,
      ageMs,
      stale: fetchedAt === null ? true : ageMs > ttlMs,
      corrupt: false,
    });
  }
  return { entries };
}
