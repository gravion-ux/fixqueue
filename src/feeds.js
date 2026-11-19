/**
 * fixqueue — retrieval of the EPSS and CISA KEV intelligence feeds.
 * @module fixqueue/feeds
 */

import https from 'node:https';

import { DEFAULT_TTL_MS, readCache, resolveCacheRoot, writeCache } from './cache.js';

/**
 * URL of the CISA Known Exploited Vulnerabilities catalogue.
 * @type {string}
 */
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/**
 * Base URL of the FIRST EPSS API.
 * @type {string}
 */
export const EPSS_URL = 'https://api.first.org/data/v1/epss';

/**
 * Maximum number of redirects followed by the default HTTP helper.
 * @type {number}
 */
const MAX_REDIRECTS = 5;

/**
 * Request timeout in milliseconds.
 * @type {number}
 */
const REQUEST_TIMEOUT_MS = 30_000;

/**
 * Perform a GET request with the Node https module, following redirects.
 * @param {string} url - Absolute URL to request.
 * @param {number} [redirects] - Redirects already followed.
 * @returns {Promise<{ statusCode: number, body: string }>} The response status and body.
 */
function httpsGet(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, (response) => {
      const status = response.statusCode ?? 0;
      const location = response.headers.location;
      if (status >= 300 && status < 400 && location) {
        response.resume();
        if (redirects >= MAX_REDIRECTS) {
          reject(new Error(`too many redirects while fetching ${url}`));
          return;
        }
        resolve(httpsGet(new URL(location, url).toString(), redirects + 1));
        return;
      }
      if (status < 200 || status >= 300) {
        response.resume();
        reject(new Error(`request to ${url} failed with status ${status}`));
        return;
      }
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ statusCode: status, body: Buffer.concat(chunks).toString('utf8') }));
    });
    request.setTimeout(REQUEST_TIMEOUT_MS, () => {
      request.destroy(new Error(`request to ${url} timed out after ${REQUEST_TIMEOUT_MS}ms`));
    });
    request.on('error', reject);
  });
}

/**
 * Resolve the HTTP helper to use for a feed request.
 * @param {{ fetchImpl?: Function }} [opts] - Options carrying an injectable helper.
 * @returns {Function} The injectable helper, or the default https helper.
 */
function resolveFetch(opts = {}) {
  return typeof opts.fetchImpl === 'function' ? opts.fetchImpl : httpsGet;
}

/**
 * Maximum number of CVEs sent in a single EPSS request.
 *
 * The EPSS API takes the identifiers as a comma-separated query parameter, so an
 * unbounded list would produce an over-long URL that the server rejects.
 * @type {number}
 */
export const EPSS_BATCH_SIZE = 100;

/**
 * Normalise a list of CVE identifiers into an uppercase, duplicate-free list.
 * @param {string[]} cves - Raw CVE identifiers.
 * @returns {string[]} The normalised identifiers in first-seen order.
 */
function normalizeCves(cves) {
  const seen = new Set();
  const result = [];
  for (const cve of Array.isArray(cves) ? cves : []) {
    if (typeof cve !== 'string' || !cve) continue;
    const normalized = cve.toUpperCase();
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    result.push(normalized);
  }
  return result;
}

/**
 * Fetch and parse the CISA KEV catalogue.
 * @param {{ fetchImpl?: Function }} [opts] - Options carrying an injectable HTTP helper.
 * @returns {Promise<{ catalogVersion: string|null, dateReleased: string|null, cves: object }>}
 *   The catalogue version and a map of KEV records keyed by uppercase CVE id.
 */
export async function fetchKev(opts = {}) {
  const fetchImpl = resolveFetch(opts);
  const response = await fetchImpl(KEV_URL);
  const doc = JSON.parse(response.body);
  const cves = {};
  for (const vulnerability of Array.isArray(doc?.vulnerabilities) ? doc.vulnerabilities : []) {
    if (!vulnerability || typeof vulnerability.cveID !== 'string') continue;
    cves[vulnerability.cveID.toUpperCase()] = {
      dueDate: vulnerability.dueDate ?? null,
      ransomware: vulnerability.knownRansomwareCampaignUse === 'Known',
      vendor: vulnerability.vendorProject ?? null,
      name: vulnerability.vulnerabilityName ?? null,
    };
  }
  return {
    catalogVersion: doc?.catalogVersion ?? null,
    dateReleased: doc?.dateReleased ?? null,
    cves,
  };
}

/**
 * Fetch EPSS probability data for a list of CVE identifiers.
 *
 * The EPSS API accepts several CVEs in one comma-joined request. Long lists are
 * split into bounded batches so the query string never grows past what a server
 * will accept. Identifiers are matched without regard to letter case.
 * @param {string[]} cves - CVE identifiers to look up.
 * @param {{ fetchImpl?: Function }} [opts] - Options carrying an injectable HTTP helper.
 * @returns {Promise<Record<string, { score: number, percentile: number, date: string|null }>>}
 *   EPSS records keyed by uppercase CVE; an empty map when no CVEs are requested.
 */
export async function fetchEpss(cves, opts = {}) {
  const list = normalizeCves(cves);
  if (list.length === 0) return {};
  const fetchImpl = resolveFetch(opts);
  const records = {};
  for (let offset = 0; offset < list.length; offset += EPSS_BATCH_SIZE) {
    const batch = list.slice(offset, offset + EPSS_BATCH_SIZE);
    const url = `${EPSS_URL}?cve=${batch.join(',')}`;
    const response = await fetchImpl(url);
    const doc = JSON.parse(response.body);
    for (const entry of Array.isArray(doc?.data) ? doc.data : []) {
      if (!entry || typeof entry.cve !== 'string') continue;
      const score = Number(entry.epss);
      const percentile = Number(entry.percentile);
      records[entry.cve.toUpperCase()] = {
        score: Number.isFinite(score) ? score : 0,
        percentile: Number.isFinite(percentile) ? percentile : 0,
        date: entry.date ?? null,
      };
    }
  }
  return records;
}

/**
 * Load EPSS and KEV intelligence, using the on-disk cache when it is fresh.
 *
 * In offline mode the cache is the only source; a missing KEV entry is an error
 * rather than a silently un-enriched result.
 * @param {string} root - Cache root directory.
 * @param {{ cves?: string[], offline?: boolean, refresh?: boolean, now?: number|Date, ttlMs?: number, fetchImpl?: Function }} [opts]
 *   Load options.
 * @returns {Promise<{ epss: object, kev: object, fromCache: boolean }>} The enrichment data.
 */
export async function loadEnrichment(root, opts = {}) {
  const {
    cves = [],
    offline = false,
    refresh = false,
    now = Date.now(),
    ttlMs = DEFAULT_TTL_MS,
    fetchImpl,
  } = opts;
  const cacheRoot = resolveCacheRoot(root);
  const requested = normalizeCves(cves);

  const cachedKev = await readCache(cacheRoot, 'kev', ttlMs, now);
  const cachedEpss = await readCache(cacheRoot, 'epss', ttlMs, now);

  const cachedEpssMap = cachedEpss && typeof cachedEpss.cves === 'object' ? cachedEpss.cves : {};
  const epssIndex = new Map();
  for (const [key, value] of Object.entries(cachedEpssMap)) {
    const normalized = key.toUpperCase();
    if (!epssIndex.has(normalized)) epssIndex.set(normalized, value);
  }
  let epssMap = Object.fromEntries(epssIndex);

  if (offline) {
    if (!cachedKev) {
      throw new Error('offline mode requires a populated KEV cache entry; no cache entry was found');
    }
    return { epss: epssMap, kev: cachedKev, fromCache: true };
  }

  let fetched = false;
  let kev = cachedKev;
  if (!kev || refresh) {
    kev = await fetchKev({ fetchImpl });
    await writeCache(cacheRoot, 'kev', kev, now);
    fetched = true;
  }

  const missing = requested.filter((cve) => !epssIndex.has(cve));
  if (refresh || missing.length > 0) {
    const fetchedRecords = await fetchEpss(refresh ? requested : missing, { fetchImpl });
    epssMap = { ...epssMap, ...fetchedRecords };
    await writeCache(cacheRoot, 'epss', { cves: epssMap }, now);
    fetched = true;
  }

  return { epss: epssMap, kev, fromCache: !fetched };
}
