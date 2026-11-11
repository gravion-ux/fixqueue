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
 * Fetch and parse the CISA KEV catalogue.
 * @param {{ fetchImpl?: Function }} [opts] - Options carrying an injectable HTTP helper.
 * @returns {Promise<{ catalogVersion: string|null, dateReleased: string|null, cves: object }>}
 *   The catalogue version and a map of CVE records.
 */
export async function fetchKev(opts = {}) {
  const fetchImpl = resolveFetch(opts);
  const response = await fetchImpl(KEV_URL);
  const doc = JSON.parse(response.body);
  const cves = {};
  for (const vulnerability of Array.isArray(doc?.vulnerabilities) ? doc.vulnerabilities : []) {
    if (!vulnerability || typeof vulnerability.cveID !== 'string') continue;
    cves[vulnerability.cveID] = {
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
 * The EPSS API accepts several CVEs in one comma-joined request.
 * @param {string[]} cves - CVE identifiers to look up.
 * @param {{ fetchImpl?: Function }} [opts] - Options carrying an injectable HTTP helper.
 * @returns {Promise<Record<string, { score: number, percentile: number, date: string|null }>>}
 *   EPSS records keyed by CVE; an empty map when no CVEs are requested.
 */
export async function fetchEpss(cves, opts = {}) {
  const list = Array.isArray(cves) ? cves.filter((cve) => typeof cve === 'string' && cve) : [];
  if (list.length === 0) return {};
  const fetchImpl = resolveFetch(opts);
  const url = `${EPSS_URL}?cve=${list.join(',')}`;
  const response = await fetchImpl(url);
  const doc = JSON.parse(response.body);
  const records = {};
  for (const entry of Array.isArray(doc?.data) ? doc.data : []) {
    if (!entry || typeof entry.cve !== 'string') continue;
    const score = Number(entry.epss);
    const percentile = Number(entry.percentile);
    records[entry.cve] = {
      score: Number.isFinite(score) ? score : 0,
      percentile: Number.isFinite(percentile) ? percentile : 0,
      date: entry.date ?? null,
    };
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
  const requested = Array.isArray(cves) ? cves.filter((cve) => typeof cve === 'string' && cve) : [];

  const cachedKev = await readCache(cacheRoot, 'kev', ttlMs, now);
  const cachedEpss = await readCache(cacheRoot, 'epss', ttlMs, now);

  if (offline) {
    if (!cachedKev) {
      throw new Error('offline mode requires a populated KEV cache entry; no cache entry was found');
    }
    const epssMap = cachedEpss && typeof cachedEpss.cves === 'object' ? cachedEpss.cves : {};
    return { epss: epssMap, kev: cachedKev, fromCache: true };
  }

  let fetched = false;
  let kev = cachedKev;
  if (!kev || refresh) {
    kev = await fetchKev({ fetchImpl });
    await writeCache(cacheRoot, 'kev', kev, now);
    fetched = true;
  }

  let epssMap = cachedEpss && typeof cachedEpss.cves === 'object' ? cachedEpss.cves : {};
  const missing = requested.filter((cve) => !epssMap[cve]);
  if (refresh || missing.length > 0) {
    const fetchedRecords = await fetchEpss(refresh ? requested : missing, { fetchImpl });
    epssMap = { ...epssMap, ...fetchedRecords };
    await writeCache(cacheRoot, 'epss', { cves: epssMap }, now);
    fetched = true;
  }

  return { epss: epssMap, kev, fromCache: !fetched };
}
