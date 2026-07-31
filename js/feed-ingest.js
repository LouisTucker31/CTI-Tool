/**
 * feed-ingest.js — pulls articles from the FreeIntelHub public API and
 * stores them in the 'feedArticles' store (see db.js / docs/schema.md).
 *
 * This is intentionally separate from parser.js: parser.js turns an
 * analyst-written report into the rich Report/ThreatRecord/Incident/etc.
 * schema, with severity and confidence scores the analyst assessed. This
 * file just normalizes a raw news-aggregator API response — there's no
 * assessment happening here, so no scores are invented. See the comment
 * on the 'feedArticles' store in db.js for the full reasoning.
 *
 * KNOWN CAVEAT (as of testing on 31 July 2026): the public API appeared to
 * ignore `page`/`limit`/filter query params entirely and always returned
 * the same first 20 articles, regardless of what was passed. The loop
 * below still attempts pagination — if that was a fluke of how the test
 * requests were made, or FreeIntelHub starts honouring the param later,
 * this picks up the extra pages automatically. If page 2 comes back
 * identical to page 1, it stops immediately rather than hammering the API
 * 104 times for the same 20 rows. Worth rechecking in DevTools periodically
 * (Network tab, call /api/articles?page=2 from a page's console) in case
 * this changes.
 */

import { dbGetAll, bulkWriteRecords } from './db.js';

const FEED_API_URL = 'https://cloudfare-workerjs.louistucker311097.workers.dev/api/articles';

/** Raw FreeIntelHub article -> our feedArticles row shape. */
export function normalizeArticle(raw) {
  return {
    articleId: `freeintelhub::${raw.id}`,
    title: raw.title || 'Untitled',
    link: raw.link || null,
    summary: raw.summary || '',
    source: raw.source || 'Unknown',
    category: raw.category || null,
    vendor: raw.vendor || null,
    vendorsAll: raw.vendors_all || [],
    sector: raw.sector || null,
    mitreTechniques: raw.mitre_techniques || [],
    iocs: raw.iocs || null,
    tlp: raw.tlp || 'WHITE',
    publishedAt: raw.published_at || null,
    dedupHash: raw.dedup_hash || null,
    fetchedAt: new Date().toISOString(),
    clientTags: [], // manual — added in the dashboard, never supplied by the feed
  };
}

async function fetchFeedPage(page) {
  const res = await fetch(`${FEED_API_URL}?page=${page}`);
  if (!res.ok) throw new Error(`FreeIntelHub API returned ${res.status}`);
  return res.json();
}

/**
 * Fetches what it can from the feed, skips anything already stored
 * (matched on dedup_hash), and writes the rest.
 * @returns {Promise<{fetchedCount:number, newCount:number, duplicateCount:number}>}
 */
export async function ingestFeed({ maxPages = 5 } = {}) {
  const existing = await dbGetAll('feedArticles');
  const knownHashes = new Set(existing.map((a) => a.dedupHash).filter(Boolean));

  const firstPage = await fetchFeedPage(1);
  const collected = [...(firstPage.data || [])];
  let lastPageHashes = new Set(collected.map((a) => a.dedup_hash));

  for (let page = 2; page <= maxPages; page++) {
    const next = await fetchFeedPage(page);
    const nextData = next.data || [];
    if (nextData.length === 0) break;
    const nextHashes = new Set(nextData.map((a) => a.dedup_hash));
    const sameAsPrevious = [...nextHashes].every((h) => lastPageHashes.has(h));
    if (sameAsPrevious) break; // pagination isn't advancing — stop rather than loop pointlessly
    collected.push(...nextData);
    lastPageHashes = nextHashes;
  }

  const normalized = collected.map(normalizeArticle);
  const newOnes = normalized.filter((a) => a.dedupHash && !knownHashes.has(a.dedupHash));

  if (newOnes.length > 0) {
    await bulkWriteRecords({ feedArticles: newOnes });
  }

  return {
    fetchedCount: collected.length,
    newCount: newOnes.length,
    duplicateCount: collected.length - newOnes.length,
  };
}
