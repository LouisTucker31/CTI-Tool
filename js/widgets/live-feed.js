/**
 * widgets/live-feed.js — the Live Threat Feed widget.
 *
 * Reads from the 'feedArticles' store (raw FreeIntelHub articles, see
 * feed-ingest.js and the store comment in db.js) and renders a filterable
 * list: date-range preset, sector dropdown, and a small boolean text search
 * supporting AND / OR / NOT and "quoted phrases", matching the same syntax
 * FreeIntelHub's own search uses. All filtering happens client-side against
 * whatever's already in IndexedDB — "Refresh feed" is a separate, explicit
 * action that goes and fetches anything new.
 *
 * Deliberately NOT wired into the dashboard's main filter bar (sector/
 * client/severity/time) — that bar drives the analyst-report widgets via
 * filters.js, which assumes the ThreatRecord schema (severity/confidence
 * scores etc.) this feed data doesn't have. This widget keeps its own
 * small filter row instead.
 */

import { dbGetAll } from '../db.js';
import { ingestFeed } from '../feed-ingest.js';
import { escapeHtml, formatDateTimeUK } from '../helpers.js';

const RANGE_OPTIONS = [
  { value: '7', label: 'Last 7 days' },
  { value: '30', label: 'Last 30 days', selected: true },
  { value: '180', label: 'Last 6 months' },
  { value: '365', label: 'Last 12 months' },
  { value: 'all', label: 'All time' },
];

// ---------------------------------------------------------------------------
// Pure logic — boolean text matching, no DOM dependency
// ---------------------------------------------------------------------------

/**
 * Supports: `APT29 AND ransomware`, `"LockBit" NOT "ESXi"`, OR groups, and
 * bare space-separated terms (treated as AND). Case-insensitive substring
 * match against the given text.
 */
export function evaluateBooleanQuery(text, query) {
  if (!query || !query.trim()) return true;
  const haystack = (text || '').toLowerCase();

  const orGroups = query.split(/\bOR\b/i).map((g) => g.trim()).filter(Boolean);

  return orGroups.some((group) => {
    const andTerms = group.split(/\bAND\b/i).map((t) => t.trim()).filter(Boolean);
    return andTerms.every((term) => {
      let negate = false;
      let t = term;
      if (/^NOT\s+/i.test(t)) {
        negate = true;
        t = t.replace(/^NOT\s+/i, '');
      }
      t = t.replace(/^"(.*)"$/, '$1').toLowerCase().trim();
      if (!t) return true;
      const found = haystack.includes(t);
      return negate ? !found : found;
    });
  });
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function articleRowHtml(article) {
  const sectorTag = article.sector
    ? `<span class="livefeed-tag">${escapeHtml(article.sector)}</span>` : '';
  const tlpTag = `<span class="livefeed-tag livefeed-tlp-${(article.tlp || 'white').toLowerCase()}">${escapeHtml(article.tlp || 'WHITE')}</span>`;
  const cves = article.iocs?.cves?.length
    ? `<span class="livefeed-tag">${escapeHtml(article.iocs.cves.join(', '))}</span>` : '';
  const mitre = (article.mitreTechniques || [])
    .map((m) => `<span class="livefeed-tag" title="${escapeHtml(m.tactic || '')}">${escapeHtml(m.id)}</span>`)
    .join('');

  return `
    <div class="report-row livefeed-row">
      <div class="report-row-title-line">
        <a class="report-row-title" href="${escapeHtml(article.link)}" target="_blank" rel="noopener noreferrer">${escapeHtml(article.title)}</a>
      </div>
      <div class="report-row-meta">${escapeHtml(article.source)} &middot; ${formatDateTimeUK(article.publishedAt)}</div>
      <div class="livefeed-tags">${sectorTag}${tlpTag}${cves}${mitre}</div>
    </div>
  `;
}

export async function renderLiveFeed(container) {
  container.innerHTML = `
    <div class="livefeed-controls">
      <button type="button" class="btn" id="livefeedRefreshBtn">Refresh feed</button>
      <select id="livefeedRange">
        ${RANGE_OPTIONS.map((o) => `<option value="${o.value}"${o.selected ? ' selected' : ''}>${o.label}</option>`).join('')}
      </select>
      <select id="livefeedSector"><option value="">All sectors</option></select>
      <input type="text" id="livefeedSearch" placeholder='e.g. APT29 AND ransomware, &quot;LockBit&quot; NOT &quot;ESXi&quot;'>
    </div>
    <p class="tile-placeholder-note" id="livefeedStatus"></p>
    <div class="livefeed-list" id="livefeedList"></div>
  `;

  const statusEl = container.querySelector('#livefeedStatus');
  const listEl = container.querySelector('#livefeedList');
  const rangeEl = container.querySelector('#livefeedRange');
  const sectorEl = container.querySelector('#livefeedSector');
  const searchEl = container.querySelector('#livefeedSearch');
  const refreshBtn = container.querySelector('#livefeedRefreshBtn');

  let articles = await dbGetAll('feedArticles');

  function populateSectors() {
    const current = sectorEl.value;
    const sectors = [...new Set(articles.map((a) => a.sector).filter(Boolean))].sort();
    sectorEl.innerHTML = '<option value="">All sectors</option>'
      + sectors.map((s) => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('');
    sectorEl.value = current; // preserve selection across a refresh
  }

  function applyFilters() {
    const rangeDays = rangeEl.value;
    const sector = sectorEl.value;
    const query = searchEl.value;
    const cutoff = rangeDays === 'all' ? null : Date.now() - Number(rangeDays) * 86400000;

    const filtered = articles.filter((a) => {
      if (cutoff && (!a.publishedAt || new Date(a.publishedAt).getTime() < cutoff)) return false;
      if (sector && a.sector !== sector) return false;
      if (!evaluateBooleanQuery(`${a.title} ${a.summary}`, query)) return false;
      return true;
    });

    filtered.sort((a, b) => new Date(b.publishedAt || 0) - new Date(a.publishedAt || 0));

    listEl.innerHTML = filtered.length
      ? filtered.map(articleRowHtml).join('')
      : '<p class="tile-placeholder-note">No matching feed items.</p>';

    statusEl.textContent = articles.length === 0
      ? 'No feed items yet — click "Refresh feed" to pull the latest from FreeIntelHub.'
      : `${filtered.length} of ${articles.length} feed items shown.`;
  }

  populateSectors();
  applyFilters();

  rangeEl.addEventListener('change', applyFilters);
  sectorEl.addEventListener('change', applyFilters);
  searchEl.addEventListener('input', applyFilters);

  refreshBtn.addEventListener('click', async () => {
    refreshBtn.disabled = true;
    refreshBtn.textContent = 'Refreshing\u2026';
    try {
      const result = await ingestFeed();
      articles = await dbGetAll('feedArticles');
      populateSectors();
      applyFilters();
      statusEl.textContent = `Refreshed: ${result.newCount} new, ${result.duplicateCount} already stored.`;
    } catch (err) {
      statusEl.textContent = `Refresh failed: ${err.message}`;
    } finally {
      refreshBtn.disabled = false;
      refreshBtn.textContent = 'Refresh feed';
    }
  });
}
