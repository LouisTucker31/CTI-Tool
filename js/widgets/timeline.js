/**
 * widgets/timeline.js — the Threat Timeline widget.
 *
 * A plain HTML/CSS vertical timeline: one continuous line down the left
 * side, a dot per entry, date + title + severity/confidence to the right,
 * the whole list scrolling naturally inside the tile. No charting library —
 * a vertical line-and-dot feed doesn't need one, and building it by hand
 * avoids fighting a Gantt-style library's own default styling (which is
 * what the previous vis-timeline version kept running into).
 *
 * Threat records and incidents are merged into one chronological
 * (newest-first) list rather than kept in separate rows — the "Show"
 * dropdown filters which category is visible, replacing the old zoom
 * controls with something more deliberate. Forecasts are deliberately left
 * out here — this tool is about confirmed/actual activity, not predictions.
 *
 * The data-shaping logic (buildVerticalTimelineEntries) stays separate from
 * the DOM-building code, same reasoning as every other widget here: it's
 * plain data-in/data-out and the part worth unit testing without a browser.
 */

import { getFilteredThreatRecords, getFilteredChildRecords } from '../filters.js';
import { escapeHtml, severityChip, citeChip, formatDateUK } from '../helpers.js';

const CATEGORY_LABELS = {
  threat: 'Threat Record',
  incident: 'Incident',
};

/** YYYY / YYYY-MM / YYYY-MM-DD -> a full YYYY-MM-DD string for reliable sorting. */
function normalizeDate(dateStr) {
  if (!dateStr || dateStr === 'Unknown') return null;
  if (/^\d{4}$/.test(dateStr)) return `${dateStr}-01-01`;
  if (/^\d{4}-\d{2}$/.test(dateStr)) return `${dateStr}-01`;
  return dateStr;
}

// ---------------------------------------------------------------------------
// Pure data-shaping logic — no DOM dependency, fully unit-testable
// ---------------------------------------------------------------------------

/**
 * Merges threat records and incidents into one newest-first list.
 * @returns {Array<{id, category, sortDate, dateLabel, title, severityLabel, confidenceLabel, sourceCitationIds}>}
 */
export function buildVerticalTimelineEntries(threatRecords, incidents) {
  const entries = [];

  for (const t of threatRecords) {
    const raw = t.lastObservedDate || t.firstObservedDate;
    const sortDate = normalizeDate(raw);
    if (!sortDate) continue;
    entries.push({
      id: t.threatId,
      threatId: t.threatId,
      category: 'threat',
      sortDate,
      dateLabel: t.lastObservedDate ? `Last observed ${formatDateUK(t.lastObservedDate)}` : `First observed ${formatDateUK(t.firstObservedDate)}`,
      title: t.threatTitle,
      severityLabel: t.severityLabel,
      confidenceLabel: t.confidenceLabel,
      sourceCitationIds: t.sourceCitationIds,
    });
  }

  for (const inc of incidents) {
    const raw = inc.incidentDate || inc.firstObservedDate;
    const sortDate = normalizeDate(raw);
    if (!sortDate) continue;
    entries.push({
      id: inc.incidentId,
      threatId: inc.parentThreatId,
      category: 'incident',
      sortDate,
      dateLabel: `Incident date ${formatDateUK(inc.incidentDate || inc.firstObservedDate)}`,
      title: inc.incidentTitle,
      severityLabel: inc.severityLabel,
      confidenceLabel: inc.confidenceLabel,
      sourceCitationIds: inc.sourceCitationIds,
    });
  }

  entries.sort((a, b) => (a.sortDate < b.sortDate ? 1 : a.sortDate > b.sortDate ? -1 : 0)); // newest first

  return entries;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function entryHtml(entry) {
  return `
    <div class="vtimeline-entry vtimeline-${entry.category}">
      <div class="vtimeline-dot"></div>
      <div class="vtimeline-content">
        <div class="vtimeline-date">${escapeHtml(entry.dateLabel)}</div>
        <div class="vtimeline-title clickable-title" data-threat-id="${escapeHtml(entry.threatId)}">${escapeHtml(entry.title || 'Untitled')}</div>
        <div class="vtimeline-meta">
          <span class="vtimeline-category-tag">${CATEGORY_LABELS[entry.category]}</span>
          ${entry.severityLabel ? severityChip(entry) : ''}
          ${citeChip(entry.sourceCitationIds)}
        </div>
      </div>
    </div>
  `;
}

export async function renderThreatTimeline(container) {
  const [threatRecords, incidents] = await Promise.all([
    getFilteredThreatRecords(),
    getFilteredChildRecords('incidents'),
  ]);

  const entries = buildVerticalTimelineEntries(threatRecords, incidents);

  if (entries.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No dated threats or incidents to plot yet.</p>';
    return;
  }

  const counts = {
    threat: entries.filter((e) => e.category === 'threat').length,
    incident: entries.filter((e) => e.category === 'incident').length,
  };

  container.classList.add('tile-body-vtimeline');
  container.innerHTML = `
    <div class="vtimeline-controls">
      <label for="vtimelineFilter">Show</label>
      <select id="vtimelineFilter">
        <option value="all">All (${entries.length})</option>
        <option value="threat">Threat Records (${counts.threat})</option>
        <option value="incident">Incidents (${counts.incident})</option>
      </select>
    </div>
    <div class="vtimeline-list" id="vtimelineList"></div>
  `;

  const listEl = container.querySelector('#vtimelineList');
  const filterEl = container.querySelector('#vtimelineFilter');

  function renderList(filter) {
    const filtered = filter === 'all' ? entries : entries.filter((e) => e.category === filter);
    listEl.innerHTML = filtered.map(entryHtml).join('');
  }

  renderList('all');
  filterEl.addEventListener('change', () => renderList(filterEl.value));
}
