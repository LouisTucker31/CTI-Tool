/**
 * widgets/timeline.js — the Threat Timeline widget (vis-timeline).
 *
 * Three rows (vis-timeline "groups"): Threat Records, Incidents, Forecasts.
 * Threat records span first->last observed as a bar; a threat with only one
 * known date renders as a point instead of a zero-width bar. Incidents are
 * always single points (they're a specific date). Forecasts span start->expiry
 * and are drawn with a dashed border to mark them as predictions, not
 * confirmed activity.
 *
 * Colour on threat-record bars reuses the dashboard's severity ramp — this
 * widget doesn't need a type-vs-severity trade-off the way the map did,
 * since the three groups already separate confirmed/incident/forecast.
 *
 * The data-shaping logic (buildTimelineData) is kept separate from the
 * actual vis-timeline instantiation (renderThreatTimeline), same reasoning
 * as the map widget: it's plain data-in/data-out and the part most likely
 * to have real bugs, so it's the part worth unit testing without a browser.
 */

import { dbGetAll } from '../db.js';
import { escapeHtml } from '../helpers.js';

const GROUPS = [
  { id: 'threats', content: 'Threat Records' },
  { id: 'incidents', content: 'Incidents' },
  { id: 'forecasts', content: 'Forecasts' },
];

const SEVERITY_CLASS_BY_LABEL = {
  Critical: 'timeline-severity-critical',
  High: 'timeline-severity-high',
  Moderate: 'timeline-severity-moderate',
  Low: 'timeline-severity-low',
  Informational: 'timeline-severity-informational',
};

/** YYYY / YYYY-MM / YYYY-MM-DD -> a full YYYY-MM-DD string, so vis-timeline
 *  never has to guess how to interpret a partial date. */
function normalizeDate(dateStr) {
  if (!dateStr || dateStr === 'Unknown') return null;
  if (/^\d{4}$/.test(dateStr)) return `${dateStr}-01-01`;
  if (/^\d{4}-\d{2}$/.test(dateStr)) return `${dateStr}-01`;
  return dateStr;
}

// ---------------------------------------------------------------------------
// Pure data-shaping logic — no vis-timeline or DOM dependency
// ---------------------------------------------------------------------------

/**
 * @returns {{ items: Array, groups: Array, rangeMin: string|null, rangeMax: string|null }}
 */
export function buildTimelineData(threatRecords, incidents, forecasts) {
  const items = [];
  const allDates = [];
  const pushDate = (d) => { if (d) allDates.push(d); };

  for (const t of threatRecords) {
    const start = normalizeDate(t.firstObservedDate);
    const end = normalizeDate(t.lastObservedDate);
    if (!start && !end) continue; // nothing datable to plot for this one
    const effectiveStart = start || end;
    const effectiveEnd = end || start;
    pushDate(effectiveStart);
    pushDate(effectiveEnd);
    items.push({
      id: `tr:${t.threatId}`,
      group: 'threats',
      content: escapeHtml(t.threatTitle || 'Untitled threat'),
      title: `${t.threatTitle || 'Untitled threat'} — ${t.severityLabel || 'Unrated'} severity, ${t.confidenceLabel || 'Unknown'} confidence`,
      start: effectiveStart,
      end: effectiveStart === effectiveEnd ? undefined : effectiveEnd,
      type: effectiveStart === effectiveEnd ? 'point' : 'range',
      className: `timeline-item ${SEVERITY_CLASS_BY_LABEL[t.severityLabel] || 'timeline-severity-informational'}`,
    });
  }

  for (const inc of incidents) {
    const date = normalizeDate(inc.incidentDate) || normalizeDate(inc.firstObservedDate);
    if (!date) continue;
    pushDate(date);
    items.push({
      id: `inc:${inc.incidentId}`,
      group: 'incidents',
      content: escapeHtml(inc.incidentTitle || 'Untitled incident'),
      title: `${inc.incidentTitle || 'Untitled incident'} — ${inc.affectedOrganisation || 'Unknown organisation'}`,
      start: date,
      type: 'point',
      className: 'timeline-item timeline-incident',
    });
  }

  for (const f of forecasts) {
    const start = normalizeDate(f.forecastStartDate) || normalizeDate(f.forecastCreationDate);
    const end = normalizeDate(f.forecastExpiryDate);
    if (!start && !end) continue;
    const effectiveStart = start || end;
    const effectiveEnd = end || start;
    pushDate(effectiveStart);
    pushDate(effectiveEnd);
    items.push({
      id: `fc:${f.forecastId}`,
      group: 'forecasts',
      content: escapeHtml(f.forecastTitle || 'Untitled forecast'),
      title: `${f.forecastTitle || 'Untitled forecast'} — ${f.confidenceLabel || 'Unknown'} confidence, expires ${f.forecastExpiryDate || 'Unknown'}`,
      start: effectiveStart,
      end: effectiveStart === effectiveEnd ? undefined : effectiveEnd,
      type: effectiveStart === effectiveEnd ? 'point' : 'range',
      className: 'timeline-item timeline-forecast',
    });
  }

  let rangeMin = null;
  let rangeMax = null;
  if (allDates.length > 0) {
    const sorted = [...allDates].sort();
    rangeMin = sorted[0];
    rangeMax = sorted[sorted.length - 1];
  }

  return { items, groups: GROUPS, rangeMin, rangeMax };
}

// ---------------------------------------------------------------------------
// vis-timeline rendering
// ---------------------------------------------------------------------------

export async function renderThreatTimeline(container) {
  const [threatRecords, incidents, forecasts] = await Promise.all([
    dbGetAll('threatRecords'),
    dbGetAll('incidents'),
    dbGetAll('forecasts'),
  ]);

  const { items, groups, rangeMin, rangeMax } = buildTimelineData(threatRecords, incidents, forecasts);

  if (items.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No dated threats, incidents or forecasts to plot yet.</p>';
    return;
  }

  container.classList.add('tile-body-timeline');
  container.innerHTML = `
    <div class="timeline-canvas"></div>
    <div class="timeline-legend">
      <span><span class="timeline-legend-swatch timeline-severity-critical"></span>Critical</span>
      <span><span class="timeline-legend-swatch timeline-severity-high"></span>High</span>
      <span><span class="timeline-legend-swatch timeline-severity-moderate"></span>Moderate</span>
      <span><span class="timeline-legend-swatch timeline-severity-low"></span>Low</span>
      <span><span class="timeline-legend-swatch timeline-severity-informational"></span>Informational</span>
      <span class="timeline-legend-note">Dashed = forecast, not yet confirmed</span>
    </div>
  `;

  const canvasEl = container.querySelector('.timeline-canvas');

  const options = {
    stack: true,
    zoomMin: 1000 * 60 * 60 * 24 * 7,           // don't allow zooming in past ~1 week
    zoomMax: 1000 * 60 * 60 * 24 * 365 * 20,    // don't allow zooming out past ~20 years
    orientation: 'top',
    tooltip: { followMouse: true },
  };

  // Keep panning/zooming bounded to roughly the data's own date range (plus a
  // little breathing room either side), the same principle as the map's
  // maxBounds — no scrolling off into decades of nothing to look at.
  if (rangeMin && rangeMax) {
    const minMs = new Date(rangeMin).getTime();
    const maxMs = new Date(rangeMax).getTime();
    const pad = Math.max((maxMs - minMs) * 0.1, 1000 * 60 * 60 * 24 * 30);
    options.min = new Date(minMs - pad);
    options.max = new Date(maxMs + pad);
    options.start = options.min;
    options.end = options.max;
  }

  const timeline = new vis.Timeline(canvasEl, items, groups, options);

  // Same container-sizing lesson as the map: re-measure after layout settles
  // and on any future resize, rather than trusting the first measurement.
  requestAnimationFrame(() => timeline.redraw());
  setTimeout(() => timeline.redraw(), 300);
  new ResizeObserver(() => timeline.redraw()).observe(canvasEl);
}
