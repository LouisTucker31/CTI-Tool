/**
 * widgets/charts.js — the Threat Activity widget (Chart.js).
 *
 * Two charts: threat records by severity, and by sector. Deliberately not
 * duplicating "threats over time" here since the Threat Timeline widget
 * already covers that ground.
 *
 * Chart.js draws to a <canvas> rather than styling DOM elements with CSS,
 * so colours are set directly in the chart config (reading the dashboard's
 * own CSS variables) rather than fighting a library's default stylesheet —
 * the exact class of bug the map and timeline widgets ran into with their
 * libraries doesn't apply here.
 *
 * Chart.js's `responsive: true` mode sets up its own internal resize
 * handling, so unlike the map/timeline widgets this one doesn't need a
 * manual ResizeObserver workaround — that's Chart.js's job, not ours.
 *
 * The data-shaping logic (buildSeverityDistribution, buildSectorDistribution)
 * stays separate from the actual Chart.js calls, same reasoning as every
 * other widget here: plain data-in/data-out, unit-testable without a browser.
 */

import { dbGetAll } from '../db.js';
import { humanize, SEVERITY_COLOR_VAR } from '../helpers.js';

const SEVERITY_ORDER = ['Critical', 'High', 'Moderate', 'Low', 'Informational'];

// ---------------------------------------------------------------------------
// Pure data-shaping logic — no Chart.js or DOM dependency
// ---------------------------------------------------------------------------

export function buildSeverityDistribution(threatRecords) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((label) => [label, 0]));
  for (const t of threatRecords) {
    if (t.severityLabel && Object.prototype.hasOwnProperty.call(counts, t.severityLabel)) {
      counts[t.severityLabel] += 1;
    }
  }
  return SEVERITY_ORDER.map((label) => ({ label, count: counts[label] }));
}

export function buildSectorDistribution(threatRecords) {
  const counts = new Map();
  for (const t of threatRecords) {
    const sector = t.primarySector || 'Unknown';
    counts.set(sector, (counts.get(sector) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([sector, count]) => ({ sector, count }))
    .sort((a, b) => b.count - a.count);
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export async function renderThreatActivity(container) {
  const threatRecords = await dbGetAll('threatRecords');

  if (threatRecords.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No threat records to chart yet.</p>';
    return;
  }

  const severityDist = buildSeverityDistribution(threatRecords);
  const sectorDist = buildSectorDistribution(threatRecords);

  container.classList.add('tile-body-charts');
  container.innerHTML = `
    <div class="chart-block">
      <p class="tile-intro-note">Threat records by severity</p>
      <div class="chart-canvas-wrap"><canvas></canvas></div>
    </div>
    <div class="chart-block">
      <p class="tile-intro-note">Threat records by sector</p>
      <div class="chart-canvas-wrap"><canvas></canvas></div>
    </div>
  `;

  const textSecondary = cssVar('--text-secondary');
  const hairline = cssVar('--border-hairline');
  const fontBody = "'IBM Plex Sans', system-ui, sans-serif";

  Chart.defaults.color = textSecondary;
  Chart.defaults.font.family = fontBody;
  Chart.defaults.borderColor = hairline;

  const [severityCanvas, sectorCanvas] = container.querySelectorAll('canvas');

  const severityColors = severityDist.map((d) => cssVar(SEVERITY_COLOR_VAR[d.label]) || cssVar('--accent-informational'));

  new Chart(severityCanvas, {
    type: 'bar',
    data: {
      labels: severityDist.map((d) => d.label),
      datasets: [{
        data: severityDist.map((d) => d.count),
        backgroundColor: severityColors,
        borderRadius: 3,
        maxBarThickness: 40,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: hairline } },
      },
    },
  });

  new Chart(sectorCanvas, {
    type: 'bar',
    data: {
      labels: sectorDist.map((d) => humanize(d.sector)),
      datasets: [{
        data: sectorDist.map((d) => d.count),
        backgroundColor: cssVar('--accent-low'),
        borderRadius: 3,
        maxBarThickness: 24,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: hairline } },
        y: { grid: { display: false } },
      },
    },
  });
}
