/**
 * app.js — dashboard shell bootstrap.
 *
 * Renders every widget from a single registry (WIDGETS below) so adding a
 * real widget later is just: build js/widgets/whatever.js, import its
 * render function here, swap it into the registry entry, flip status to
 * 'live'. Nothing else about the shell needs to change.
 *
 * Two widgets are real right now (Key Findings, Recent Reports) — both
 * simple enough to read directly from db.js without needing their own
 * file yet. Once the bigger ones (map, timeline, charts, MITRE matrix)
 * get built, those get their own files under js/widgets/ per the original
 * plan — these two just didn't need it yet.
 *
 * Deliberately NOT built yet (see chat for why): widget layout persistence
 * across reloads, and making the filter bar actually filter anything —
 * both need real widgets to exist first before they're worth wiring up.
 */

import { dbGetAll, bulkWriteRecords } from './db.js';
import { parseReport } from './parser.js';
import { escapeHtml, humanize, severityChip, citeChip, formatDateUK } from './helpers.js';
import { renderWorldMap } from './widgets/map.js';
import { renderThreatTimeline } from './widgets/timeline.js';
import { renderThreatActivity } from './widgets/charts.js';
import { renderCategoryOverview } from './widgets/category-overview.js';

// ---------------------------------------------------------------------------
// Real widget: Key Findings
// ---------------------------------------------------------------------------

async function renderKeyFindings(container) {
  const [threatRecords, incidents] = await Promise.all([
    dbGetAll('threatRecords'),
    dbGetAll('incidents'),
  ]);

  if (threatRecords.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No reports imported yet. Use "Import report" above to load one.</p>';
    return;
  }

  const highestSeverity = threatRecords.reduce((max, record) => {
    if (max === null) return record;
    return (record.severityScore || 0) > (max.severityScore || 0) ? record : max;
  }, null);

  container.innerHTML = `
    <div class="stat-row"><span>Threat records tracked</span><strong>${threatRecords.length}</strong></div>
    <div class="stat-row"><span>Confirmed incidents</span><strong>${incidents.length}</strong></div>
    <div class="stat-row highlight">
      <span>Highest severity</span>
      <span>${severityChip(highestSeverity)} ${citeChip(highestSeverity.sourceCitationIds)}</span>
    </div>
    <p class="tile-footnote">${escapeHtml(highestSeverity.threatTitle)}</p>
  `;
}

// ---------------------------------------------------------------------------
// Real widget: Recent Reports
// ---------------------------------------------------------------------------

async function renderRecentReports(container) {
  const reports = await dbGetAll('reports');

  if (reports.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No reports imported yet.</p>';
    return;
  }

  const sorted = [...reports].sort((a, b) => new Date(b.importDate) - new Date(a.importDate));

  container.innerHTML = sorted.map((report) => `
    <div class="report-row">
      <div class="report-row-title">${escapeHtml(report.reportTitle)}</div>
      <div class="report-row-meta">
        ${escapeHtml(humanize(report.primarySector))} &middot; ${escapeHtml(humanize(report.primaryLocation))}
        &middot; period ending ${escapeHtml(formatDateUK(report.reportingPeriodEnd))}
      </div>
    </div>
  `).join('');
}

// ---------------------------------------------------------------------------
// Real widget: Emerging Threats
// ---------------------------------------------------------------------------

async function renderEmergingThreats(container) {
  const threatRecords = await dbGetAll('threatRecords');
  const emergingThreats = threatRecords.filter((t) => t.trendDirection === 'EMERGING');

  if (emergingThreats.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">Nothing currently marked as an emerging trend.</p>';
    return;
  }

  const threatsHtml = emergingThreats.map((t) => `
    <div class="report-row">
      <div class="report-row-title">${escapeHtml(t.threatTitle)}</div>
      <div class="report-row-meta">${severityChip(t)} ${citeChip(t.sourceCitationIds)} &middot; ${escapeHtml(humanize(t.primarySector))}</div>
    </div>
  `).join('');

  container.innerHTML = `<div class="tile-scroll-list">${threatsHtml}</div>`;
}

// ---------------------------------------------------------------------------
// Real widget: Exercise Planning
// ---------------------------------------------------------------------------

const CONSIDERATION_TYPE_LABELS = {
  SCENARIO_THEME: 'Scenario theme',
  DECISION_POINT: 'Decision point',
  COMMUNICATIONS_CHALLENGE: 'Communications challenge',
  SUPPLY_CHAIN_CHALLENGE: 'Supply chain challenge',
  REGULATORY_CHALLENGE: 'Regulatory challenge',
};

async function renderExercisePlanning(container) {
  const considerations = await dbGetAll('exerciseConsiderations');

  if (considerations.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No exercise-planning considerations stored yet.</p>';
    return;
  }

  const sorted = [...considerations].sort(
    (a, b) => (b.exerciseRelevanceConfidenceScore || 0) - (a.exerciseRelevanceConfidenceScore || 0)
  );

  const categoryCount = new Set(considerations.map((c) => c.considerationType)).size;

  const listHtml = sorted.map((item) => `
    <div class="report-row">
      <div class="report-row-title">${escapeHtml(item.title)}</div>
      <div class="report-row-meta">
        ${escapeHtml(CONSIDERATION_TYPE_LABELS[item.considerationType] || humanize(item.considerationType))}
        &middot; Confidence: ${escapeHtml(item.exerciseRelevanceConfidenceLabel || 'Unknown')}
        ${citeChip(item.sourceCitationIds)}
      </div>
    </div>
  `).join('');

  container.innerHTML = `
    <p class="tile-intro-note">${considerations.length} consideration${considerations.length === 1 ? '' : 's'} across ${categoryCount} categor${categoryCount === 1 ? 'y' : 'ies'}</p>
    <div class="tile-scroll-list">${listHtml}</div>
  `;
}

// ---------------------------------------------------------------------------
// Placeholder widget factory
// ---------------------------------------------------------------------------

function placeholder(note) {
  return async (container) => {
    container.innerHTML = `<p class="tile-placeholder-note">${escapeHtml(note)}</p>`;
  };
}

// ---------------------------------------------------------------------------
// Widget registry — the single source of truth for what's on the dashboard
// ---------------------------------------------------------------------------

const WIDGETS = [
  {
    id: 'world-map', title: 'World Map', span: 'large-tall', status: 'live',
    render: renderWorldMap,
  },
  {
    id: 'threat-score', title: 'Global Threat Score', span: 'medium', status: 'planned',
    render: placeholder('Will calculate one weighted score across the whole dataset — unaffected by dashboard filters — once the scoring rules are built.'),
  },
  {
    id: 'key-findings', title: 'Key Findings', span: 'medium', status: 'live',
    render: renderKeyFindings,
  },
  {
    id: 'timeline', title: 'Threat Timeline', span: 'half-tall', status: 'live',
    render: renderThreatTimeline,
  },
  {
    id: 'activity-chart', title: 'Threat Activity', span: 'half-tall', status: 'live',
    render: renderThreatActivity,
  },
  {
    id: 'category-overview', title: 'Category Overview', span: 'half', status: 'live',
    render: renderCategoryOverview,
  },
  {
    id: 'mitre-overview', title: 'MITRE ATT&CK Overview', span: 'half', status: 'planned',
    render: placeholder('A technique matrix, highlighted by how often each technique shows up across stored threats.'),
  },
  {
    id: 'emerging-threats', title: 'Emerging Threats', span: 'half', status: 'live',
    render: renderEmergingThreats,
  },
  {
    id: 'client-relevance', title: 'Client Relevance', span: 'half', status: 'planned',
    render: placeholder('A filterable view of everything currently tagged to a specific client.'),
  },
  {
    id: 'exercise-planning', title: 'Exercise Planning', span: 'half', status: 'live',
    render: renderExercisePlanning,
  },
  {
    id: 'recent-reports', title: 'Recent Reports', span: 'half', status: 'live',
    render: renderRecentReports,
  },
  {
    id: 'recent-changes', title: 'Recent Data Changes', span: 'full', status: 'planned',
    render: placeholder('A log of imports, edits, merges and deletions, once the audit log is wired up.'),
  },
];

// ---------------------------------------------------------------------------
// Tile chrome (build, collapse/close, restore-from-hidden)
// ---------------------------------------------------------------------------

function buildTile(widget) {
  const tile = document.createElement('section');
  tile.className = `tile span-${widget.span}`;
  tile.dataset.widgetId = widget.id;
  tile.setAttribute('aria-label', widget.title);

  const statusLabel = widget.status === 'live' ? 'LIVE' : 'PLANNED';
  tile.innerHTML = `
    <header class="tile-header">
      <span class="tile-eyebrow">${escapeHtml(widget.title)}
        <span class="tile-status ${widget.status}">${statusLabel}</span>
      </span>
      <span class="tile-controls">
        <button type="button" class="tile-collapse" title="Collapse">–</button>
        <button type="button" class="tile-close" title="Close">×</button>
      </span>
    </header>
    <div class="tile-body">Loading&hellip;</div>
  `;
  return tile;
}

function wireTileControls(tile, grid, hiddenTray) {
  const body = tile.querySelector('.tile-body');
  const collapseBtn = tile.querySelector('.tile-collapse');
  collapseBtn.addEventListener('click', () => {
    const collapsing = !tile.classList.contains('tile-collapsed');
    tile.classList.toggle('tile-collapsed', collapsing);
    body.classList.toggle('collapsed', collapsing);
    collapseBtn.textContent = collapsing ? '+' : '–';
    collapseBtn.title = collapsing ? 'Expand' : 'Collapse';
  });
  tile.querySelector('.tile-close').addEventListener('click', () => {
    tile.remove();
    addHiddenPill(tile.dataset.widgetId, grid, hiddenTray);
  });
}

function addHiddenPill(widgetId, grid, hiddenTray) {
  const widget = WIDGETS.find((w) => w.id === widgetId);
  if (!widget) return;

  hiddenTray.hidden = false;
  const pill = document.createElement('button');
  pill.type = 'button';
  pill.className = 'hidden-pill';
  pill.textContent = `Show "${widget.title}"`;
  pill.addEventListener('click', async () => {
    pill.remove();
    if (hiddenTray.querySelectorAll('.hidden-pill').length === 0) hiddenTray.hidden = true;
    const tile = buildTile(widget);
    grid.appendChild(tile);
    wireTileControls(tile, grid, hiddenTray);
    await renderTileBody(tile, widget);
  });
  hiddenTray.appendChild(pill);
}

async function renderTileBody(tile, widget) {
  const body = tile.querySelector('.tile-body');
  try {
    await widget.render(body);
  } catch (err) {
    body.innerHTML = `<p class="tile-placeholder-note">Couldn't load this widget: ${escapeHtml(err.message)}</p>`;
  }
}

// ---------------------------------------------------------------------------
// Filter bar — options are real, filtering behaviour is not wired up yet
// ---------------------------------------------------------------------------

async function populateFilterOptions() {
  const threatRecords = await dbGetAll('threatRecords');
  const sectors = new Set();
  const clients = new Set();

  threatRecords.forEach((record) => {
    if (record.primarySector) sectors.add(record.primarySector);
    (record.clientTags || []).forEach((client) => clients.add(client));
  });

  const sectorSelect = document.getElementById('filterSector');
  const clientSelect = document.getElementById('filterClient');

  // Clear everything except the first "All ..." default option, so this can
  // run again after a new import without piling up duplicate entries.
  sectorSelect.querySelectorAll('option:not(:first-child)').forEach((opt) => opt.remove());
  clientSelect.querySelectorAll('option:not(:first-child)').forEach((opt) => opt.remove());

  [...sectors].sort().forEach((sector) => {
    const opt = document.createElement('option');
    opt.value = sector;
    opt.textContent = humanize(sector);
    sectorSelect.appendChild(opt);
  });

  [...clients].sort().forEach((client) => {
    const opt = document.createElement('option');
    opt.value = client;
    opt.textContent = humanize(client);
    clientSelect.appendChild(opt);
  });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

async function refreshLiveWidgets() {
  const grid = document.getElementById('widgetGrid');
  for (const widget of WIDGETS) {
    if (widget.status !== 'live') continue;
    const tile = grid.querySelector(`[data-widget-id="${widget.id}"]`);
    if (tile) await renderTileBody(tile, widget);
  }
}

async function handleImportFile(file) {
  const statusEl = document.getElementById('importStatus');
  statusEl.hidden = false;
  statusEl.className = 'import-status';
  statusEl.innerHTML = '<p>Parsing&hellip;</p>';

  try {
    const text = await file.text();
    const { recordsByStore, warnings } = parseReport(text);
    await bulkWriteRecords(recordsByStore);

    const counts = Object.entries(recordsByStore)
      .map(([store, records]) => `${records.length} ${store}`)
      .join(', ');

    statusEl.classList.add('success');
    statusEl.innerHTML = `
      <p class="import-status-title">Imported "${escapeHtml(file.name)}"</p>
      <p>${escapeHtml(counts)}</p>
      ${warnings.length > 0
        ? `<p>${warnings.length} warning(s):</p><ul>${warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join('')}</ul>`
        : '<p>No warnings.</p>'}
    `;

    await refreshLiveWidgets();
    await populateFilterOptions();
  } catch (err) {
    statusEl.classList.add('error');
    statusEl.innerHTML = `<p class="import-status-title">Import failed</p><p>${escapeHtml(err.message)}</p>`;
  }
}

function wireImportControls() {
  const importBtn = document.getElementById('importBtn');
  const importFileInput = document.getElementById('importFileInput');
  importBtn.addEventListener('click', () => importFileInput.click());
  importFileInput.addEventListener('change', () => {
    const file = importFileInput.files[0];
    importFileInput.value = ''; // allow re-selecting the same file again later
    if (file) handleImportFile(file);
  });
}

async function boot() {
  const grid = document.getElementById('widgetGrid');
  const hiddenTray = document.getElementById('hiddenTray');

  wireImportControls();

  for (const widget of WIDGETS) {
    const tile = buildTile(widget);
    grid.appendChild(tile);
    wireTileControls(tile, grid, hiddenTray);
  }

  // Fill in content after every tile shell exists, so the layout appears
  // instantly and each widget's data fills in as it resolves.
  for (const widget of WIDGETS) {
    const tile = grid.querySelector(`[data-widget-id="${widget.id}"]`);
    if (tile) await renderTileBody(tile, widget);
  }

  await populateFilterOptions();
}

boot();