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

// ---------------------------------------------------------------------------
// Small display helpers
// ---------------------------------------------------------------------------

const SEVERITY_KEY_BY_LABEL = {
  Critical: 'critical',
  High: 'high',
  Moderate: 'moderate',
  Low: 'low',
  Informational: 'informational',
};

function severityChip({ severityLabel, confidenceLabel }) {
  const key = SEVERITY_KEY_BY_LABEL[severityLabel] || 'informational';
  const solid = confidenceLabel === 'Very High' ? ' confidence-solid' : '';
  const title = `Confidence: ${confidenceLabel || 'Unknown'}`;
  return `<span class="severity-chip severity-${key}${solid}" title="${title}">${severityLabel || 'Unrated'}</span>`;
}

function citeChip(citationIds) {
  const count = (citationIds || []).length;
  if (count === 0) return '';
  return `<span class="cite-chip" title="${count} source${count === 1 ? '' : 's'} cited">[${count} source${count === 1 ? '' : 's'}]</span>`;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}

/** DEFENCE_SUPPLY_CHAIN -> "Defence Supply Chain". Display-only — never touches stored data. */
function humanize(token) {
  if (!token) return token;
  return token
    .split('_')
    .join(' ')
    .toLowerCase()
    .replace(/(^|[\s-])([a-z])/g, (match, sep, letter) => sep + letter.toUpperCase());
}

// ---------------------------------------------------------------------------
// Real widget: Key Findings
// ---------------------------------------------------------------------------

async function renderKeyFindings(container) {
  const [threatRecords, incidents, forecasts] = await Promise.all([
    dbGetAll('threatRecords'),
    dbGetAll('incidents'),
    dbGetAll('forecasts'),
  ]);

  if (threatRecords.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No reports imported yet. Use "Import report" above to load one.</p>';
    return;
  }

  const now = new Date();
  const activeForecasts = forecasts.filter(
    (f) => !f.forecastExpiryDate || new Date(f.forecastExpiryDate) > now
  );

  const highestSeverity = threatRecords.reduce((max, record) => {
    if (max === null) return record;
    return (record.severityScore || 0) > (max.severityScore || 0) ? record : max;
  }, null);

  container.innerHTML = `
    <div class="stat-row"><span>Threat records tracked</span><strong>${threatRecords.length}</strong></div>
    <div class="stat-row"><span>Confirmed incidents</span><strong>${incidents.length}</strong></div>
    <div class="stat-row"><span>Active forecasts</span><strong>${activeForecasts.length} of ${forecasts.length}</strong></div>
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
        &middot; period ending ${escapeHtml(report.reportingPeriodEnd || 'Unknown')}
      </div>
    </div>
  `).join('');
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
    id: 'world-map', title: 'World Map', span: 'large-tall', status: 'planned',
    render: placeholder('Will plot affected and threat-actor locations on an interactive map, sized by incident count, once the mapping widget is built (Leaflet).'),
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
    id: 'timeline', title: 'Threat Timeline', span: 'full', status: 'planned',
    render: placeholder('Will lay out incidents, campaigns and forecasts chronologically across every imported report.'),
  },
  {
    id: 'activity-chart', title: 'Threat Activity', span: 'half', status: 'planned',
    render: placeholder('Charts of threats and incidents over time, by sector, actor and attack technique.'),
  },
  {
    id: 'category-overview', title: 'Category Overview', span: 'half', status: 'planned',
    render: placeholder('A tabbed view across actors, attack methods, sectors, vulnerabilities and more.'),
  },
  {
    id: 'mitre-overview', title: 'MITRE ATT&CK Overview', span: 'half', status: 'planned',
    render: placeholder('A technique matrix, highlighted by how often each technique shows up across stored threats.'),
  },
  {
    id: 'client-relevance', title: 'Client Relevance', span: 'half', status: 'planned',
    render: placeholder('A filterable view of everything currently tagged to a specific client.'),
  },
  {
    id: 'emerging-threats', title: 'Emerging Threats', span: 'third', status: 'planned',
    render: placeholder('Threats and forecasts currently marked as emerging or upcoming.'),
  },
  {
    id: 'exercise-planning', title: 'Exercise Planning', span: 'third', status: 'planned',
    render: placeholder('Scenario themes, decision points and supporting evidence pulled from exercise considerations.'),
  },
  {
    id: 'recent-reports', title: 'Recent Reports', span: 'third', status: 'live',
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
  tile.querySelector('.tile-collapse').addEventListener('click', () => {
    body.classList.toggle('collapsed');
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