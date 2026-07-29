/**
 * widgets/category-overview.js — the Category Overview widget.
 *
 * A tabbed list covering the four categories that don't have a home
 * anywhere else on the dashboard: Threat Actors, Attack Methods,
 * Vulnerabilities, Malware/Tools. (Exercise considerations, emerging
 * threats, and MITRE mappings already have their own dedicated widgets.)
 *
 * Attack methods are free-text tags on threat records rather than their
 * own stored entity, so that tab is a tally of how often each tag appears
 * rather than a list of individual records like the other three tabs.
 *
 * As with every other widget here, the data-shaping (buildXTab functions)
 * is kept separate from the DOM-rendering, so it can be unit tested
 * without a browser.
 */

import { dbGetAll } from '../db.js';
import { escapeHtml, humanize, severityChip, citeChip } from '../helpers.js';

const TABS = [
  { id: 'actors', label: 'Threat Actors' },
  { id: 'methods', label: 'Attack Methods' },
  { id: 'vulnerabilities', label: 'Vulnerabilities' },
  { id: 'malware', label: 'Malware' },
];

// ---------------------------------------------------------------------------
// Pure data-shaping logic — no DOM dependency
// ---------------------------------------------------------------------------

export function buildActorsTab(threatActors) {
  return [...threatActors].sort(
    (a, b) => (b.attributionConfidenceScore || 0) - (a.attributionConfidenceScore || 0)
  );
}

export function buildAttackMethodsTab(threatRecords) {
  const counts = new Map();
  for (const t of threatRecords) {
    for (const method of t.attackMethods || []) {
      counts.set(method, (counts.get(method) || 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([method, count]) => ({ method, count }))
    .sort((a, b) => b.count - a.count);
}

export function buildVulnerabilitiesTab(vulnerabilities) {
  return [...vulnerabilities].sort((a, b) => (b.severityScore || 0) - (a.severityScore || 0));
}

export function buildMalwareTab(malwareTools) {
  return [...malwareTools].sort((a, b) => (b.confidenceScore || 0) - (a.confidenceScore || 0));
}

// ---------------------------------------------------------------------------
// Row templates
// ---------------------------------------------------------------------------

function actorRow(actor) {
  const aliases = (actor.aliases || []).filter((a) => a && a !== 'Unknown');
  return `
    <div class="report-row">
      <div class="report-row-title">${escapeHtml(actor.actorName || 'Unnamed actor')}</div>
      <div class="report-row-meta">
        ${escapeHtml(humanize(actor.actorType))}
        &middot; Attribution: ${escapeHtml(actor.attributionStatus || 'Unknown')} (${escapeHtml(actor.attributionConfidenceLabel || 'Unknown')})
        ${citeChip(actor.sourceCitationIds)}
      </div>
      ${aliases.length > 0 ? `<div class="report-row-meta">Aliases: ${escapeHtml(aliases.join(', '))}</div>` : ''}
    </div>
  `;
}

function methodRow(entry) {
  return `
    <div class="report-row">
      <div class="report-row-title">${escapeHtml(humanize(entry.method))}</div>
      <div class="report-row-meta">Appears in ${entry.count} threat record${entry.count === 1 ? '' : 's'}</div>
    </div>
  `;
}

function vulnerabilityRow(vuln) {
  return `
    <div class="report-row">
      <div class="report-row-title">${escapeHtml(vuln.cveId || vuln.vulnerabilityName || 'Unnamed vulnerability')}</div>
      <div class="report-row-meta">
        ${severityChip(vuln)} ${escapeHtml(humanize(vuln.exploitationStatus))} ${citeChip(vuln.sourceCitationIds)}
      </div>
      ${vuln.vendor ? `<div class="report-row-meta">${escapeHtml(vuln.vendor)}${vuln.product?.length ? ` &middot; ${escapeHtml(vuln.product.join(', '))}` : ''}</div>` : ''}
    </div>
  `;
}

function malwareRow(item) {
  return `
    <div class="report-row">
      <div class="report-row-title">${escapeHtml(humanize(item.name) || 'Unnamed')}</div>
      <div class="report-row-meta">
        ${escapeHtml(humanize(item.type))}
        &middot; Confidence: ${escapeHtml(item.confidenceLabel || 'Unknown')}
        ${citeChip(item.sourceCitationIds)}
      </div>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

export async function renderCategoryOverview(container) {
  const [threatActors, threatRecords, vulnerabilities, malwareTools] = await Promise.all([
    dbGetAll('threatActors'),
    dbGetAll('threatRecords'),
    dbGetAll('vulnerabilities'),
    dbGetAll('malwareTools'),
  ]);

  const data = {
    actors: buildActorsTab(threatActors),
    methods: buildAttackMethodsTab(threatRecords),
    vulnerabilities: buildVulnerabilitiesTab(vulnerabilities),
    malware: buildMalwareTab(malwareTools),
  };

  const rowRenderers = {
    actors: actorRow,
    methods: methodRow,
    vulnerabilities: vulnerabilityRow,
    malware: malwareRow,
  };

  if (Object.values(data).every((list) => list.length === 0)) {
    container.innerHTML = '<p class="tile-placeholder-note">No actors, methods, vulnerabilities or malware stored yet.</p>';
    return;
  }

  container.innerHTML = `
    <div class="tab-bar">
      ${TABS.map((tab) => `<button type="button" class="tab-btn" data-tab="${tab.id}">${escapeHtml(tab.label)} (${data[tab.id].length})</button>`).join('')}
    </div>
    <div class="tile-scroll-list" id="categoryTabContent"></div>
  `;

  const contentEl = container.querySelector('#categoryTabContent');
  const tabButtons = [...container.querySelectorAll('.tab-btn')];

  function showTab(tabId) {
    tabButtons.forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === tabId));
    const list = data[tabId];
    contentEl.innerHTML = list.length > 0
      ? list.map(rowRenderers[tabId]).join('')
      : '<p class="tile-placeholder-note">Nothing in this category yet.</p>';
  }

  tabButtons.forEach((btn) => btn.addEventListener('click', () => showTab(btn.dataset.tab)));

  const firstNonEmpty = TABS.find((tab) => data[tab.id].length > 0)?.id || TABS[0].id;
  showTab(firstNonEmpty);
}
