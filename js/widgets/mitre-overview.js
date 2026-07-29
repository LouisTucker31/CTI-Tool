/**
 * widgets/mitre-overview.js — the MITRE ATT&CK Overview widget.
 *
 * Two tabs: Techniques (ranked by how often each shows up across stored
 * threats, with an explicit-vs-inferred breakdown) and Tactics (which
 * higher-level MITRE tactic categories are most represented).
 *
 * A single technique can belong to more than one tactic (TACTIC is a
 * pipe-separated field in the source data), so the tactic tally counts
 * each tactic a mapping touches, not just the first one.
 *
 * Reuses the same tab-bar / tile-scroll-list / report-row CSS already
 * built for Category Overview — no new styling needed for this widget.
 */

import { dbGetAll } from '../db.js';
import { escapeHtml, humanize, citeChip } from '../helpers.js';

const TABS = [
  { id: 'techniques', label: 'Techniques' },
  { id: 'tactics', label: 'Tactics' },
];

// ---------------------------------------------------------------------------
// Pure data-shaping logic — no DOM dependency
// ---------------------------------------------------------------------------

export function buildTechniqueDistribution(mitreMappings) {
  const byTechnique = new Map();

  for (const m of mitreMappings) {
    if (!byTechnique.has(m.techniqueId)) {
      byTechnique.set(m.techniqueId, {
        techniqueId: m.techniqueId,
        techniqueName: m.techniqueName,
        tactics: new Set(),
        count: 0,
        explicitCount: 0,
        inferredCount: 0,
        sourceCitationIds: new Set(),
      });
    }
    const entry = byTechnique.get(m.techniqueId);
    entry.count += 1;
    if (m.mappingType === 'EXPLICIT') entry.explicitCount += 1;
    if (m.mappingType === 'INFERRED') entry.inferredCount += 1;
    (m.tactic || []).forEach((t) => entry.tactics.add(t));
    (m.sourceCitationIds || []).forEach((id) => entry.sourceCitationIds.add(id));
  }

  return [...byTechnique.values()]
    .map((e) => ({ ...e, tactics: [...e.tactics], sourceCitationIds: [...e.sourceCitationIds] }))
    .sort((a, b) => b.count - a.count);
}

export function buildTacticDistribution(mitreMappings) {
  const counts = new Map();
  for (const m of mitreMappings) {
    for (const tactic of m.tactic || []) {
      counts.set(tactic, (counts.get(tactic) || 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([tactic, count]) => ({ tactic, count }))
    .sort((a, b) => b.count - a.count);
}

// ---------------------------------------------------------------------------
// Row templates
// ---------------------------------------------------------------------------

function techniqueRow(t) {
  const breakdown = [];
  if (t.explicitCount > 0) breakdown.push(`${t.explicitCount} explicit`);
  if (t.inferredCount > 0) breakdown.push(`${t.inferredCount} inferred`);

  return `
    <div class="report-row">
      <div class="report-row-title">${escapeHtml(t.techniqueId)} &mdash; ${escapeHtml(t.techniqueName)}</div>
      <div class="report-row-meta">
        ${escapeHtml(t.tactics.map((tac) => humanize(tac)).join(', '))}
        &middot; ${escapeHtml(breakdown.join(', '))}
        ${citeChip(t.sourceCitationIds)}
      </div>
    </div>
  `;
}

function tacticRow(entry) {
  return `
    <div class="report-row">
      <div class="report-row-title">${escapeHtml(humanize(entry.tactic))}</div>
      <div class="report-row-meta">${entry.count} technique occurrence${entry.count === 1 ? '' : 's'}</div>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

export async function renderMitreOverview(container) {
  const mitreMappings = await dbGetAll('mitreMappings');

  if (mitreMappings.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No MITRE ATT&amp;CK mappings stored yet.</p>';
    return;
  }

  const data = {
    techniques: buildTechniqueDistribution(mitreMappings),
    tactics: buildTacticDistribution(mitreMappings),
  };
  const rowRenderers = { techniques: techniqueRow, tactics: tacticRow };

  container.innerHTML = `
    <div class="tab-bar">
      ${TABS.map((tab) => `<button type="button" class="tab-btn" data-tab="${tab.id}">${escapeHtml(tab.label)} (${data[tab.id].length})</button>`).join('')}
    </div>
    <div class="tile-scroll-list" id="mitreTabContent"></div>
  `;

  const contentEl = container.querySelector('#mitreTabContent');
  const tabButtons = [...container.querySelectorAll('.tab-btn')];

  function showTab(tabId) {
    tabButtons.forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === tabId));
    contentEl.innerHTML = data[tabId].map(rowRenderers[tabId]).join('');
  }

  tabButtons.forEach((btn) => btn.addEventListener('click', () => showTab(btn.dataset.tab)));
  showTab('techniques');
}
