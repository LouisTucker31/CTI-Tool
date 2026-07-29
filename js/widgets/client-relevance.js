/**
 * widgets/client-relevance.js — the Client Relevance widget.
 *
 * Client tagging is manual and stored as plain strings on threat records
 * and exercise considerations (see schema.md — clients are never inferred
 * from sector/location/similarity). This widget just surfaces whatever's
 * already been tagged: pick a client, see the threat records and exercise
 * considerations linked to them.
 *
 * The dashboard's own header filter bar isn't wired to widgets yet, so this
 * widget has its own client picker for now — forecasts are left out here
 * too, same reasoning as everywhere else on this dashboard.
 */

import { dbGetAll } from '../db.js';
import { escapeHtml, humanize, severityChip, citeChip } from '../helpers.js';

const CONSIDERATION_TYPE_LABELS = {
  SCENARIO_THEME: 'Scenario theme',
  DECISION_POINT: 'Decision point',
  COMMUNICATIONS_CHALLENGE: 'Communications challenge',
  SUPPLY_CHAIN_CHALLENGE: 'Supply chain challenge',
  REGULATORY_CHALLENGE: 'Regulatory challenge',
};

// ---------------------------------------------------------------------------
// Pure data-shaping logic — no DOM dependency
// ---------------------------------------------------------------------------

export function getDistinctClients(threatRecords, exerciseConsiderations) {
  const clients = new Set();
  threatRecords.forEach((t) => (t.clientTags || []).forEach((c) => clients.add(c)));
  exerciseConsiderations.forEach((e) => (e.clientTags || []).forEach((c) => clients.add(c)));
  return [...clients].sort();
}

export function filterByClient(threatRecords, exerciseConsiderations, client) {
  return {
    threats: threatRecords.filter((t) => (t.clientTags || []).includes(client)),
    considerations: exerciseConsiderations.filter((e) => (e.clientTags || []).includes(client)),
  };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function threatRow(t) {
  return `
    <div class="report-row">
      <div class="report-row-title">${escapeHtml(t.threatTitle)}</div>
      <div class="report-row-meta">${severityChip(t)} ${citeChip(t.sourceCitationIds)} &middot; ${escapeHtml(humanize(t.primarySector))}</div>
    </div>
  `;
}

function considerationRow(item) {
  return `
    <div class="report-row">
      <div class="report-row-title">${escapeHtml(item.title)}</div>
      <div class="report-row-meta">
        ${escapeHtml(CONSIDERATION_TYPE_LABELS[item.considerationType] || humanize(item.considerationType))}
        &middot; Confidence: ${escapeHtml(item.exerciseRelevanceConfidenceLabel || 'Unknown')}
        ${citeChip(item.sourceCitationIds)}
      </div>
    </div>
  `;
}

export async function renderClientRelevance(container) {
  const [threatRecords, exerciseConsiderations] = await Promise.all([
    dbGetAll('threatRecords'),
    dbGetAll('exerciseConsiderations'),
  ]);

  const clients = getDistinctClients(threatRecords, exerciseConsiderations);

  if (clients.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No client tags found in what\'s been imported yet.</p>';
    return;
  }

  container.innerHTML = `
    <div class="widget-select-control">
      <label for="clientRelevancePicker">Client</label>
      <select id="clientRelevancePicker">
        ${clients.map((c) => `<option value="${escapeHtml(c)}">${escapeHtml(humanize(c))}</option>`).join('')}
      </select>
    </div>
    <div class="tile-scroll-list" id="clientRelevanceContent"></div>
  `;

  const contentEl = container.querySelector('#clientRelevanceContent');
  const pickerEl = container.querySelector('#clientRelevancePicker');

  function renderForClient(client) {
    const { threats, considerations } = filterByClient(threatRecords, exerciseConsiderations, client);

    if (threats.length === 0 && considerations.length === 0) {
      contentEl.innerHTML = '<p class="tile-placeholder-note">Nothing tagged to this client yet.</p>';
      return;
    }

    contentEl.innerHTML = `
      ${threats.length > 0 ? `<p class="widget-section-label">Threat records (${threats.length})</p>${threats.map(threatRow).join('')}` : ''}
      ${considerations.length > 0 ? `<p class="widget-section-label">Exercise considerations (${considerations.length})</p>${considerations.map(considerationRow).join('')}` : ''}
    `;
  }

  renderForClient(pickerEl.value);
  pickerEl.addEventListener('change', () => renderForClient(pickerEl.value));
}
