/**
 * widgets/client-relevance.js — the Client Relevance widget.
 *
 * Two separate ways a threat can be "relevant" to a client, kept visually
 * distinct rather than merged into one list:
 *
 *   1. Exact — the report explicitly tagged this client by name
 *      (clientTags). Same as this widget always did.
 *   2. Possibly relevant — the client's sector, location, a named
 *      technology/system, or a named supplier overlaps with the threat's,
 *      but the report never actually named this client. A suggestion to
 *      go and check, not a confirmed match.
 *
 * Adding a client happens through a modal (#addClientModalBackdrop, wired
 * once in app.js, same pattern as the threat-detail and settings modals)
 * rather than an inline form in this widget — this widget only triggers
 * it open and refreshes once a client's been saved. Only the name is
 * required; sector, location, technologies and suppliers are all optional
 * — each one just adds another possible match signal, per the brief.
 */

import { dbGetAll, dbDelete } from '../db.js';
import { getFilteredThreatRecords, getFilteredChildRecords } from '../filters.js';
import { escapeHtml, humanize, severityChip, citeChip } from '../helpers.js';
import {
  findExactlyTaggedThreats, findExactlyTaggedConsiderations, findPossiblyRelevantThreats,
} from '../client-matching.js';

const CONSIDERATION_TYPE_LABELS = {
  SCENARIO_THEME: 'Scenario theme',
  DECISION_POINT: 'Decision point',
  COMMUNICATIONS_CHALLENGE: 'Communications challenge',
  SUPPLY_CHAIN_CHALLENGE: 'Supply chain challenge',
  REGULATORY_CHALLENGE: 'Regulatory challenge',
};

const REASON_LABELS = {
  sector: 'shared sector',
  location: 'shared location',
  technology: 'shared technology/system',
  supplier: 'shared supplier',
};

// ---------------------------------------------------------------------------
// Row templates
// ---------------------------------------------------------------------------

function threatRow(t) {
  return `
    <div class="report-row">
      <div class="report-row-title clickable-title" data-threat-id="${escapeHtml(t.threatId)}">${escapeHtml(t.threatTitle)}</div>
      <div class="report-row-meta">${severityChip(t)} ${citeChip(t.sourceCitationIds)} &middot; ${escapeHtml(humanize(t.primarySector))}</div>
    </div>
  `;
}

function possiblyRelevantRow({ threat, reasons }) {
  return `
    <div class="report-row">
      <div class="report-row-title clickable-title" data-threat-id="${escapeHtml(threat.threatId)}">${escapeHtml(threat.threatTitle)}</div>
      <div class="report-row-meta">${severityChip(threat)} &middot; ${escapeHtml(reasons.map((r) => REASON_LABELS[r]).join(', '))}</div>
    </div>
  `;
}

function considerationRow(item) {
  return `
    <div class="report-row">
      <div class="report-row-title clickable-title" data-threat-id="${escapeHtml(item.parentThreatId)}">${escapeHtml(item.title)}</div>
      <div class="report-row-meta">
        ${escapeHtml(CONSIDERATION_TYPE_LABELS[item.considerationType] || humanize(item.considerationType))}
        &middot; Confidence: ${escapeHtml(item.exerciseRelevanceConfidenceLabel || 'Unknown')}
        ${citeChip(item.sourceCitationIds)}
      </div>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

export async function renderClientRelevance(container) {
  const [clients, threatRecords, exerciseConsiderations, vulnerabilities] = await Promise.all([
    dbGetAll('clients'),
    getFilteredThreatRecords({ ignoreClient: true }),
    getFilteredChildRecords('exerciseConsiderations', 'parentThreatId', { ignoreClient: true }),
    dbGetAll('vulnerabilities'),
  ]);

  const vulnerabilitiesByThreatId = new Map();
  for (const v of vulnerabilities) {
    if (!vulnerabilitiesByThreatId.has(v.parentThreatId)) vulnerabilitiesByThreatId.set(v.parentThreatId, []);
    vulnerabilitiesByThreatId.get(v.parentThreatId).push(v);
  }

  if (clients.length === 0) {
    container.innerHTML = `
      <p class="tile-placeholder-note">No clients added yet.</p>
      <div class="widget-select-control">
        <button type="button" class="btn" id="addClientBtn">Add client</button>
      </div>
    `;
    container.querySelector('#addClientBtn').addEventListener('click', () => openAddClientModal());
    return;
  }

  container.innerHTML = `
    <div class="widget-select-control">
      <label for="clientPicker">Client</label>
      <select id="clientPicker">
        ${clients.map((c) => `<option value="${escapeHtml(c.clientId)}">${escapeHtml(c.name)}</option>`).join('')}
      </select>
      <button type="button" class="btn" id="addClientBtn">Add client</button>
      <button type="button" class="btn" id="editClientBtn">Edit</button>
      <button type="button" class="report-delete-btn" id="deleteClientBtn">Delete</button>
    </div>
    <div class="tile-scroll-list" id="clientRelevanceContent"></div>
  `;

  const contentEl = container.querySelector('#clientRelevanceContent');
  const pickerEl = container.querySelector('#clientPicker');

  container.querySelector('#addClientBtn').addEventListener('click', () => openAddClientModal());

  container.querySelector('#editClientBtn').addEventListener('click', () => {
    const client = clients.find((c) => c.clientId === pickerEl.value);
    if (client) openAddClientModal(client);
  });

  container.querySelector('#deleteClientBtn').addEventListener('click', async () => {
    const client = clients.find((c) => c.clientId === pickerEl.value);
    if (!client) return;
    if (!confirm(`Remove "${client.name}" from the client list? This only removes the client entry — nothing in your imported reports changes.`)) return;
    await dbDelete('clients', client.clientId);
    await renderClientRelevance(container);
  });

  function renderForClient(clientId) {
    const client = clients.find((c) => c.clientId === clientId);
    if (!client) {
      contentEl.innerHTML = '';
      return;
    }

    const exactThreats = findExactlyTaggedThreats(client, threatRecords);
    const exactConsiderations = findExactlyTaggedConsiderations(client, exerciseConsiderations);
    const exactThreatIds = new Set(exactThreats.map((t) => t.threatId));
    const possibleMatches = findPossiblyRelevantThreats(
      client, threatRecords, vulnerabilitiesByThreatId, exactThreatIds
    );

    const detailLine = [
      client.sector ? `Sector: ${humanize(client.sector)}` : null,
      client.location ? `Location: ${humanize(client.location)}` : null,
      client.technologies ? `Technologies: ${escapeHtml(client.technologies)}` : null,
      client.suppliers ? `Suppliers: ${escapeHtml(client.suppliers)}` : null,
    ].filter(Boolean).join(' &middot; ');

    if (exactThreats.length === 0 && exactConsiderations.length === 0 && possibleMatches.length === 0) {
      contentEl.innerHTML = `
        ${detailLine ? `<p class="tile-intro-note">${detailLine}</p>` : ''}
        <p class="tile-placeholder-note">Nothing tagged or matching this client yet.</p>
      `;
      return;
    }

    contentEl.innerHTML = `
      ${detailLine ? `<p class="tile-intro-note">${detailLine}</p>` : ''}
      ${exactThreats.length > 0 ? `<p class="widget-section-label">Threat records (${exactThreats.length})</p>${exactThreats.map(threatRow).join('')}` : ''}
      ${exactConsiderations.length > 0 ? `<p class="widget-section-label">Exercise considerations (${exactConsiderations.length})</p>${exactConsiderations.map(considerationRow).join('')}` : ''}
      ${possibleMatches.length > 0 ? `<p class="widget-section-label">Possibly relevant — not explicitly tagged (${possibleMatches.length})</p>${possibleMatches.map(possiblyRelevantRow).join('')}` : ''}
    `;
  }

  renderForClient(pickerEl.value);
  pickerEl.addEventListener('change', () => renderForClient(pickerEl.value));
}

function openAddClientModal(existingClient) {
  if (window.__openAddClientModal) {
    window.__openAddClientModal(existingClient);
  } else {
    document.getElementById('addClientModalBackdrop').hidden = false;
  }
}
