/**
 * widgets/client-relevance.js — the Client Relevance widget.
 *
 * Two separate ways a threat can be "relevant" to a client, kept visually
 * distinct rather than merged into one list:
 *
 *   1. Exact — the report explicitly tagged this client by name
 *      (clientTags). Same as this widget always did.
 *   2. Possibly relevant — the client's own sector or location overlaps
 *      with the threat's, but the report never actually named this
 *      client. This is a suggestion to go and check, not a confirmed
 *      match — sector/location overlap alone isn't real evidence of
 *      relevance (the exact same principle the report-generation prompt
 *      itself is built around).
 *
 * Clients are created and stored right here rather than requiring a
 * separate management screen — "name, sector, location" is deliberately
 * the entire client record, per the brief: not too detailed.
 */

import { dbGetAll, dbPut, dbDelete } from '../db.js';
import { getFilteredThreatRecords, getFilteredChildRecords } from '../filters.js';
import { escapeHtml, humanize, severityChip, citeChip } from '../helpers.js';
import { COUNTRY_CENTROIDS } from './map.js';
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
  const reasonLabels = { sector: 'shared sector', location: 'shared location' };
  return `
    <div class="report-row">
      <div class="report-row-title clickable-title" data-threat-id="${escapeHtml(threat.threatId)}">${escapeHtml(threat.threatTitle)}</div>
      <div class="report-row-meta">${severityChip(threat)} &middot; ${escapeHtml(reasons.map((r) => reasonLabels[r]).join(', '))}</div>
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
  const [clients, threatRecords, exerciseConsiderations, locations, allThreatRecords] = await Promise.all([
    dbGetAll('clients'),
    getFilteredThreatRecords({ ignoreClient: true }),
    getFilteredChildRecords('exerciseConsiderations', 'parentThreatId', { ignoreClient: true }),
    dbGetAll('locations'),
    dbGetAll('threatRecords'), // unfiltered — sector suggestions should cover everything imported, not just the current filter
  ]);

  const locationsByThreatId = new Map();
  for (const loc of locations) {
    if (!locationsByThreatId.has(loc.parentThreatId)) locationsByThreatId.set(loc.parentThreatId, []);
    locationsByThreatId.get(loc.parentThreatId).push(loc);
  }

  const knownSectors = [...new Set(allThreatRecords.map((t) => t.primarySector).filter((s) => s && s !== 'ALL'))].sort();
  const knownCountries = Object.keys(COUNTRY_CENTROIDS).sort();

  container.innerHTML = `
    <datalist id="clientSectorOptions">${knownSectors.map((s) => `<option value="${escapeHtml(s)}">`).join('')}</datalist>
    <datalist id="clientLocationOptions">${knownCountries.map((c) => `<option value="${escapeHtml(c)}">`).join('')}</datalist>

    <div class="widget-select-control" id="clientPickerRow">
      <label for="clientPicker">Client</label>
      <select id="clientPicker">
        ${clients.map((c) => `<option value="${escapeHtml(c.clientId)}">${escapeHtml(c.name)}</option>`).join('')}
      </select>
      <button type="button" class="btn" id="addClientBtn">Add client</button>
      ${clients.length > 0 ? '<button type="button" class="report-delete-btn" id="deleteClientBtn">Delete</button>' : ''}
    </div>

    <form id="addClientForm" class="add-client-form" hidden>
      <input type="text" id="newClientName" placeholder="Client name" required>
      <input type="text" id="newClientSector" placeholder="Sector (e.g. Government)" list="clientSectorOptions">
      <input type="text" id="newClientLocation" placeholder="Location (e.g. United Kingdom)" list="clientLocationOptions">
      <div class="add-client-form-actions">
        <button type="submit" class="btn">Save</button>
        <button type="button" class="btn" id="cancelAddClientBtn">Cancel</button>
      </div>
    </form>

    <div class="tile-scroll-list" id="clientRelevanceContent"></div>
  `;

  const contentEl = container.querySelector('#clientRelevanceContent');
  const pickerRowEl = container.querySelector('#clientPickerRow');
  const pickerEl = container.querySelector('#clientPicker');
  const formEl = container.querySelector('#addClientForm');
  const addBtn = container.querySelector('#addClientBtn');
  const cancelBtn = container.querySelector('#cancelAddClientBtn');
  const deleteBtn = container.querySelector('#deleteClientBtn');

  if (clients.length === 0) {
    pickerRowEl.hidden = true;
    contentEl.innerHTML = '';
  }

  function showForm() {
    pickerRowEl.hidden = true;
    formEl.hidden = false;
    container.querySelector('#newClientName').focus();
  }
  function hideForm() {
    formEl.hidden = true;
    if (clients.length > 0) pickerRowEl.hidden = false;
  }

  if (clients.length === 0) showForm();

  addBtn.addEventListener('click', showForm);
  cancelBtn.addEventListener('click', hideForm);

  formEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = container.querySelector('#newClientName').value.trim();
    if (!name) return;
    const sector = container.querySelector('#newClientSector').value.trim().toUpperCase().replace(/[\s-]+/g, '_');
    const location = container.querySelector('#newClientLocation').value.trim().toUpperCase().replace(/[\s-]+/g, '_');

    await dbPut('clients', {
      clientId: `CLIENT-${Date.now()}`,
      name,
      sector: sector || null,
      location: location || null,
      dateAdded: new Date().toISOString(),
    });

    await renderClientRelevance(container);
  });

  if (deleteBtn) {
    deleteBtn.addEventListener('click', async () => {
      const client = clients.find((c) => c.clientId === pickerEl.value);
      if (!client) return;
      if (!confirm(`Remove "${client.name}" from the client list? This only removes the client entry — nothing in your imported reports changes.`)) return;
      await dbDelete('clients', client.clientId);
      await renderClientRelevance(container);
    });
  }

  function renderForClient(clientId) {
    const client = clients.find((c) => c.clientId === clientId);
    if (!client) {
      contentEl.innerHTML = '';
      return;
    }

    const exactThreats = findExactlyTaggedThreats(client, threatRecords);
    const exactConsiderations = findExactlyTaggedConsiderations(client, exerciseConsiderations);
    const exactThreatIds = new Set(exactThreats.map((t) => t.threatId));
    const possibleMatches = findPossiblyRelevantThreats(client, threatRecords, locationsByThreatId, exactThreatIds);

    const detailLine = [
      client.sector ? `Sector: ${humanize(client.sector)}` : null,
      client.location ? `Location: ${humanize(client.location)}` : null,
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
      ${possibleMatches.length > 0 ? `<p class="widget-section-label">Possibly relevant — shared sector/location, not explicitly tagged (${possibleMatches.length})</p>${possibleMatches.map(possiblyRelevantRow).join('')}` : ''}
    `;
  }

  if (clients.length > 0) {
    renderForClient(pickerEl.value);
    pickerEl.addEventListener('change', () => renderForClient(pickerEl.value));
  }
}
