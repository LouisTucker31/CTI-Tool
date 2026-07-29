/**
 * threat-detail.js — the shared "click a threat title, see everything about
 * it" modal, usable from any widget.
 *
 * Rather than each widget building its own detail view, every clickable
 * title just needs a `data-threat-id="..."` attribute and the
 * `clickable-title` class — a single delegated click listener (wired once,
 * in wireDetailModal) catches all of them regardless of which widget or
 * library rendered the element, including things inside a Leaflet popup.
 *
 * Every child entity (locations, incidents, actors, vulnerabilities,
 * malware, MITRE mappings, exercise considerations) is looked up via the
 * parentThreatId index already defined in db.js — no new indexes needed.
 */

import { dbGet, dbGetAllByIndex } from './db.js';
import { escapeHtml, humanize, severityChip, citeChip, formatDateUK } from './helpers.js';

function detailSection(title, itemsHtml) {
  if (!itemsHtml) return '';
  return `<div class="detail-section"><p class="widget-section-label">${escapeHtml(title)}</p>${itemsHtml}</div>`;
}

async function fetchCitations(citationIds) {
  const results = await Promise.all((citationIds || []).map((id) => dbGet('citations', id).catch(() => null)));
  return results.filter(Boolean);
}

export async function showThreatDetail(threatId) {
  const backdrop = document.getElementById('detailModalBackdrop');
  const contentEl = document.getElementById('detailModalContent');
  contentEl.innerHTML = '<p class="tile-placeholder-note">Loading&hellip;</p>';
  backdrop.hidden = false;

  const [threat, locations, incidents, actors, vulnerabilities, malware, mappings, considerations] = await Promise.all([
    dbGet('threatRecords', threatId),
    dbGetAllByIndex('locations', 'parentThreatId', threatId),
    dbGetAllByIndex('incidents', 'parentThreatId', threatId),
    dbGetAllByIndex('threatActors', 'parentThreatId', threatId),
    dbGetAllByIndex('vulnerabilities', 'parentThreatId', threatId),
    dbGetAllByIndex('malwareTools', 'parentThreatId', threatId),
    dbGetAllByIndex('mitreMappings', 'parentThreatId', threatId),
    dbGetAllByIndex('exerciseConsiderations', 'parentThreatId', threatId),
  ]);

  if (!threat) {
    contentEl.innerHTML = '<p class="tile-placeholder-note">Couldn\'t find that threat record — it may have been part of a report that was later removed.</p>';
    return;
  }

  const citations = await fetchCitations(threat.sourceCitationIds);

  const datesLine = [
    threat.firstObservedDate ? `First observed ${formatDateUK(threat.firstObservedDate)}` : null,
    threat.lastObservedDate ? `Last observed ${formatDateUK(threat.lastObservedDate)}` : null,
  ].filter(Boolean).join(' &middot; ');

  contentEl.innerHTML = `
    <p class="detail-title">${escapeHtml(threat.threatTitle)}</p>
    <div class="detail-meta">
      ${severityChip(threat)}
      <span class="detail-status">${escapeHtml(humanize(threat.threatStatus))} &middot; ${escapeHtml(humanize(threat.trendDirection))}</span>
      ${citeChip(threat.sourceCitationIds)}
    </div>
    ${datesLine ? `<p class="detail-dates">${datesLine}</p>` : ''}
    <p class="detail-description">${escapeHtml(threat.fullDescription || threat.oneLineSummary || '')}</p>

    ${detailSection('Locations', locations.map((l) => `
      <div class="report-row">
        <div class="report-row-title">${escapeHtml(l.city && l.city !== 'Unknown' ? humanize(l.city) : (humanize(l.country) || 'Unknown location'))}</div>
        <div class="report-row-meta">${escapeHtml(humanize(l.locationType))}</div>
      </div>
    `).join(''))}

    ${detailSection('Incidents', incidents.map((i) => `
      <div class="report-row">
        <div class="report-row-title">${escapeHtml(i.incidentTitle)}</div>
        <div class="report-row-meta">${escapeHtml(i.affectedOrganisation ? humanize(i.affectedOrganisation) : '')} &middot; ${escapeHtml(formatDateUK(i.incidentDate))}</div>
      </div>
    `).join(''))}

    ${detailSection('Threat Actors', actors.map((a) => `
      <div class="report-row">
        <div class="report-row-title">${escapeHtml(a.actorName)}</div>
        <div class="report-row-meta">${escapeHtml(humanize(a.actorType))} &middot; Attribution: ${escapeHtml(humanize(a.attributionStatus))}</div>
      </div>
    `).join(''))}

    ${detailSection('Vulnerabilities', vulnerabilities.map((v) => `
      <div class="report-row">
        <div class="report-row-title">${escapeHtml(v.cveId || v.vulnerabilityName || 'Unnamed vulnerability')}</div>
        <div class="report-row-meta">${severityChip(v)} ${escapeHtml(humanize(v.exploitationStatus))}</div>
      </div>
    `).join(''))}

    ${detailSection('Malware & Tools', malware.map((m) => `
      <div class="report-row">
        <div class="report-row-title">${escapeHtml(humanize(m.name))}</div>
        <div class="report-row-meta">${escapeHtml(humanize(m.type))}</div>
      </div>
    `).join(''))}

    ${detailSection('MITRE ATT&CK Techniques', mappings.map((m) => `
      <div class="report-row">
        <div class="report-row-title">${escapeHtml(m.techniqueId)} &mdash; ${escapeHtml(m.techniqueName)}</div>
        <div class="report-row-meta">${escapeHtml((m.tactic || []).map((t) => humanize(t)).join(', '))} &middot; ${escapeHtml(humanize(m.mappingType))}</div>
      </div>
    `).join(''))}

    ${detailSection('Exercise Considerations', considerations.map((c) => `
      <div class="report-row">
        <div class="report-row-title">${escapeHtml(c.title)}</div>
        <div class="report-row-meta">${escapeHtml(humanize(c.considerationType))}</div>
      </div>
    `).join(''))}

    ${detailSection('Sources', citations.map((c) => `
      <div class="report-row">
        <div class="report-row-title">${escapeHtml(c.sourceTitle)}</div>
        <div class="report-row-meta">${escapeHtml(c.sourcePublisher)} &middot; ${escapeHtml(formatDateUK(c.sourcePublicationDate))}</div>
      </div>
    `).join(''))}
  `;
}

/** Call once, from boot(). Sets up the modal's close controls and the single delegated click listener that opens it from anywhere. */
export function wireDetailModal() {
  const backdrop = document.getElementById('detailModalBackdrop');
  const closeBtn = document.getElementById('detailModalClose');

  function hide() {
    backdrop.hidden = true;
  }

  closeBtn.addEventListener('click', hide);
  backdrop.addEventListener('click', (e) => {
    if (e.target === backdrop) hide(); // clicked the dark overlay itself, not the panel
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !backdrop.hidden) hide();
  });

  document.body.addEventListener('click', (e) => {
    const trigger = e.target.closest('[data-threat-id]');
    if (trigger) showThreatDetail(trigger.dataset.threatId);
  });
}
