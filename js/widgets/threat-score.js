/**
 * widgets/threat-score.js — the Global Threat Score widget.
 *
 * One weighted score across the whole dataset, independent of the
 * dashboard's filter bar (per the concept doc: filtering changes what you
 * see, not the underlying score).
 *
 * What feeds it, deliberately kept small so the result stays explainable:
 *   - Severity, scaled down by how confident the report was in that
 *     assessment (a Critical rating we're only Low-confidence about counts
 *     for much less than a Critical rating rated Very High confidence).
 *   - A small bump for threats whose trend is INCREASING/ESCALATING, and a
 *     small reduction for DECLINING ones.
 *   - A small bump per confirmed incident tied to a still-active threat.
 *   - RESOLVED and HISTORICAL threat records are excluded entirely — a
 *     closed matter shouldn't keep inflating the current score.
 *
 * The raw sum is squashed into a 0-100 range with diminishing returns
 * (approaches but never reaches 100) rather than a hard cap, so score
 * growth feels smooth rather than clipped. The constant (K=12) was picked
 * by testing against the real sample report — a single, genuinely serious
 * state-sponsored-threat report lands at ~74 (High), leaving real headroom
 * for the score to climb further as more evidence accumulates across
 * imports, rather than one report alone maxing it out.
 *
 * Forecasts are not part of this at all — consistent with the rest of the
 * dashboard, this is about confirmed/active threats, not predictions.
 */

import { dbGetAll } from '../db.js';
import { escapeHtml } from '../helpers.js';

const EXCLUDED_STATUSES = new Set(['RESOLVED', 'HISTORICAL']);
const INCREASING_TRENDS = new Set(['INCREASING', 'ESCALATING']);
const SCORE_CURVE_K = 12;

const SCORE_BAND_CLASS = {
  Low: 'score-band-low',
  Guarded: 'score-band-guarded',
  Elevated: 'score-band-elevated',
  High: 'score-band-high',
  Critical: 'score-band-critical',
};

function scoreLabel(score) {
  if (score >= 81) return 'Critical';
  if (score >= 61) return 'High';
  if (score >= 41) return 'Elevated';
  if (score >= 21) return 'Guarded';
  return 'Low';
}

// ---------------------------------------------------------------------------
// Pure scoring logic — no DOM dependency, fully unit-testable
// ---------------------------------------------------------------------------

export function computeGlobalThreatScore(threatRecords, incidents) {
  const activeThreats = threatRecords.filter((t) => !EXCLUDED_STATUSES.has(t.threatStatus));

  let rawSum = 0;
  let increasingCount = 0;
  let highOrAboveCount = 0;

  for (const t of activeThreats) {
    const confidenceRatio = (t.confidenceScore || 1) / 4;
    let trendAdjustment = 0;
    if (INCREASING_TRENDS.has(t.trendDirection)) {
      trendAdjustment = 0.5;
      increasingCount += 1;
    } else if (t.trendDirection === 'DECLINING') {
      trendAdjustment = -0.3;
    }
    rawSum += Math.max(0, (t.severityScore || 0) * confidenceRatio + trendAdjustment);
    if ((t.severityScore || 0) >= 4) highOrAboveCount += 1;
  }

  const activeThreatIds = new Set(activeThreats.map((t) => t.threatId));
  const relevantIncidentCount = incidents.filter((inc) => activeThreatIds.has(inc.parentThreatId)).length;
  rawSum += relevantIncidentCount * 0.5;

  const score = Math.round(100 * (1 - Math.exp(-rawSum / SCORE_CURVE_K)));
  const label = scoreLabel(score);

  const factors = [];
  if (activeThreats.length > 0) {
    factors.push(`${activeThreats.length} active threat record${activeThreats.length === 1 ? '' : 's'}`);
  }
  if (highOrAboveCount > 0) {
    factors.push(`${highOrAboveCount} rated High or Critical severity`);
  }
  if (increasingCount > 0) {
    factors.push(`${increasingCount} showing an increasing or escalating trend`);
  }
  if (relevantIncidentCount > 0) {
    factors.push(`${relevantIncidentCount} confirmed incident${relevantIncidentCount === 1 ? '' : 's'} tied to an active threat`);
  }

  return { score, label, factors, activeThreatCount: activeThreats.length };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

export async function renderGlobalThreatScore(container) {
  const [threatRecords, incidents] = await Promise.all([
    dbGetAll('threatRecords'),
    dbGetAll('incidents'),
  ]);

  if (threatRecords.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No reports imported yet.</p>';
    return;
  }

  const { score, label, factors, activeThreatCount } = computeGlobalThreatScore(threatRecords, incidents);
  const bandClass = SCORE_BAND_CLASS[label] || SCORE_BAND_CLASS.Low;

  if (activeThreatCount === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No active threat records — everything currently stored is resolved or historical.</p>';
    return;
  }

  container.innerHTML = `
    <div class="score-display ${bandClass}">
      <span class="score-number">${score}</span>
      <span class="score-label">${escapeHtml(label)}</span>
    </div>
    <p class="tile-intro-note">Reflects the whole dataset — unaffected by the filter bar above.</p>
    ${factors.length > 0 ? `<ul class="score-factors">${factors.map((f) => `<li>${escapeHtml(f)}</li>`).join('')}</ul>` : ''}
  `;
}
