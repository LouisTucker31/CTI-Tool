/**
 * widgets/threat-score.js — the Global Threat Score widget.
 *
 * One weighted score across the whole dataset, independent of the
 * dashboard's filter bar (per the concept doc: filtering changes what you
 * see, not the underlying score).
 *
 * v2 — the original formula summed every active threat's contribution,
 * which meant the score would structurally climb toward 100 as more
 * reports accumulated over time, almost regardless of actual severity —
 * a report with 15 threats scored 99/Critical even with zero incidents,
 * actors, vulnerabilities or malware attached, purely from volume. Since
 * this tool is built to accumulate reports, that meant the score would
 * eventually hit Critical and stay there permanently, which defeats the
 * point of having a differentiated score at all.
 *
 * Two fixes, both verified against real reports before landing on them:
 *
 *   1. recordType now matters. TREND-type threat records (broad
 *      industry-wide observations, e.g. "AI is accelerating both sides
 *      of the threat landscape") count for half the weight of CAMPAIGN /
 *      INCIDENT_GROUP / VULNERABILITY_ACTIVITY records — those represent
 *      something concrete and attributable; a trend is context, not a
 *      specific active threat.
 *
 *   2. The score is now an AVERAGE across active threats (bounded,
 *      doesn't inflate with volume) plus a small, saturating bonus for
 *      having several serious concrete threats at once — "many serious
 *      things happening simultaneously is worse than one" without letting
 *      raw count dominate the number the way summing did.
 *
 * What feeds a single threat's contribution:
 *   - Severity, scaled down by how confident the report was in that
 *     assessment (a Critical rating we're only Low-confidence about counts
 *     for much less than a Critical rating rated Very High confidence).
 *   - A small bump for threats whose trend is INCREASING/ESCALATING, and a
 *     small reduction for DECLINING ones.
 *   - RESOLVED and HISTORICAL threat records are excluded entirely — a
 *     closed matter shouldn't keep inflating the current score.
 *
 * Forecasts are not part of this at all — consistent with the rest of the
 * dashboard, this is about confirmed/active threats, not predictions.
 */

import { dbGetAll } from '../db.js';
import { escapeHtml } from '../helpers.js';

const EXCLUDED_STATUSES = new Set(['RESOLVED', 'HISTORICAL']);
const INCREASING_TRENDS = new Set(['INCREASING', 'ESCALATING']);
const RECORD_TYPE_WEIGHT = { CAMPAIGN: 1.0, INCIDENT_GROUP: 1.0, VULNERABILITY_ACTIVITY: 1.0, TREND: 0.5 };
const MAX_ITEM_SCORE = 5.5; // severity 5 * confidence ratio 1.0 + trend bump 0.5 — the ceiling a single item can reach
const VOLUME_BONUS_MAX = 15; // points a report can gain from having several serious concrete threats at once
const VOLUME_BONUS_K = 4;
const INCIDENT_BONUS_PER = 2;
const INCIDENT_BONUS_MAX = 10;

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

  if (activeThreats.length === 0) {
    return { score: 0, label: scoreLabel(0), factors: [], activeThreatCount: 0 };
  }

  let itemScoreSum = 0;
  let increasingCount = 0;
  let highOrAboveCount = 0;
  let seriousCount = 0; // concrete (not TREND) + High/Critical severity + at least High confidence

  for (const t of activeThreats) {
    const confidenceRatio = (t.confidenceScore || 1) / 4;
    let trendAdjustment = 0;
    if (INCREASING_TRENDS.has(t.trendDirection)) {
      trendAdjustment = 0.5;
      increasingCount += 1;
    } else if (t.trendDirection === 'DECLINING') {
      trendAdjustment = -0.3;
    }
    const recordTypeWeight = RECORD_TYPE_WEIGHT[t.recordType] ?? 1.0; // unrecognised/missing type defaults to full weight
    const itemScore = Math.max(0, ((t.severityScore || 0) * confidenceRatio + trendAdjustment) * recordTypeWeight);
    itemScoreSum += itemScore;

    if ((t.severityScore || 0) >= 4) highOrAboveCount += 1;
    if (t.recordType !== 'TREND' && (t.severityScore || 0) >= 4 && (t.confidenceScore || 0) >= 3) {
      seriousCount += 1;
    }
  }

  const avgItemScore = itemScoreSum / activeThreats.length;
  const baseScore = Math.min(100, (avgItemScore / MAX_ITEM_SCORE) * 100);
  const volumeBonus = VOLUME_BONUS_MAX * (1 - Math.exp(-seriousCount / VOLUME_BONUS_K));

  const activeThreatIds = new Set(activeThreats.map((t) => t.threatId));
  const relevantIncidentCount = incidents.filter((inc) => activeThreatIds.has(inc.parentThreatId)).length;
  const incidentBonus = Math.min(INCIDENT_BONUS_MAX, relevantIncidentCount * INCIDENT_BONUS_PER);

  const score = Math.min(100, Math.round(baseScore + volumeBonus + incidentBonus));
  const label = scoreLabel(score);

  const factors = [];
  factors.push(`${activeThreats.length} active threat record${activeThreats.length === 1 ? '' : 's'}`);
  if (highOrAboveCount > 0) {
    factors.push(`${highOrAboveCount} rated High or Critical severity`);
  }
  if (increasingCount > 0) {
    factors.push(`${increasingCount} showing an increasing or escalating trend`);
  }
  if (seriousCount > 0) {
    factors.push(`${seriousCount} confirmed or attributable (not trend-level) threat${seriousCount === 1 ? '' : 's'} at High/Critical severity`);
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
