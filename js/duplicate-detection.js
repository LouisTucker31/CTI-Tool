/**
 * duplicate-detection.js — cross-report duplicate detection for import.
 *
 * Two different tiers, because they need genuinely different treatment:
 *
 * EXACT-MATCH (Vulnerabilities by CVE ID, Malware by name) — reliable
 * enough to safely auto-resolve. If the person chooses to skip one,
 * any reference to it elsewhere in the new report (e.g. a threat record's
 * vulnerabilityIds) is rewritten to point at the *existing* stored record
 * instead — otherwise skipping would leave a dangling reference to
 * something never written to storage.
 *
 * INFORMATIONAL-ONLY (Threat records by title similarity, Threat actors by
 * name/alias overlap) — flagged for the person's awareness during import,
 * never auto-resolved. Threat record titles have no exact key at all, so
 * any match is a guess. Threat actors have a fairly reliable match, but
 * unlike vulnerabilities/malware there's no array field letting multiple
 * reports reference one shared actor record — skipping one the same way
 * would silently leave some other threat's actor list incomplete rather
 * than cleanly deduplicated. See the section below for the full reasoning.
 *
 * Per the schema doc's own principles: duplicates are never imported or
 * merged automatically — this module only detects and reports them; the
 * decision of what to do about it belongs to the user, in app.js.
 */

import { dbGetAll } from './db.js';

// ---------------------------------------------------------------------------
// Informational-only similarity detection — threat records and actors
// ---------------------------------------------------------------------------
//
// Unlike vulnerabilities/malware above, these two have no safe way to
// auto-resolve a match:
//   - Threat records have no exact key at all — only a title/description
//     to compare, which is inherently a guess, never a certainty.
//   - Threat actors DO have a fairly reliable match (name/alias overlap),
//     but unlike vulnerabilities/malware there's no array field on
//     ThreatRecord for multiple reports to reference one shared actor —
//     an actor belongs to exactly one threat record. Skipping a "duplicate"
//     actor the way vulnerabilities are skipped would silently make some
//     other threat's actor list incomplete, not cleanly deduplicated.
//
// So both are surfaced as a plain heads-up during import — never acted on
// automatically. If the person agrees something's genuinely duplicated,
// the fix is to review and delete the redundant report manually.

const TITLE_SIMILARITY_THRESHOLD = 0.35; // calibrated against real report titles — see chat
const STOPWORDS = new Set(['a', 'an', 'the', 'of', 'in', 'on', 'and', 'or', 'to', 'for', 'with', 'against', 'via', 'using', 'by']);

function tokenizeTitle(title) {
  return new Set(
    (title || '')
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, ' ')
      .split(/\s+/)
      .filter((w) => w.length > 2 && !STOPWORDS.has(w))
  );
}

function jaccardSimilarity(setA, setB) {
  if (setA.size === 0 || setB.size === 0) return 0;
  let intersection = 0;
  for (const item of setA) if (setB.has(item)) intersection++;
  return intersection / (setA.size + setB.size - intersection);
}

function actorNamePool(actor) {
  const names = [actor.actorName, ...(actor.aliases || [])];
  return new Set(names.filter(Boolean).map((n) => n.toUpperCase()));
}

/**
 * @returns {{ similarThreats: Array<{newTitle, existingTitle, existingThreatId, similarityPercent}>,
 *             similarActors: Array<{newName, existingName, existingThreatId}> }}
 */
export async function detectPossibleMatches(recordsByStore) {
  const [existingThreatRecords, existingActors] = await Promise.all([
    dbGetAll('threatRecords'),
    dbGetAll('threatActors'),
  ]);

  const similarThreats = [];
  for (const newThreat of recordsByStore.threatRecords || []) {
    const newTokens = tokenizeTitle(newThreat.threatTitle);
    let best = null;
    for (const existing of existingThreatRecords) {
      const score = jaccardSimilarity(newTokens, tokenizeTitle(existing.threatTitle));
      if (score >= TITLE_SIMILARITY_THRESHOLD && (!best || score > best.score)) {
        best = { existingThreat: existing, score };
      }
    }
    if (best) {
      similarThreats.push({
        newTitle: newThreat.threatTitle,
        existingTitle: best.existingThreat.threatTitle,
        existingThreatId: best.existingThreat.threatId,
        similarityPercent: Math.round(best.score * 100),
      });
    }
  }

  const similarActors = [];
  for (const newActor of recordsByStore.threatActors || []) {
    const newPool = actorNamePool(newActor);
    const existingMatch = existingActors.find((existing) => {
      const existingPool = actorNamePool(existing);
      for (const name of newPool) if (existingPool.has(name)) return true;
      return false;
    });
    if (existingMatch) {
      similarActors.push({
        newName: newActor.actorName,
        existingName: existingMatch.actorName,
        existingThreatId: existingMatch.parentThreatId,
      });
    }
  }

  return { similarThreats, similarActors };
}

// ---------------------------------------------------------------------------
// Exact-match detection (CVE ID / malware name) — safe to auto-resolve
// ---------------------------------------------------------------------------

/**
 * @returns {{ vulnerabilityDuplicates: Array<{newId, existingId, label}>,
 *             malwareDuplicates: Array<{newId, existingId, label}> }}
 */
export async function detectDuplicates(recordsByStore) {
  const [existingVulns, existingMalware] = await Promise.all([
    dbGetAll('vulnerabilities'),
    dbGetAll('malwareTools'),
  ]);

  const existingVulnByCve = new Map(
    existingVulns.filter((v) => v.cveId).map((v) => [v.cveId, v])
  );
  const existingMalwareByName = new Map(
    existingMalware.filter((m) => m.name).map((m) => [m.name.toUpperCase(), m])
  );

  const vulnerabilityDuplicates = [];
  for (const v of recordsByStore.vulnerabilities || []) {
    const existing = v.cveId ? existingVulnByCve.get(v.cveId) : null;
    if (existing) {
      vulnerabilityDuplicates.push({ newId: v.vulnerabilityId, existingId: existing.vulnerabilityId, label: v.cveId });
    }
  }

  const malwareDuplicates = [];
  for (const m of recordsByStore.malwareTools || []) {
    const existing = m.name ? existingMalwareByName.get(m.name.toUpperCase()) : null;
    if (existing) {
      malwareDuplicates.push({ newId: m.malwareToolId, existingId: existing.malwareToolId, label: m.name });
    }
  }

  return { vulnerabilityDuplicates, malwareDuplicates };
}

// ---------------------------------------------------------------------------
// Resolution — fully pure, no DB access, easy to unit test
// ---------------------------------------------------------------------------

function rewriteIdReferences(records, fieldNames, idMap) {
  if (idMap.size === 0) return records;
  return records.map((record) => {
    const updated = { ...record };
    for (const field of fieldNames) {
      if (Array.isArray(updated[field])) {
        updated[field] = updated[field].map((id) => idMap.get(id) || id);
      }
    }
    return updated;
  });
}

/**
 * Applies the user's skip/keep choice, returning a new recordsByStore with
 * skipped duplicates removed and any references to them re-pointed at the
 * already-existing stored record.
 */
export function resolveDuplicates(recordsByStore, duplicates, { skipVulnerabilities, skipMalware }) {
  let result = { ...recordsByStore };

  if (skipVulnerabilities && duplicates.vulnerabilityDuplicates.length > 0) {
    const skipIds = new Set(duplicates.vulnerabilityDuplicates.map((d) => d.newId));
    const idMap = new Map(duplicates.vulnerabilityDuplicates.map((d) => [d.newId, d.existingId]));
    result.vulnerabilities = result.vulnerabilities.filter((v) => !skipIds.has(v.vulnerabilityId));
    result.threatRecords = rewriteIdReferences(result.threatRecords, ['vulnerabilityIds'], idMap);
  }

  if (skipMalware && duplicates.malwareDuplicates.length > 0) {
    const skipIds = new Set(duplicates.malwareDuplicates.map((d) => d.newId));
    const idMap = new Map(duplicates.malwareDuplicates.map((d) => [d.newId, d.existingId]));
    result.malwareTools = result.malwareTools.filter((m) => !skipIds.has(m.malwareToolId));
    result.threatRecords = rewriteIdReferences(result.threatRecords, ['malwareToolIds'], idMap);
  }

  return result;
}
