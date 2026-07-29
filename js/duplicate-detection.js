/**
 * duplicate-detection.js — cross-report duplicate detection for import.
 *
 * v1 scope, deliberately: only Vulnerabilities (matched by CVE ID) and
 * Malware/Tools (matched by name, case-insensitive). These are the two
 * entity types with a genuinely reliable natural key — a CVE ID either is
 * or isn't the same vulnerability, no fuzzy judgement required. Threat
 * records would need title/description similarity matching to detect
 * duplicates, which is a much harder problem deserving its own design
 * pass rather than being bolted on here.
 *
 * Per the schema doc's own principles: duplicates are never imported or
 * merged automatically — this module only detects and reports them; the
 * decision of what to do about it belongs to the user, in app.js.
 *
 * If the user chooses to skip a duplicate, any reference to it elsewhere
 * in the new report (e.g. a threat record's vulnerabilityIds) is rewritten
 * to point at the *existing* stored record instead — otherwise skipping
 * the duplicate would leave a dangling reference to something that was
 * never written to storage.
 */

import { dbGetAll } from './db.js';

// ---------------------------------------------------------------------------
// Detection — pure except for reading current storage state
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
