/**
 * report-deletion.js — safely deleting a single imported report.
 *
 * "Safely" because of duplicate detection: if a later report skipped
 * importing a duplicate CVE/malware entry, its threat records got their
 * vulnerabilityIds/malwareToolIds rewritten to point at THIS report's copy
 * instead (see duplicate-detection.js). Blindly deleting everything this
 * report owns would leave that other report's threat record referencing a
 * vulnerability/malware record that no longer exists.
 *
 * So deletion works in two passes, computed together in
 * analyzeReportDeletion so the confirmation preview and the actual delete
 * can never disagree with each other:
 *
 *   1. For each vulnerability/malware record this report owns, check
 *      whether any surviving (other report's) threat record still
 *      references it. If so, it's RE-HOMED — its parentThreatId is
 *      rewritten to one of those surviving threat records — rather than
 *      deleted, so it stays reachable through the normal
 *      parentThreatId-based lookups every widget already uses.
 *   2. Everything else this report owns (locations, incidents, actors,
 *      MITRE mappings, exercise considerations, intelligence items,
 *      citations, and the report/threat records themselves) is deleted
 *      outright — none of those are ever cross-referenced by another
 *      report, since only vulnerabilityIds/malwareToolIds get rewritten
 *      at import time.
 */

import { dbGetAll, dbPut, dbDelete, addAuditLogEntry } from './db.js';

const UNCONDITIONAL_CHILD_STORES = [
  'locations', 'incidents', 'threatActors', 'mitreMappings',
  'exerciseConsiderations', 'intelligenceItems',
];

const STORE_ID_FIELDS = {
  locations: 'locationId',
  incidents: 'incidentId',
  threatActors: 'actorId',
  mitreMappings: 'mappingId',
  exerciseConsiderations: 'exerciseItemId',
  intelligenceItems: 'itemId',
};

function classifyOwnedRecords(records, reportThreatIds, survivingThreatRecords, idField, refField) {
  const owned = records.filter((r) => reportThreatIds.has(r.parentThreatId));
  const toDelete = [];
  const toRehome = [];

  for (const record of owned) {
    const referencingThreat = survivingThreatRecords.find(
      (t) => (t[refField] || []).includes(record[idField])
    );
    if (referencingThreat) {
      toRehome.push({ record, newParentThreatId: referencingThreat.threatId });
    } else {
      toDelete.push(record);
    }
  }

  return { toDelete, toRehome };
}

/**
 * Works out exactly what deleting this report would do, without changing
 * anything yet. Used both to build the confirmation message and by
 * deleteReport itself.
 */
export async function analyzeReportDeletion(reportId) {
  const [threatRecords, vulnerabilities, malwareTools, citations] = await Promise.all([
    dbGetAll('threatRecords'),
    dbGetAll('vulnerabilities'),
    dbGetAll('malwareTools'),
    dbGetAll('citations'),
  ]);

  const reportThreatIds = new Set(
    threatRecords.filter((t) => t.parentReportId === reportId).map((t) => t.threatId)
  );
  const survivingThreatRecords = threatRecords.filter((t) => !reportThreatIds.has(t.threatId));

  const vulnResult = classifyOwnedRecords(
    vulnerabilities, reportThreatIds, survivingThreatRecords, 'vulnerabilityId', 'vulnerabilityIds'
  );
  const malwareResult = classifyOwnedRecords(
    malwareTools, reportThreatIds, survivingThreatRecords, 'malwareToolId', 'malwareToolIds'
  );

  const childCounts = {};
  for (const storeName of UNCONDITIONAL_CHILD_STORES) {
    const all = await dbGetAll(storeName);
    childCounts[storeName] = all.filter((r) => reportThreatIds.has(r.parentThreatId)).length;
  }

  const citationCount = citations.filter((c) => c.parentReportId === reportId).length;

  return {
    reportId,
    reportThreatIds,
    threatRecordCount: reportThreatIds.size,
    childCounts,
    citationCount,
    vulnerabilitiesToDelete: vulnResult.toDelete,
    vulnerabilitiesToRehome: vulnResult.toRehome,
    malwareToDelete: malwareResult.toDelete,
    malwareToRehome: malwareResult.toRehome,
  };
}

export async function deleteReport(reportId) {
  const analysis = await analyzeReportDeletion(reportId);
  const {
    reportThreatIds, vulnerabilitiesToDelete, vulnerabilitiesToRehome,
    malwareToDelete, malwareToRehome,
  } = analysis;

  // Re-home first — these records survive, just pointing at a different parent now.
  for (const { record, newParentThreatId } of vulnerabilitiesToRehome) {
    await dbPut('vulnerabilities', { ...record, parentThreatId: newParentThreatId });
  }
  for (const { record, newParentThreatId } of malwareToRehome) {
    await dbPut('malwareTools', { ...record, parentThreatId: newParentThreatId });
  }

  // Delete everything else this report owned outright.
  for (const record of vulnerabilitiesToDelete) {
    await dbDelete('vulnerabilities', record.vulnerabilityId);
  }
  for (const record of malwareToDelete) {
    await dbDelete('malwareTools', record.malwareToolId);
  }

  for (const storeName of UNCONDITIONAL_CHILD_STORES) {
    const all = await dbGetAll(storeName);
    const idField = STORE_ID_FIELDS[storeName];
    const toDelete = all.filter((r) => reportThreatIds.has(r.parentThreatId));
    for (const record of toDelete) {
      await dbDelete(storeName, record[idField]);
    }
  }

  // Citations belong to the report directly, not via a threat record.
  const citations = await dbGetAll('citations');
  for (const c of citations.filter((c) => c.parentReportId === reportId)) {
    await dbDelete('citations', c.citationId);
  }

  // The threat records themselves.
  for (const threatId of reportThreatIds) {
    await dbDelete('threatRecords', threatId);
  }

  // The report record itself.
  await dbDelete('reports', reportId);

  await addAuditLogEntry({
    action: 'DELETE_REPORT',
    reportId,
    threatRecordCount: analysis.threatRecordCount,
  });

  return analysis;
}
