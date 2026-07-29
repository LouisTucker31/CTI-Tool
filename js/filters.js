/**
 * filters.js — shared filter-bar state and the filtering logic every
 * widget uses instead of calling dbGetAll() directly.
 *
 * One rule, applied consistently everywhere: a threat record passes if it
 * matches all active filters (sector/client/severity/time — AND logic,
 * not OR); anything that isn't a threat record itself (locations, actors,
 * vulnerabilities, MITRE mappings, exercise considerations, incidents) is
 * kept only if its parentThreatId belongs to a threat record that passes.
 *
 * Severity is a threshold, not an exact match — selecting "High" shows
 * High and Critical both, matching how severity filters normally work in
 * security tooling (nobody filtering for "High" wants Critical hidden).
 *
 * Global Threat Score, Recent Reports, and Recent Data Changes
 * deliberately do NOT use this module — see their own files for why.
 */

import { dbGetAll } from './db.js';

export const filterState = {
  sector: '',
  client: '',
  severity: '', // '' = all, else '1'-'5' meaning "this severity or above"
  time: 'all',  // 'all' | '12m' | '6m' | '3m' | '1m'
};

export function isAnyFilterActive() {
  return !!(filterState.sector || filterState.client || filterState.severity || (filterState.time && filterState.time !== 'all'));
}

function timeRangeCutoff(time) {
  if (!time || time === 'all') return null;
  const months = { '12m': 12, '6m': 6, '3m': 3, '1m': 1 }[time];
  if (!months) return null;
  const cutoff = new Date();
  cutoff.setMonth(cutoff.getMonth() - months);
  return cutoff;
}

function threatRecordMatchesFilters(t, options = {}) {
  if (!options.ignoreSector && filterState.sector && t.primarySector !== filterState.sector) return false;
  if (!options.ignoreClient && filterState.client && !(t.clientTags || []).includes(filterState.client)) return false;
  if (!options.ignoreSeverity && filterState.severity && (t.severityScore || 0) < Number(filterState.severity)) return false;

  const cutoff = timeRangeCutoff(filterState.time);
  if (cutoff) {
    const dateStr = t.lastObservedDate || t.firstObservedDate;
    if (!dateStr) return false; // no date to check against — safer to exclude than guess
    const date = new Date(dateStr);
    if (Number.isNaN(date.getTime()) || date < cutoff) return false;
  }

  return true;
}

/** Threat records matching every active filter (pass e.g. { ignoreClient: true } for widgets with their own client picker, like Client Relevance). */
export async function getFilteredThreatRecords(options = {}) {
  const all = await dbGetAll('threatRecords');
  return all.filter((t) => threatRecordMatchesFilters(t, options));
}

/** Just the set of threatIds currently passing the filters — cheap to reuse across several child-store lookups. */
export async function getFilteredThreatIdSet(options = {}) {
  const filtered = await getFilteredThreatRecords(options);
  return new Set(filtered.map((t) => t.threatId));
}

/**
 * Any store whose records carry a parentThreatId (locations, incidents,
 * threatActors, vulnerabilities, malwareTools, mitreMappings,
 * exerciseConsiderations, intelligenceItems), filtered down to only those
 * belonging to a threat record that currently passes the filters.
 */
export async function getFilteredChildRecords(storeName, parentField = 'parentThreatId', options = {}) {
  const [all, threatIdSet] = await Promise.all([dbGetAll(storeName), getFilteredThreatIdSet(options)]);
  return all.filter((record) => threatIdSet.has(record[parentField]));
}
