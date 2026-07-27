/**
 * parser.js — turns the DATA IMPORT APPENDIX text block from a CTI report
 * into the exact record shapes db.js's bulkWriteRecords() expects.
 *
 * It never touches the narrative prose (sections 1-14 of a report) — only
 * the machine-readable block between ===CTI_IMPORT_START=== and
 * ===CTI_IMPORT_END===. See docs/schema.md for the full field reference
 * this mirrors.
 *
 * Entry point: parseReport(rawText) -> { recordsByStore, warnings }
 * `recordsByStore` can be passed straight into bulkWriteRecords() from db.js.
 */

import { namespaceId } from './db.js';

// ---------------------------------------------------------------------------
// Fixed vocabularies (schema.md section 2 / prompt addendum rule 8)
// ---------------------------------------------------------------------------

const SEVERITY_LABELS = { 1: 'Informational', 2: 'Low', 3: 'Moderate', 4: 'High', 5: 'Critical' };
const CONFIDENCE_LABELS = { 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Very High' };

const KNOWN_ENUMS = {
  researchMethod: ['EXISTING_DOCUMENT_ANALYSIS', 'NEW_ONLINE_RESEARCH', 'COMBINED_RESEARCH'],
  threatStatus: ['NEW', 'ACTIVE', 'ONGOING', 'ESCALATING', 'STABLE', 'DECLINING', 'RESOLVED', 'HISTORICAL', 'UNKNOWN'],
  trendDirection: ['INCREASING', 'DECREASING', 'STABLE', 'EMERGING', 'IRREGULAR', 'UNKNOWN'],
  recordType: ['CAMPAIGN', 'INCIDENT_GROUP', 'TREND', 'VULNERABILITY_ACTIVITY'],
  attributionStatus: ['CONFIRMED', 'ASSESSED', 'SUSPECTED', 'UNKNOWN'],
  mappingType: ['EXPLICIT', 'INFERRED'],
  exploitationStatus: ['EXPLOITED', 'EXPLOITED_IN_REPORTED_INCIDENTS', 'NO_KNOWN_PUBLIC_EXPLOITATION', 'UNKNOWN'],
  locationType: [
    'REPORT_SCOPE', 'AFFECTED_LOCATION', 'VICTIM_ORGANISATION', 'THREAT_ACTOR',
    'SUSPECTED_ORIGIN', 'INFRASTRUCTURE', 'COMMAND_AND_CONTROL', 'DATA_HOSTING', 'UNKNOWN',
  ],
  locationPrecision: ['COUNTRY', 'REGION', 'CITY', 'COORDINATES', 'UNKNOWN'],
  itemType: [
    'STATISTIC', 'OBSERVATION', 'LOCATION_DETAIL', 'ATTACK_METHOD', 'DATA_IMPACT',
    'OPERATIONAL_IMPACT', 'SAFETY_IMPACT', 'FINANCIAL_IMPACT', 'VULNERABILITY',
    'MALWARE', 'FORECAST_NOTE', 'CLIENT_RELEVANCE',
  ],
  considerationType: [
    'SCENARIO_THEME', 'DECISION_POINT', 'COMMUNICATIONS_CHALLENGE',
    'SUPPLY_CHAIN_CHALLENGE', 'REGULATORY_CHALLENGE',
  ],
  // Imports only ever produce these two — EXPIRED/CONFIRMED/etc. are set later by the app itself.
  forecastStatus: ['UPCOMING', 'ACTIVE'],
};

// Fields whose value space is a fixed vocabulary, not free text. For these,
// "UNKNOWN" is frequently a legitimate enum member in its own right (e.g.
// THREAT_STATUS, ATTRIBUTION_STATUS) — it must NOT be run through the
// generic NONE/UNKNOWN null-token normalization that free-text fields get,
// or it gets silently rewritten to 'Unknown' and fails enum validation.
const ENUM_FIELD_KEYS = new Set([
  'recordType', 'threatStatus', 'trendDirection', 'attributionStatus',
  'mappingType', 'exploitationStatus', 'locationType', 'locationPrecision',
  'itemType', 'considerationType', 'researchMethod', 'forecastStatus',
]);

// Raw appendix field name -> canonical camelCase schema field name.
// Only needed where generic snake->camel conversion wouldn't match schema.md.
const FIELD_NAME_OVERRIDES = {
  SOURCE_IDS: 'sourceCitationIds',
  ASSOCIATED_CLIENTS: 'clientTags',
  RELEVANT_CLIENTS: 'clientTags',
  THREAT_ACTOR_IDS_OR_NAMES: 'threatActorIds',
  THREAT_ACTOR_IDS: 'threatActorIds',
  ASSOCIATED_THREAT_ACTORS: 'associatedThreatActorIds',
  MALWARE_AND_TOOLS: 'malwareToolIds',
  VULNERABILITIES: 'vulnerabilityIds',
  ASSOCIATED_ACTORS: 'associatedActorIds',
  SUPPORTING_INTELLIGENCE_ITEM_IDS: 'supportingIntelligenceItemIds',
  RELEVANT_THREAT_IDS: 'relevantThreatIds',
  PARENT_THREAT_IDS: 'parentThreatIds',
  PARENT_THREAT_ID: 'parentThreatId',
};

// Fields (post-mapping, camelCase) that hold references to other entities'
// local IDs and therefore need namespacing + cross-reference validation.
const ID_ARRAY_FIELDS = new Set([
  'associatedThreatActorIds', 'threatActorIds', 'malwareToolIds', 'vulnerabilityIds',
  'associatedLocationIds', 'affectedLocationIds', 'actorLocationIds',
  'associatedIncidentIds', 'associatedMitreMappingIds', 'associatedActorIds',
  'supportingIntelligenceItemIds', 'parentThreatIds', 'sourceCitationIds',
  'relevantThreatIds',
]);

// Which store each of those FK field names should be checked against.
const ID_FIELD_TARGET_STORE = {
  associatedThreatActorIds: 'threatActors',
  threatActorIds: 'threatActors',
  associatedActorIds: 'threatActors',
  malwareToolIds: 'malwareTools',
  vulnerabilityIds: 'vulnerabilities',
  associatedLocationIds: 'locations',
  affectedLocationIds: 'locations',
  actorLocationIds: 'locations',
  associatedIncidentIds: 'incidents',
  associatedMitreMappingIds: 'mitreMappings',
  supportingIntelligenceItemIds: 'intelligenceItems',
  parentThreatIds: 'threatRecords',
  sourceCitationIds: 'citations',
  relevantThreatIds: 'threatRecords',
};

const LOCAL_ID_PATTERN = /^[A-Z]{2,5}-\d+$/; // TR-001, LOC-002, ACT-003, VUL-004, MAL-001, MAP-005, EX-006, FC-001, INC-007
const CITATION_ID_PATTERN = /^S\d+$/; // S001

// ---------------------------------------------------------------------------
// Low-level string helpers
// ---------------------------------------------------------------------------

function snakeToCamel(key) {
  return key
    .toLowerCase()
    .split('_')
    .map((word, i) => (i === 0 ? word : word.charAt(0).toUpperCase() + word.slice(1)))
    .join('');
}

function isNoneToken(value) {
  const u = value.toUpperCase();
  return u === 'NONE' || u === 'N/A' || u === 'NOT_APPLICABLE' || u.startsWith('NONE_');
}

function isUnknownToken(value) {
  return value.toUpperCase() === 'UNKNOWN';
}

/** NONE -> null, UNKNOWN -> 'Unknown' (kept, not blanked), anything else -> trimmed as-is. */
function normalizeToken(raw) {
  const v = String(raw).trim();
  if (v === '') return null;
  if (isNoneToken(v)) return null;
  if (isUnknownToken(v)) return 'Unknown';
  return v;
}

/** Splits on '|' when present; always returns an array of normalized tokens (or []). */
function splitMultiValue(raw) {
  if (raw === undefined || raw === null) return [];
  const parts = String(raw).split('|').map((p) => normalizeToken(p)).filter((p) => p !== null);
  return parts;
}

function parseIntOrNull(value) {
  if (value === null || value === undefined || value === 'Unknown') return null;
  const n = parseInt(value, 10);
  return Number.isNaN(n) ? null : n;
}

function parseFloatOrNull(value) {
  if (value === null || value === undefined || value === 'Unknown') return null;
  const n = parseFloat(value);
  return Number.isNaN(n) ? null : n;
}

function deriveSeverityLabel(score) {
  return score === null ? null : (SEVERITY_LABELS[score] || null);
}

function deriveConfidenceLabel(score) {
  return score === null ? null : (CONFIDENCE_LABELS[score] || null);
}

/** YYYY / YYYY-MM / YYYY-MM-DD -> { value, precision }. */
function parseDateWithPrecision(raw) {
  const v = normalizeToken(raw ?? '');
  if (v === null) return { value: null, precision: null };
  if (v === 'Unknown') return { value: null, precision: 'UNKNOWN' };
  if (/^\d{4}$/.test(v)) return { value: v, precision: 'YEAR' };
  if (/^\d{4}-\d{2}$/.test(v)) return { value: v, precision: 'MONTH' };
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return { value: v, precision: 'EXACT' };
  return { value: v, precision: 'UNKNOWN' }; // unexpected shape — kept as-is, flagged as imprecise
}

// ---------------------------------------------------------------------------
// Tokenizing / block-walking engine
// ---------------------------------------------------------------------------

const BLOCK_START_RE = /^===([A-Z_]+)_START===$/;
const BLOCK_END_RE = /^===([A-Z_]+)_END===$/;
const TEXT_FIELD_START_RE = /^([A-Z_]+)_START$/;
const TEXT_FIELD_END_RE = /^([A-Z_]+)_END$/;
const KEY_VALUE_RE = /^([A-Z_]+):\s?(.*)$/;

function extractImportBlock(fullText) {
  const startIdx = fullText.indexOf('===CTI_IMPORT_START===');
  const endIdx = fullText.indexOf('===CTI_IMPORT_END===');
  if (startIdx === -1 || endIdx === -1 || endIdx < startIdx) return null;
  return fullText.slice(startIdx + '===CTI_IMPORT_START==='.length, endIdx);
}

/**
 * Walks the import block line by line. Returns:
 *  - topLevelFields: raw fields dict for anything at stack depth 0 (report metadata)
 *  - blocks: flat array of { tag, fields } in document order, for every
 *            ===TAG_START===...===TAG_END=== block encountered, at any depth.
 * Nested blocks (e.g. LOCATION inside THREAT_RECORD) already carry their own
 * PARENT_THREAT_ID field in the source, so we don't need to reconstruct
 * parentage structurally — the stack only tells us which fields dict a plain
 * KEY: VALUE line belongs to right now.
 */
function walkBlocks(importBlockText) {
  const lines = importBlockText.split('\n');
  const topLevelFields = {};
  const blocks = [];
  const stack = []; // each entry: { tag, fields }

  let collectingTextField = null; // { name, lines: [] } while inside a KEY_START...KEY_END span

  const currentFields = () => (stack.length > 0 ? stack[stack.length - 1].fields : topLevelFields);

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === '') continue;

    if (collectingTextField) {
      const endMatch = line.match(TEXT_FIELD_END_RE);
      if (endMatch && endMatch[1] === collectingTextField.name) {
        currentFields()[collectingTextField.name] = collectingTextField.lines.join('\n');
        collectingTextField = null;
      } else {
        collectingTextField.lines.push(rawLine);
      }
      continue;
    }

    const blockStart = line.match(BLOCK_START_RE);
    if (blockStart) {
      stack.push({ tag: blockStart[1], fields: {} });
      continue;
    }

    const blockEnd = line.match(BLOCK_END_RE);
    if (blockEnd) {
      const closed = stack.pop();
      if (!closed || closed.tag !== blockEnd[1]) {
        throw new Error(`Parser error: mismatched block end ===${blockEnd[1]}_END=== — check the appendix formatting.`);
      }
      blocks.push(closed);
      continue;
    }

    const textFieldStart = line.match(TEXT_FIELD_START_RE);
    if (textFieldStart) {
      collectingTextField = { name: textFieldStart[1], lines: [] };
      continue;
    }

    const kv = line.match(KEY_VALUE_RE);
    if (kv) {
      currentFields()[kv[1]] = kv[2];
      continue;
    }

    // Unrecognised line shape — ignore rather than fail the whole import.
  }

  return { topLevelFields, blocks };
}

/**
 * Converts a raw fields dict (SCREAMING_SNAKE keys, string values) into a
 * camelCase-keyed dict with pipe-separated values already split into arrays
 * and NONE/UNKNOWN tokens normalized. Multi-line text fields (already joined
 * strings from walkBlocks) pass through as plain strings, not split.
 */
function mapRawFields(rawFields, multiValueKeys) {
  const out = {};
  for (const [rawKey, rawValue] of Object.entries(rawFields)) {
    const camelKey = FIELD_NAME_OVERRIDES[rawKey] || snakeToCamel(rawKey);
    if (ENUM_FIELD_KEYS.has(camelKey)) {
      const trimmed = String(rawValue).trim();
      out[camelKey] = trimmed === '' ? null : trimmed.toUpperCase();
    } else if (multiValueKeys.has(camelKey)) {
      out[camelKey] = splitMultiValue(rawValue);
    } else {
      out[camelKey] = normalizeToken(rawValue);
    }
  }
  return out;
}

function looksLikeLocalId(token) {
  return LOCAL_ID_PATTERN.test(token) || CITATION_ID_PATTERN.test(token);
}

/** Namespaces tokens that look like local IDs; leaves genuine free-text tags untouched. */
function namespaceIdArray(tokens, reportId) {
  if (!Array.isArray(tokens)) return [];
  return tokens.map((t) => (looksLikeLocalId(t) ? namespaceId(reportId, t) : t));
}

// ---------------------------------------------------------------------------
// Per-entity finalize functions
// ---------------------------------------------------------------------------

const THREAT_RECORD_MULTI = new Set([
  'threatCategory', 'additionalSectors', 'clientTags', 'associatedOrganisations',
  'associatedThreatActorIds', 'attackMethods', 'malwareToolIds', 'vulnerabilityIds',
  'tags', 'sourceCitationIds',
]);

function finalizeThreatRecord(rawFields, reportId, warnings) {
  const f = mapRawFields(rawFields, THREAT_RECORD_MULTI);
  const severityScore = parseIntOrNull(f.severityScore);
  const confidenceScore = parseIntOrNull(f.confidenceScore);
  const first = parseDateWithPrecision(f.firstObservedDate);
  const last = parseDateWithPrecision(f.lastObservedDate);

  if (f.recordType && !KNOWN_ENUMS.recordType.includes(f.recordType)) {
    warnings.push(`Unrecognised RECORD_TYPE "${f.recordType}" on ${f.threatId}`);
  }
  if (f.threatStatus && !KNOWN_ENUMS.threatStatus.includes(f.threatStatus)) {
    warnings.push(`Unrecognised THREAT_STATUS "${f.threatStatus}" on ${f.threatId}`);
  }
  if (f.trendDirection && !KNOWN_ENUMS.trendDirection.includes(f.trendDirection)) {
    warnings.push(`Unrecognised TREND_DIRECTION "${f.trendDirection}" on ${f.threatId}`);
  }

  return {
    threatId: namespaceId(reportId, f.threatId),
    parentReportId: reportId,
    recordType: f.recordType,
    threatTitle: f.threatTitle,
    oneLineSummary: f.oneLineSummary,
    fullDescription: f.fullDescription || null,
    threatCategory: f.threatCategory,
    threatStatus: f.threatStatus,
    trendDirection: f.trendDirection,
    severityScore,
    severityLabel: deriveSeverityLabel(severityScore),
    severityLabelRaw: f.severityLabel,
    severityRationale: f.severityRationale,
    confidenceScore,
    confidenceLabel: deriveConfidenceLabel(confidenceScore),
    confidenceLabelRaw: f.confidenceLabel,
    confidenceRationale: f.confidenceRationale,
    firstObservedDate: first.value,
    firstObservedDatePrecision: first.precision,
    lastObservedDate: last.value,
    lastObservedDatePrecision: last.precision,
    primarySector: f.primarySector,
    additionalSectors: f.additionalSectors,
    clientTags: f.clientTags,
    associatedOrganisations: f.associatedOrganisations,
    associatedThreatActorIds: namespaceIdArray(f.associatedThreatActorIds, reportId),
    attackMethods: f.attackMethods,
    malwareToolIds: namespaceIdArray(f.malwareToolIds, reportId),
    vulnerabilityIds: namespaceIdArray(f.vulnerabilityIds, reportId),
    tags: f.tags,
    sourceCitationIds: namespaceIdArray(f.sourceCitationIds, reportId),
  };
}

const LOCATION_MULTI = new Set(['sourceCitationIds']);

function finalizeLocation(rawFields, reportId, warnings) {
  const f = mapRawFields(rawFields, LOCATION_MULTI);
  const confidenceScore = parseIntOrNull(f.locationConfidenceScore);

  if (f.locationType && !KNOWN_ENUMS.locationType.includes(f.locationType)) {
    warnings.push(`Unrecognised LOCATION_TYPE "${f.locationType}" on ${f.locationId}`);
  }
  if (f.locationPrecision && !KNOWN_ENUMS.locationPrecision.includes(f.locationPrecision)) {
    warnings.push(`Unrecognised LOCATION_PRECISION "${f.locationPrecision}" on ${f.locationId}`);
  }

  return {
    locationId: namespaceId(reportId, f.locationId),
    parentThreatId: namespaceId(reportId, f.parentThreatId),
    locationType: f.locationType,
    country: f.country,
    region: f.region,
    city: f.city,
    latitude: parseFloatOrNull(f.latitude),
    longitude: parseFloatOrNull(f.longitude),
    locationPrecision: f.locationPrecision,
    locationConfidenceScore: confidenceScore,
    locationConfidenceLabel: deriveConfidenceLabel(confidenceScore),
    locationConfidenceLabelRaw: f.locationConfidenceLabel,
    locationExplanation: f.locationExplanation,
    sourceCitationIds: namespaceIdArray(f.sourceCitationIds, reportId),
  };
}

const INCIDENT_MULTI = new Set(['affectedLocationIds', 'threatActorIds', 'attackMethods', 'sourceCitationIds']);

function finalizeIncident(rawFields, reportId) {
  const f = mapRawFields(rawFields, INCIDENT_MULTI);
  const severityScore = parseIntOrNull(f.severityScore);
  const confidenceScore = parseIntOrNull(f.confidenceScore);
  const incidentDate = parseDateWithPrecision(f.incidentDate);
  const first = parseDateWithPrecision(f.firstObservedDate);
  const last = parseDateWithPrecision(f.lastObservedDate);

  return {
    incidentId: namespaceId(reportId, f.incidentId),
    parentThreatId: namespaceId(reportId, f.parentThreatId),
    incidentTitle: f.incidentTitle,
    incidentDate: incidentDate.value,
    incidentDatePrecision: incidentDate.precision,
    firstObservedDate: first.value,
    firstObservedDatePrecision: first.precision,
    lastObservedDate: last.value,
    lastObservedDatePrecision: last.precision,
    affectedOrganisation: f.affectedOrganisation,
    affectedSector: f.affectedSector,
    affectedLocationIds: namespaceIdArray(f.affectedLocationIds, reportId),
    threatActorIds: namespaceIdArray(f.threatActorIds, reportId),
    attackMethods: f.attackMethods,
    impactSummary: f.impactSummary,
    severityScore,
    severityLabel: deriveSeverityLabel(severityScore),
    severityLabelRaw: f.severityLabel,
    confidenceScore,
    confidenceLabel: deriveConfidenceLabel(confidenceScore),
    confidenceLabelRaw: f.confidenceLabel,
    sourceCitationIds: namespaceIdArray(f.sourceCitationIds, reportId),
  };
}

const ITEM_MULTI = new Set(['associatedIncidentIds', 'associatedLocationIds', 'clientTags', 'sourceCitationIds']);

function finalizeIntelligenceItem(rawFields, reportId, warnings) {
  const f = mapRawFields(rawFields, ITEM_MULTI);
  const confidenceScore = parseIntOrNull(f.confidenceScore);
  const itemDate = parseDateWithPrecision(f.itemDate);
  const periodStart = parseDateWithPrecision(f.itemPeriodStart);
  const periodEnd = parseDateWithPrecision(f.itemPeriodEnd);
  const comparisonPeriodStart = parseDateWithPrecision(f.comparisonPeriodStart);
  const comparisonPeriodEnd = parseDateWithPrecision(f.comparisonPeriodEnd);

  if (f.itemType && !KNOWN_ENUMS.itemType.includes(f.itemType)) {
    warnings.push(`Unrecognised ITEM_TYPE "${f.itemType}" on ${f.itemId}`);
  }

  return {
    itemId: namespaceId(reportId, f.itemId),
    parentThreatId: namespaceId(reportId, f.parentThreatId),
    associatedIncidentIds: namespaceIdArray(f.associatedIncidentIds, reportId),
    itemType: f.itemType,
    itemTitle: f.itemTitle,
    itemText: f.itemText,
    itemDate: itemDate.value,
    itemDatePrecision: itemDate.precision,
    itemPeriodStart: periodStart.value,
    itemPeriodEnd: periodEnd.value,
    numericalValue: parseFloatOrNull(f.numericalValue),
    valueUnit: f.valueUnit,
    comparisonValue: parseFloatOrNull(f.comparisonValue),
    comparisonPeriodStart: comparisonPeriodStart.value,
    comparisonPeriodEnd: comparisonPeriodEnd.value,
    percentageChange: parseFloatOrNull(f.percentageChange),
    associatedLocationIds: namespaceIdArray(f.associatedLocationIds, reportId),
    clientTags: f.clientTags,
    confidenceScore,
    confidenceLabel: deriveConfidenceLabel(confidenceScore),
    confidenceLabelRaw: f.confidenceLabel,
    sourceCitationIds: namespaceIdArray(f.sourceCitationIds, reportId),
    limitations: f.limitations,
  };
}

const ACTOR_MULTI = new Set(['aliases', 'suspectedAffiliation', 'actorLocationIds', 'sourceCitationIds']);

function finalizeThreatActor(rawFields, reportId, warnings) {
  const f = mapRawFields(rawFields, ACTOR_MULTI);
  const confidenceScore = parseIntOrNull(f.attributionConfidenceScore);

  if (f.attributionStatus && !KNOWN_ENUMS.attributionStatus.includes(f.attributionStatus)) {
    warnings.push(`Unrecognised ATTRIBUTION_STATUS "${f.attributionStatus}" on ${f.actorId}`);
  }

  return {
    actorId: namespaceId(reportId, f.actorId),
    parentThreatId: namespaceId(reportId, f.parentThreatId),
    actorName: f.actorName,
    aliases: f.aliases,
    actorType: f.actorType,
    suspectedAffiliation: f.suspectedAffiliation,
    attributionStatus: f.attributionStatus,
    attributionConfidenceScore: confidenceScore,
    attributionConfidenceLabel: deriveConfidenceLabel(confidenceScore),
    attributionConfidenceLabelRaw: f.attributionConfidenceLabel,
    actorLocationIds: namespaceIdArray(f.actorLocationIds, reportId),
    supportingEvidence: f.supportingEvidence,
    sourceCitationIds: namespaceIdArray(f.sourceCitationIds, reportId),
  };
}

const VULN_MULTI = new Set(['product', 'associatedIncidentIds', 'sourceCitationIds']);

function finalizeVulnerability(rawFields, reportId, warnings) {
  const f = mapRawFields(rawFields, VULN_MULTI);
  const severityScore = parseIntOrNull(f.severityScore);
  const confidenceScore = parseIntOrNull(f.confidenceScore);
  const firstExploited = parseDateWithPrecision(f.firstExploitedDate);

  if (f.exploitationStatus && !KNOWN_ENUMS.exploitationStatus.includes(f.exploitationStatus)) {
    warnings.push(`Unrecognised EXPLOITATION_STATUS "${f.exploitationStatus}" on ${f.vulnerabilityId}`);
  }

  return {
    vulnerabilityId: namespaceId(reportId, f.vulnerabilityId),
    parentThreatId: namespaceId(reportId, f.parentThreatId),
    cveId: f.cveId,
    vulnerabilityName: f.vulnerabilityName,
    product: f.product,
    vendor: f.vendor,
    exploitationStatus: f.exploitationStatus,
    firstExploitedDate: firstExploited.value,
    firstExploitedDatePrecision: firstExploited.precision,
    associatedIncidentIds: namespaceIdArray(f.associatedIncidentIds, reportId),
    severityScore,
    severityLabel: deriveSeverityLabel(severityScore),
    severityLabelRaw: f.severityLabel,
    confidenceScore,
    confidenceLabel: deriveConfidenceLabel(confidenceScore),
    confidenceLabelRaw: f.confidenceLabel,
    sourceCitationIds: namespaceIdArray(f.sourceCitationIds, reportId),
  };
}

const MALWARE_MULTI = new Set(['purpose', 'associatedActorIds', 'associatedIncidentIds', 'sourceCitationIds']);

function finalizeMalwareTool(rawFields, reportId) {
  const f = mapRawFields(rawFields, MALWARE_MULTI);
  const confidenceScore = parseIntOrNull(f.confidenceScore);

  return {
    malwareToolId: namespaceId(reportId, f.malwareToolId),
    parentThreatId: namespaceId(reportId, f.parentThreatId),
    name: f.name,
    type: f.type,
    purpose: f.purpose,
    associatedActorIds: namespaceIdArray(f.associatedActorIds, reportId),
    associatedIncidentIds: namespaceIdArray(f.associatedIncidentIds, reportId),
    confidenceScore,
    confidenceLabel: deriveConfidenceLabel(confidenceScore),
    confidenceLabelRaw: f.confidenceLabel,
    sourceCitationIds: namespaceIdArray(f.sourceCitationIds, reportId),
  };
}

const MAPPING_MULTI = new Set(['associatedIncidentIds', 'tactic', 'sourceCitationIds']);

function finalizeMitreMapping(rawFields, reportId, warnings) {
  const f = mapRawFields(rawFields, MAPPING_MULTI);
  const confidenceScore = parseIntOrNull(f.mappingConfidenceScore);

  if (f.mappingType && !KNOWN_ENUMS.mappingType.includes(f.mappingType)) {
    warnings.push(`Unrecognised MAPPING_TYPE "${f.mappingType}" on ${f.mappingId}`);
  }

  return {
    mappingId: namespaceId(reportId, f.mappingId),
    parentThreatId: namespaceId(reportId, f.parentThreatId),
    associatedIncidentIds: namespaceIdArray(f.associatedIncidentIds, reportId),
    techniqueId: f.techniqueId,
    techniqueName: f.techniqueName,
    tactic: f.tactic,
    mappingType: f.mappingType,
    mappingConfidenceScore: confidenceScore,
    mappingConfidenceLabel: deriveConfidenceLabel(confidenceScore),
    mappingConfidenceLabelRaw: f.mappingConfidenceLabel,
    supportingEvidence: f.supportingEvidence,
    sourceCitationIds: namespaceIdArray(f.sourceCitationIds, reportId),
  };
}

const EXERCISE_MULTI = new Set([
  'clientTags', 'relevantSectors', 'relevantTechnologies', 'relevantDepartments',
  'associatedIncidentIds', 'associatedMitreMappingIds', 'sourceCitationIds',
]);

function finalizeExerciseConsideration(rawFields, reportId, warnings) {
  const f = mapRawFields(rawFields, EXERCISE_MULTI);
  const confidenceScore = parseIntOrNull(f.exerciseRelevanceConfidenceScore);

  if (f.considerationType && !KNOWN_ENUMS.considerationType.includes(f.considerationType)) {
    warnings.push(`Unrecognised CONSIDERATION_TYPE "${f.considerationType}" on ${f.exerciseItemId}`);
  }

  return {
    exerciseItemId: namespaceId(reportId, f.exerciseItemId),
    parentThreatId: namespaceId(reportId, f.parentThreatId),
    considerationType: f.considerationType,
    title: f.title,
    description: f.description,
    clientTags: f.clientTags,
    relevantSectors: f.relevantSectors,
    relevantTechnologies: f.relevantTechnologies,
    relevantDepartments: f.relevantDepartments,
    associatedIncidentIds: namespaceIdArray(f.associatedIncidentIds, reportId),
    associatedMitreMappingIds: namespaceIdArray(f.associatedMitreMappingIds, reportId),
    exerciseRelevanceConfidenceScore: confidenceScore,
    exerciseRelevanceConfidenceLabel: deriveConfidenceLabel(confidenceScore),
    exerciseRelevanceConfidenceLabelRaw: f.exerciseRelevanceConfidenceLabel,
    sourceCitationIds: namespaceIdArray(f.sourceCitationIds, reportId),
  };
}

const FORECAST_MULTI = new Set([
  'parentThreatIds', 'predictedLocations', 'predictedSectors', 'predictedThreatType',
  'supportingIntelligenceItemIds', 'conditionsSupportingForecast', 'conditionsUnderminingForecast',
  'clientTags', 'sourceCitationIds',
]);

function finalizeForecast(rawFields, reportId, warnings) {
  const f = mapRawFields(rawFields, FORECAST_MULTI);
  const confidenceScore = parseIntOrNull(f.confidenceScore);
  const created = parseDateWithPrecision(f.forecastCreationDate);
  const start = parseDateWithPrecision(f.forecastStartDate);
  const expiry = parseDateWithPrecision(f.forecastExpiryDate);

  if (f.forecastStatus && !KNOWN_ENUMS.forecastStatus.includes(f.forecastStatus)) {
    warnings.push(
      `Forecast ${f.forecastId} has FORECAST_STATUS "${f.forecastStatus}" — imports should only ` +
      `ever set UPCOMING or ACTIVE; other statuses are meant to be set later by the app.`
    );
  }

  return {
    forecastId: namespaceId(reportId, f.forecastId),
    parentThreatIds: namespaceIdArray(f.parentThreatIds, reportId),
    forecastTitle: f.forecastTitle,
    forecastDescription: f.forecastDescription,
    forecastCreationDate: created.value,
    forecastStartDate: start.value,
    forecastExpiryDate: expiry.value,
    predictedLocations: f.predictedLocations,
    predictedSectors: f.predictedSectors,
    predictedThreatType: f.predictedThreatType,
    forecastStatus: f.forecastStatus, // import always sets UPCOMING/ACTIVE; app manages transitions after this
    confidenceScore,
    confidenceLabel: deriveConfidenceLabel(confidenceScore),
    confidenceLabelRaw: f.confidenceLabel,
    supportingEvidence: f.supportingEvidence,
    supportingIntelligenceItemIds: namespaceIdArray(f.supportingIntelligenceItemIds, reportId),
    conditionsSupporting: f.conditionsSupportingForecast,
    conditionsUndermining: f.conditionsUnderminingForecast,
    clientTags: f.clientTags,
    sourceCitationIds: namespaceIdArray(f.sourceCitationIds, reportId),
  };
}

const CITATION_MULTI = new Set(['relevantThreatIds']);

function finalizeCitation(rawFields, reportId) {
  const f = mapRawFields(rawFields, CITATION_MULTI);
  const pubDate = parseDateWithPrecision(f.sourcePublicationDate);

  return {
    citationId: namespaceId(reportId, f.sourceId),
    parentReportId: reportId,
    sourceTitle: f.sourceTitle,
    sourcePublisher: f.sourcePublisher,
    sourcePublicationDate: pubDate.value,
    sourcePublicationDatePrecision: pubDate.precision,
    sourceType: f.sourceType,
    sourceUrlOrDocumentName: f.sourceUrlOrDocumentName,
    dateAccessed: f.dateAccessed,
    relevantThreatIds: namespaceIdArray(f.relevantThreatIds, reportId),
    sourceQualityNotes: f.sourceQualityNotes,
  };
}

const REPORT_MULTI = new Set([
  'subsectors', 'namedClients', 'relevantOrganisations', 'technologiesOfInterest',
]);

const REPORT_ANALYSIS_MULTI = new Set([
  'mostCommonThreatCategories', 'mostCommonAttackMethods', 'mostCommonMitreTechniques',
  'mostActiveThreatActors', 'mostAffectedLocations', 'mostTargetedSectors',
  'mostSignificantVulnerabilities', 'mostSignificantMalware', 'keyExerciseThemes',
]);

function finalizeReport(topLevelFields, reportAnalysisRawFields, reportId, warnings) {
  const f = mapRawFields(topLevelFields, REPORT_MULTI);
  const overallConfidenceScore = parseIntOrNull(f.overallConfidenceScore);

  if (f.researchMethod && !KNOWN_ENUMS.researchMethod.includes(f.researchMethod)) {
    warnings.push(`Unrecognised RESEARCH_METHOD "${f.researchMethod}" on report ${reportId}`);
  }

  let reportAnalysisRollup = null;
  let reportAuthorSummary = null;
  if (reportAnalysisRawFields) {
    const ra = mapRawFields(reportAnalysisRawFields, REPORT_ANALYSIS_MULTI);
    reportAuthorSummary = ra.reportAuthorSummary || null;
    reportAnalysisRollup = {
      mostCommonThreatCategories: ra.mostCommonThreatCategories,
      mostCommonAttackMethods: ra.mostCommonAttackMethods,
      mostCommonMitreTechniques: ra.mostCommonMitreTechniques,
      mostActiveThreatActorIds: namespaceIdArray(ra.mostActiveThreatActors, reportId),
      mostAffectedLocations: ra.mostAffectedLocations,
      mostTargetedSectors: ra.mostTargetedSectors,
      mostSignificantVulnerabilityIds: namespaceIdArray(ra.mostSignificantVulnerabilities, reportId),
      mostSignificantMalwareIds: namespaceIdArray(ra.mostSignificantMalware, reportId),
      overallTrendDirection: ra.overallTrendDirection,
      keyExerciseThemes: ra.keyExerciseThemes,
    };
  }

  return {
    reportId: f.reportId,
    schemaVersion: f.schemaVersion,
    reportTitle: f.reportTitle,
    primaryLocation: f.primaryLocation,
    primarySector: f.primarySector,
    subsectors: f.subsectors,
    reportingPeriodStart: f.reportingPeriodStart,
    reportingPeriodEnd: f.reportingPeriodEnd,
    reportGenerationDate: f.reportGenerationDate,
    researchDate: f.researchDate,
    researchMethod: f.researchMethod,
    intendedUse: f.intendedUse,
    namedClients: f.namedClients,
    relevantOrganisations: f.relevantOrganisations,
    technologiesOfInterest: f.technologiesOfInterest,
    overallConfidenceScore,
    overallConfidenceLabel: deriveConfidenceLabel(overallConfidenceScore),
    overallConfidenceLabelRaw: f.overallConfidenceLabel,
    declaredThreatRecordCount: parseIntOrNull(f.threatRecordCount),
    declaredIncidentCount: parseIntOrNull(f.incidentCount),
    declaredForecastCount: parseIntOrNull(f.forecastCount),
    executiveSummary: f.reportExecutiveSummary || null,
    reportAuthorSummary,
    reportAnalysisRollup,
    originalFileName: null, // set by the caller (import UI) once a real file is involved
    originalFileRef: null,
    importDate: new Date().toISOString(),
    importStats: null, // filled in by the caller once approval counts are known
    reportStatus: 'ACTIVE',
    changeHistory: [],
  };
}

// ---------------------------------------------------------------------------
// Top-level orchestration
// ---------------------------------------------------------------------------

const BLOCK_TAG_TO_STORE = {
  THREAT_RECORD: 'threatRecords',
  LOCATION: 'locations',
  INCIDENT: 'incidents',
  INTELLIGENCE_ITEM: 'intelligenceItems',
  THREAT_ACTOR: 'threatActors',
  VULNERABILITY: 'vulnerabilities',
  MALWARE_TOOL: 'malwareTools',
  MITRE_MAPPING: 'mitreMappings',
  EXERCISE_CONSIDERATION: 'exerciseConsiderations',
  FORECAST: 'forecasts',
  SOURCE_REFERENCE: 'citations',
  // REPORT_ANALYSIS is handled separately — merged into the report record, not its own store.
};

export function parseReport(rawText) {
  const warnings = [];
  const importBlockText = extractImportBlock(rawText);
  if (importBlockText === null) {
    throw new Error(
      'No ===CTI_IMPORT_START===/===CTI_IMPORT_END=== block found. ' +
      'This file does not look like a report generated with the standard prompt.'
    );
  }

  const { topLevelFields, blocks } = walkBlocks(importBlockText);
  const reportIdRaw = topLevelFields.REPORT_ID;
  if (!reportIdRaw) {
    throw new Error('No REPORT_ID found at the top of the import block — cannot namespace any records.');
  }
  const reportId = reportIdRaw.trim();

  const recordsByStore = {
    threatRecords: [], locations: [], incidents: [], intelligenceItems: [],
    threatActors: [], vulnerabilities: [], malwareTools: [], mitreMappings: [],
    exerciseConsiderations: [], forecasts: [], citations: [],
  };

  let reportAnalysisRawFields = null;

  for (const block of blocks) {
    if (block.tag === 'REPORT_ANALYSIS') {
      reportAnalysisRawFields = block.fields;
      continue;
    }
    const storeName = BLOCK_TAG_TO_STORE[block.tag];
    if (!storeName) {
      warnings.push(`Unrecognised block type ===${block.tag}_START=== — skipped.`);
      continue;
    }
    switch (block.tag) {
      case 'THREAT_RECORD':
        recordsByStore.threatRecords.push(finalizeThreatRecord(block.fields, reportId, warnings));
        break;
      case 'LOCATION':
        recordsByStore.locations.push(finalizeLocation(block.fields, reportId, warnings));
        break;
      case 'INCIDENT':
        recordsByStore.incidents.push(finalizeIncident(block.fields, reportId));
        break;
      case 'INTELLIGENCE_ITEM':
        recordsByStore.intelligenceItems.push(finalizeIntelligenceItem(block.fields, reportId, warnings));
        break;
      case 'THREAT_ACTOR':
        recordsByStore.threatActors.push(finalizeThreatActor(block.fields, reportId, warnings));
        break;
      case 'VULNERABILITY':
        recordsByStore.vulnerabilities.push(finalizeVulnerability(block.fields, reportId, warnings));
        break;
      case 'MALWARE_TOOL':
        recordsByStore.malwareTools.push(finalizeMalwareTool(block.fields, reportId));
        break;
      case 'MITRE_MAPPING':
        recordsByStore.mitreMappings.push(finalizeMitreMapping(block.fields, reportId, warnings));
        break;
      case 'EXERCISE_CONSIDERATION':
        recordsByStore.exerciseConsiderations.push(finalizeExerciseConsideration(block.fields, reportId, warnings));
        break;
      case 'FORECAST':
        recordsByStore.forecasts.push(finalizeForecast(block.fields, reportId, warnings));
        break;
      case 'SOURCE_REFERENCE':
        recordsByStore.citations.push(finalizeCitation(block.fields, reportId));
        break;
      default:
        break;
    }
  }

  const reportRecord = finalizeReport(topLevelFields, reportAnalysisRawFields, reportId, warnings);
  recordsByStore.reports = [reportRecord];

  // Cross-reference validation pass — flags dangling FK references without blocking import.
  const knownIds = {};
  for (const [storeName, records] of Object.entries(recordsByStore)) {
    const idField = {
      threatRecords: 'threatId', locations: 'locationId', incidents: 'incidentId',
      intelligenceItems: 'itemId', threatActors: 'actorId', vulnerabilities: 'vulnerabilityId',
      malwareTools: 'malwareToolId', mitreMappings: 'mappingId',
      exerciseConsiderations: 'exerciseItemId', forecasts: 'forecastId', citations: 'citationId',
      reports: 'reportId',
    }[storeName];
    if (!idField) continue;
    knownIds[storeName] = new Set(records.map((r) => r[idField]));
  }

  for (const [storeName, records] of Object.entries(recordsByStore)) {
    for (const record of records) {
      for (const [fieldName, targetStore] of Object.entries(ID_FIELD_TARGET_STORE)) {
        if (!(fieldName in record)) continue;
        const value = record[fieldName];
        const ids = Array.isArray(value) ? value : (value ? [value] : []);
        const targetSet = knownIds[targetStore];
        if (!targetSet) continue;
        for (const id of ids) {
          if (typeof id === 'string' && id.includes('::') && !targetSet.has(id)) {
            warnings.push(
              `Unresolved reference: ${storeName}.${fieldName} points to "${id}", ` +
              `which has no matching record in ${targetStore}.`
            );
          }
        }
      }
    }
  }

  return { recordsByStore, warnings };
}

export { extractImportBlock, walkBlocks, mapRawFields }; // exported for targeted testing
