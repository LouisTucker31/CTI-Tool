# CTI Visualisation Tool — Data Schema Reference

**Version:** 1.0
**Based on:** CTI-20260727-UK-DEFENCE (both versions) — the two working sample reports.
**Purpose:** This is the single source of truth for every entity, field and rule the
storage layer and parser are built against. Any change to this doc should happen
*before* touching code, not after.

---

## 1. Global ID Convention

Every report generates its own local IDs (`TR-001`, `INT-004`, `ACT-002`, `S009`...).
Two different reports can and will reuse the same local ID for unrelated things.

**Rule:** at import time, every local ID is rewritten to a globally unique key:

```
{reportId}::{localId}
e.g. CTI-20260727-UK-DEFENCE::TR-001
```

All cross-references inside a report (e.g. a Threat Record's
`ASSOCIATED_THREAT_ACTORS: ACT-001|ACT-002`) get rewritten to the same namespaced
form at parse time, so nothing in storage ever relies on a bare local ID.

---

## 2. Normalization Rules (applied by the parser, not the prompt)

These exist so two reports that format things slightly differently (as our two
samples did) still land in storage identically.

| Issue seen | Rule applied |
|---|---|
| `CONFIDENCE_LABEL`/`SEVERITY_LABEL` written as `VERY_HIGH` in one report, `Very High` in another | **The numeric `*_SCORE` is authoritative.** The label string from the source is stored only as raw/original text (audit trail). The app derives its own display label from the score via a fixed lookup table — the source label is never trusted for logic or filtering. |
| Null tokens: `NONE`, `UNKNOWN`, occasional stray variants (`NONE_SPECIFICALLY_SELECTED`) | `NONE` → null (does not apply). `UNKNOWN` → null, but flagged as "unknown, not absent" for display (e.g. shows "Unknown" not blank). Any other unrecognised token → treated as `UNKNOWN` and logged as a parser warning on the Import Review screen. |
| Field name variants for the same concept (`ASSOCIATED_CLIENTS` / `RELEVANT_CLIENTS` / `CLIENT_TAGS`; `THREAT_ACTOR_IDS` / `THREAT_ACTOR_IDS_OR_NAMES`) | Parser accepts a known alias list per field and normalizes to one internal name. See §4 for the canonical name used in each entity. |
| Dates given as `2022`, `2024-07`, or `2025-09-19` | Precision is inferred from the string shape, not a separate field: 4 digits = `YEAR`, `YYYY-MM` = `MONTH`, full date = `EXACT`. (Locations already carry an explicit `LOCATION_PRECISION` field — that one is taken as-is.) |
| An ID reference (e.g. in `ASSOCIATED_THREAT_ACTORS`) with no matching entity block anywhere in the report | Kept as an unlinked plain-text tag rather than dropped or crashed on, and flagged on the Import Review screen so the user can see it wasn't linkable. |
| Pipe-separated multi-value fields (`TACTIC: CREDENTIAL_ACCESS|DISCOVERY`) | Parsed to an array. Any field documented below as "(array)" supports this. |

---

## 3. Entity Relationship Summary

```
Report (1)
 ├─ Citation (many)                         — the S001, S002... reference list
 ├─ ThreatRecord (many)
 │   ├─ Location (many)                     — typed: report scope / affected / actor / etc.
 │   ├─ IntelligenceItem (many)             — optionally tagged to one Incident
 │   ├─ Incident (many)                     — the "several incidents inside one threat" case
 │   ├─ ThreatActor (many)
 │   ├─ Vulnerability (many)
 │   ├─ MalwareTool (many)
 │   ├─ MitreMapping (many)                 — optionally tagged to one Incident
 │   └─ ExerciseConsideration (many)
 └─ Forecast (many)                         — spans one or more ThreatRecords, not nested under one
```

Everything ultimately traces back to a Report and at least one Citation — this
satisfies the "every displayed item must be traceable to a source" principle
from the original concept doc.

---

## 4. Entity Definitions

### 4.1 Report

The imported document itself.

| Field | Type | Notes |
|---|---|---|
| `reportId` | string (PK) | Local ID kept as-is at this level — it *is* the namespace root. |
| `schemaVersion` | string | |
| `reportTitle` | string | |
| `primaryLocation` | string | |
| `primarySector` | string | |
| `subsectors` | array | |
| `reportingPeriodStart` / `reportingPeriodEnd` | date | |
| `reportGenerationDate` / `researchDate` | date | |
| `researchMethod` | enum | `EXISTING_DOCUMENT_ANALYSIS \| NEW_ONLINE_RESEARCH \| COMBINED_RESEARCH` |
| `intendedUse` | string | |
| `namedClients` | array | |
| `relevantOrganisations` | array | |
| `technologiesOfInterest` | array | |
| `overallConfidenceScore` | int 1–4 | label derived, not stored from source |
| `threatRecordCount` / `incidentCount` / `forecastCount` | int | as declared by the report; the app also computes its own actual counts at import for a sanity-check diff |
| `executiveSummary` | text | the report's own summary — never overwritten by later imports |
| `reportAuthorSummary` | text | from `REPORT_AUTHOR_SUMMARY` — explicitly labelled in the UI as *this report's own analysis*, kept separate from the app's independently-calculated trend summary |
| `reportAnalysisRollup` | object | `{ mostCommonThreatCategories[], mostCommonAttackMethods[], mostCommonMitreTechniques[], mostActiveThreatActorIds[], mostAffectedLocations[], mostTargetedSectors[], mostSignificantVulnerabilityIds[], mostSignificantMalwareIds[], overallTrendDirection, keyExerciseThemes[] }` — same "author's own analysis" treatment |
| `originalFileName` / `originalFileRef` | string / blob ref | the source PDF/text, kept accessible |
| `importDate` | datetime | |
| `importStats` | object | `{ numberExtracted, numberApproved, numberRejected, numberDuplicates, numberEdited }` |
| `reportStatus` | string | e.g. `ACTIVE`, `ARCHIVED` |
| `changeHistory` | array | audit log entries |

### 4.2 ThreatRecord

| Field | Type | Notes |
|---|---|---|
| `threatId` | string (PK, namespaced) | |
| `parentReportId` | string (FK) | |
| `recordType` | enum | `CAMPAIGN \| INCIDENT_GROUP \| TREND \| VULNERABILITY_ACTIVITY` |
| `threatTitle` / `oneLineSummary` / `fullDescription` | string/text | |
| `threatCategory` | array | |
| `threatStatus` | enum | `NEW \| ACTIVE \| ONGOING \| ESCALATING \| STABLE \| DECLINING \| RESOLVED \| HISTORICAL \| UNKNOWN` |
| `trendDirection` | enum | `INCREASING \| DECREASING \| STABLE \| EMERGING \| IRREGULAR \| UNKNOWN` |
| `severityScore` (1–5) / `severityRationale` | int / text | label derived from score |
| `confidenceScore` (1–4) / `confidenceRationale` | int / text | label derived from score |
| `firstObservedDate` + precision / `lastObservedDate` + precision | date | |
| `primarySector` / `additionalSectors` | string / array | |
| `clientTags` | array | canonical name — aliases `ASSOCIATED_CLIENTS`/`RELEVANT_CLIENTS` map here |
| `associatedOrganisations` | array (free text) | |
| `associatedThreatActorIds` | array (FK, may include unresolved tags per §2) | |
| `attackMethods` / `tags` | array (free text) | |
| `malwareToolIds` / `vulnerabilityIds` | array (FK) | |
| `sourceCitationIds` | array (FK) | |

### 4.3 Location (child of ThreatRecord)

| Field | Type | Notes |
|---|---|---|
| `locationId` | string (PK, namespaced) | |
| `parentThreatId` | string (FK) | |
| `locationType` | enum | `REPORT_SCOPE \| AFFECTED_LOCATION \| VICTIM_ORGANISATION \| THREAT_ACTOR \| SUSPECTED_ORIGIN \| INFRASTRUCTURE \| COMMAND_AND_CONTROL \| DATA_HOSTING \| UNKNOWN` |
| `country` / `region` / `city` | string | |
| `latitude` / `longitude` | float, nullable | present when precision is `CITY` and the place is unambiguous (named airport, capital, etc.) |
| `locationPrecision` | enum | `COUNTRY \| REGION \| CITY \| COORDINATES \| UNKNOWN` |
| `locationConfidenceScore` | int 1–4 | label derived |
| `locationExplanation` | text | |
| `sourceCitationIds` | array (FK) | |

### 4.4 Incident (child of ThreatRecord)

| Field | Type | Notes |
|---|---|---|
| `incidentId` | string (PK, namespaced) | |
| `parentThreatId` | string (FK) | |
| `incidentTitle` | string | |
| `incidentDate` / `firstObservedDate` / `lastObservedDate` | date | |
| `affectedOrganisation` / `affectedSector` | string | |
| `affectedLocationIds` | array (FK → Location) | |
| `threatActorIds` | array (FK) | canonical name — alias `THREAT_ACTOR_IDS_OR_NAMES` maps here |
| `attackMethods` | array | |
| `impactSummary` | text | |
| `severityScore` / `confidenceScore` | int | labels derived |
| `sourceCitationIds` | array (FK) | |

### 4.5 IntelligenceItem (child of ThreatRecord, optionally tagged to an Incident)

The atomic, independently-displayable statistic/observation.

| Field | Type | Notes |
|---|---|---|
| `itemId` | string (PK, namespaced) | |
| `parentThreatId` | string (FK) | |
| `associatedIncidentIds` | array (FK, nullable) | |
| `itemType` | enum | `STATISTIC \| OBSERVATION \| LOCATION_DETAIL \| ATTACK_METHOD \| DATA_IMPACT \| OPERATIONAL_IMPACT \| SAFETY_IMPACT \| FINANCIAL_IMPACT \| VULNERABILITY \| MALWARE \| FORECAST_NOTE \| CLIENT_RELEVANCE` |
| `itemTitle` / `itemText` | string/text | |
| `itemDate` + `itemPeriodStart` / `itemPeriodEnd` | date | |
| `numericalValue` / `valueUnit` | float / string, nullable | this is what feeds charts directly |
| `comparisonValue` + `comparisonPeriodStart/End` / `percentageChange` | nullable | supports "vs previous period" chart annotations |
| `associatedLocationIds` | array (FK) | |
| `clientTags` | array | |
| `confidenceScore` | int 1–4 | label derived |
| `sourceCitationIds` | array (FK) | |
| `limitations` | text | shown alongside the item so caveats travel with the stat, not just the parent threat |

### 4.6 ThreatActor (child of ThreatRecord)

| Field | Type | Notes |
|---|---|---|
| `actorId` | string (PK, namespaced) | |
| `parentThreatId` | string (FK) | |
| `actorName` / `aliases` | string / array | |
| `actorType` / `suspectedAffiliation` | string / array | |
| `attributionStatus` | enum | `CONFIRMED \| ASSESSED \| SUSPECTED \| UNKNOWN` |
| `attributionConfidenceScore` | int 1–4 | label derived |
| `actorLocationIds` | array (FK → Location) | |
| `supportingEvidence` | text | |
| `sourceCitationIds` | array (FK) | |

### 4.7 Vulnerability (child of ThreatRecord)

| Field | Type | Notes |
|---|---|---|
| `vulnerabilityId` | string (PK, namespaced) | |
| `parentThreatId` | string (FK) | |
| `cveId` | string | primary duplicate-detection key across reports later |
| `vulnerabilityName` / `product` (array) / `vendor` | string | |
| `exploitationStatus` | enum | `EXPLOITED \| EXPLOITED_IN_REPORTED_INCIDENTS \| NO_KNOWN_PUBLIC_EXPLOITATION \| UNKNOWN` |
| `firstExploitedDate` | date, nullable | |
| `associatedIncidentIds` | array (FK) | |
| `severityScore` / `confidenceScore` | int | labels derived |
| `sourceCitationIds` | array (FK) | |

### 4.8 MalwareTool (child of ThreatRecord)

| Field | Type | Notes |
|---|---|---|
| `malwareToolId` | string (PK, namespaced) | |
| `parentThreatId` | string (FK) | |
| `name` / `type` / `purpose` (array) | string | |
| `associatedActorIds` / `associatedIncidentIds` | array (FK) | |
| `confidenceScore` | int 1–4 | label derived |
| `sourceCitationIds` | array (FK) | |

### 4.9 MitreMapping (child of ThreatRecord, optionally tagged to an Incident)

| Field | Type | Notes |
|---|---|---|
| `mappingId` | string (PK, namespaced) | |
| `parentThreatId` | string (FK) | |
| `associatedIncidentIds` | array (FK, nullable) | |
| `techniqueId` / `techniqueName` | string | e.g. `T1190` |
| `tactic` | array | pipe-separated in source when a technique spans tactics |
| `mappingType` | enum | `EXPLICIT \| INFERRED` |
| `mappingConfidenceScore` | int 1–4 | label derived |
| `supportingEvidence` | text | |
| `sourceCitationIds` | array (FK) | |

### 4.10 ExerciseConsideration (child of ThreatRecord)

| Field | Type | Notes |
|---|---|---|
| `exerciseItemId` | string (PK, namespaced) | |
| `parentThreatId` | string (FK) | |
| `considerationType` | enum | `SCENARIO_THEME \| DECISION_POINT \| COMMUNICATIONS_CHALLENGE \| SUPPLY_CHAIN_CHALLENGE \| REGULATORY_CHALLENGE` |
| `title` / `description` | string/text | |
| `clientTags` / `relevantSectors` / `relevantTechnologies` / `relevantDepartments` | array | |
| `associatedIncidentIds` / `associatedMitreMappingIds` | array (FK) | |
| `exerciseRelevanceConfidenceScore` | int 1–4 | label derived |
| `sourceCitationIds` | array (FK) | |

### 4.11 Forecast (top-level — spans one or more ThreatRecords)

| Field | Type | Notes |
|---|---|---|
| `forecastId` | string (PK, namespaced) | |
| `parentThreatIds` | array (FK) | plural — not nested under a single threat |
| `forecastTitle` / `forecastDescription` | string/text | |
| `forecastCreationDate` / `forecastStartDate` / `forecastExpiryDate` | date | |
| `predictedLocations` / `predictedSectors` / `predictedThreatType` | array | |
| `forecastStatus` | enum, **app-managed lifecycle** | Import always sets `UPCOMING` or `ACTIVE`. The app transitions it to `EXPIRED` automatically once `forecastExpiryDate` passes, and the user can manually set `CONFIRMED \| PARTIALLY_CONFIRMED \| DISPROVED \| WITHDRAWN`. Never auto-deleted. |
| `confidenceScore` | int 1–4 | label derived |
| `supportingEvidence` | text | |
| `supportingIntelligenceItemIds` | array (FK) | |
| `conditionsSupporting` / `conditionsUndermining` | array | |
| `clientTags` | array | |
| `sourceCitationIds` | array (FK) | |

### 4.12 Citation (top-level — the report's own reference list, S001, S002...)

| Field | Type | Notes |
|---|---|---|
| `citationId` | string (PK, namespaced) | |
| `parentReportId` | string (FK) | |
| `sourceTitle` / `sourcePublisher` | string | |
| `sourcePublicationDate` + precision | date | |
| `sourceType` | string | |
| `sourceUrlOrDocumentName` | string | |
| `dateAccessed` | date | |
| `relevantThreatIds` | array (FK) | |
| `sourceQualityNotes` | text | |

---

## 5. Proposed IndexedDB Object Stores

One store per entity above, all keyed on their namespaced ID:

| Store | Key path | Suggested indexes |
|---|---|---|
| `reports` | `reportId` | `primarySector`, `primaryLocation`, `importDate` |
| `threatRecords` | `threatId` | `parentReportId`, `primarySector`, `threatStatus`, `severityScore`, `clientTags` (multi-entry) |
| `locations` | `locationId` | `parentThreatId`, `locationType`, `country` |
| `incidents` | `incidentId` | `parentThreatId`, `incidentDate` |
| `intelligenceItems` | `itemId` | `parentThreatId`, `associatedIncidentIds` (multi-entry), `itemType`, `itemDate` |
| `threatActors` | `actorId` | `parentThreatId`, `actorName` |
| `vulnerabilities` | `vulnerabilityId` | `parentThreatId`, `cveId` (for later cross-report duplicate detection) |
| `malwareTools` | `malwareToolId` | `parentThreatId` |
| `mitreMappings` | `mappingId` | `parentThreatId`, `techniqueId` |
| `exerciseConsiderations` | `exerciseItemId` | `parentThreatId`, `considerationType` |
| `forecasts` | `forecastId` | `parentThreatIds` (multi-entry), `forecastStatus`, `forecastExpiryDate` |
| `citations` | `citationId` | `parentReportId` |
| `clients` | `clientName` | (manual entity — name, sector, locations, notes; not part of the import format) |
| `auditLog` | auto-increment | `targetId`, `timestamp` |

`clientTags` fields across entities are stored as arrays of plain client-name
strings, not foreign keys to the `clients` store — this matches the concept
principle that client tagging is manual and a client record can exist even
before any threat mentions it (or vice versa).

---

## 6. Deliberately Deferred to Later Phases

Not schema gaps — just not needed to unblock the storage layer build:

- **Cross-report duplicate detection logic** (matching rules, merge UI). The
  schema supports it (`cveId` index, title/date matching potential) but the
  matching algorithm itself is a Phase 2 import-pipeline concern.
- **Client entity management UI** — the `clients` store above is minimal for now.
- **Forecast lifecycle automation** (the expiry-check job) — scheduling logic,
  not schema.
- **Global Threat Score calculation** — reads across all these stores but is
  its own weighted-rules module, built once real data exists to test against.
