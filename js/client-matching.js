/**
 * client-matching.js — suggesting which threats might be relevant to a
 * manually-defined client, based on sector/location overlap.
 *
 * Deliberately NOT the same thing as the existing exact clientTags match
 * (in client-relevance.js) — a shared sector or location is a much weaker
 * signal than a report explicitly naming the client, so this is kept as a
 * clearly separate, clearly-labelled suggestion rather than merged into
 * "confirmed" relevance. This mirrors a principle already written into the
 * report-generation prompt itself: sector similarity alone is not evidence
 * of client relevance, just a reason to go and check.
 *
 * Name matching for the *exact* tier normalizes both sides (uppercase,
 * spaces/hyphens collapsed to underscores) and allows a "contains" match
 * either direction — reports tag clients in an ALL_CAPS_UNDERSCORE
 * convention (e.g. ROLLS-ROYCE_HOLDINGS_PLC) while a client typed here
 * will usually look like "Rolls-Royce" — exact equality alone would miss
 * almost every real match.
 */

function normalize(value) {
  return (value || '').toUpperCase().replace(/[\s-]+/g, '_');
}

function splitList(value) {
  return (value || '').split(',').map((s) => s.trim()).filter(Boolean);
}

function looseContains(haystack, needle) {
  const a = normalize(haystack);
  const b = normalize(needle);
  if (!a || !b) return false;
  return a.includes(b) || b.includes(a);
}

export function namesLooselyMatch(clientName, tag) {
  return looseContains(clientName, tag);
}

/**
 * Threats/considerations explicitly tagged to this client (clientTags),
 * using loose name matching rather than requiring an exact string match.
 */
export function findExactlyTaggedThreats(client, threatRecords) {
  return threatRecords.filter((t) =>
    (t.clientTags || []).some((tag) => namesLooselyMatch(client.name, tag))
  );
}

export function findExactlyTaggedConsiderations(client, exerciseConsiderations) {
  return exerciseConsiderations.filter((c) =>
    (c.clientTags || []).some((tag) => namesLooselyMatch(client.name, tag))
  );
}

/**
 * Threats NOT already exactly tagged to this client, but sharing its
 * sector, location, a named technology/system, or a named supplier —
 * returned with the specific reason(s) so the person can judge whether
 * the overlap actually means anything.
 *
 * @param locationsByThreatId Map<threatId, Array<location>>
 * @param vulnerabilitiesByThreatId Map<threatId, Array<vulnerability>>
 *   Both grouped by parentThreatId ahead of time, so this stays a pure,
 *   easily-testable function with no DB access of its own.
 */
export function findPossiblyRelevantThreats(client, threatRecords, locationsByThreatId, vulnerabilitiesByThreatId, excludeThreatIds) {
  const clientSector = normalize(client.sector);
  const clientLocation = normalize(client.location);
  const clientTechs = splitList(client.technologies);
  const clientSuppliers = splitList(client.suppliers);
  const matches = [];

  for (const t of threatRecords) {
    if (excludeThreatIds.has(t.threatId)) continue;

    const reasons = [];

    const sectorMatches = clientSector && (
      t.primarySector === clientSector ||
      t.primarySector === 'ALL' ||
      (t.additionalSectors || []).includes(clientSector)
    );
    if (sectorMatches) reasons.push('sector');

    const locations = locationsByThreatId.get(t.threatId) || [];
    const locationMatches = clientLocation && locations.some((loc) => loc.country === clientLocation);
    if (locationMatches) reasons.push('location');

    if (clientTechs.length > 0) {
      const vulns = vulnerabilitiesByThreatId.get(t.threatId) || [];
      const techMatches = vulns.some((v) =>
        clientTechs.some((tech) =>
          (v.vendor && looseContains(v.vendor, tech)) ||
          (v.product || []).some((p) => looseContains(p, tech))
        )
      );
      if (techMatches) reasons.push('technology');
    }

    if (clientSuppliers.length > 0) {
      const supplierMatches = (t.associatedOrganisations || []).some((org) =>
        clientSuppliers.some((sup) => looseContains(org, sup))
      );
      if (supplierMatches) reasons.push('supplier');
    }

    if (reasons.length > 0) {
      matches.push({ threat: t, reasons });
    }
  }

  return matches;
}
