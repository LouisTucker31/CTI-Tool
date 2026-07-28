/**
 * widgets/map.js — the World Map widget (Leaflet).
 *
 * Two marker categories only, matching the concept doc: affected locations
 * and threat-actor locations. Everything else (REPORT_SCOPE, INFRASTRUCTURE,
 * etc.) is left off the map for now — those are scope/meta information, not
 * "something happened here" points, and would just add clutter.
 *
 * Encoding:
 *   - Shape: circle = affected location, diamond = threat-actor location.
 *   - Colour: highest severity among the threats plotted at that point,
 *     reusing the dashboard's own severity ramp (not a separate palette).
 *   - Size: how many distinct threat records reference that point.
 *
 * Locations with real coordinates (a handful of named cities in this data)
 * use them directly. Everything else is country-precision, so it's placed
 * at that country's centroid from COUNTRY_CENTROIDS below — deliberately a
 * lookup, not a guess: if a country token isn't in the table, that location
 * is left off the map and counted in the "couldn't be plotted" note rather
 * than inventing a position for it.
 *
 * The data-aggregation logic (groupLocationsForMap) is kept separate from
 * the actual Leaflet drawing (renderWorldMap) on purpose — it's the part
 * most likely to have real bugs, and it's plain data-in/data-out, so it can
 * be unit tested without needing a browser or a live map.
 */

import { dbGetAll } from '../db.js';
import { escapeHtml, severityChip, citeChip, humanize } from '../helpers.js';

// ---------------------------------------------------------------------------
// Country centroids (approximate — good enough for a country-level dot,
// not meant to be precise). Add more here as new reports bring new countries.
// ---------------------------------------------------------------------------

export const COUNTRY_CENTROIDS = {
  UNITED_KINGDOM: [54.0, -2.5], IRELAND: [53.4, -8.0], UNITED_STATES: [39.8, -98.6],
  CANADA: [56.1, -106.3], RUSSIA: [61.5, 105.3], CHINA: [35.9, 104.2],
  NORTH_KOREA: [40.3, 127.5], SOUTH_KOREA: [36.5, 127.9], JAPAN: [36.2, 138.3],
  IRAN: [32.4, 53.7], IRAQ: [33.2, 43.7], SYRIA: [34.8, 39.0], ISRAEL: [31.0, 34.9],
  SAUDI_ARABIA: [24.0, 45.0], UNITED_ARAB_EMIRATES: [23.4, 53.8], QATAR: [25.4, 51.2],
  KUWAIT: [29.3, 47.5], JORDAN: [30.6, 36.2], LEBANON: [33.9, 35.9], TURKEY: [39.0, 35.2],
  EGYPT: [26.8, 30.8], LIBYA: [26.3, 17.2], MOROCCO: [31.8, -7.1], ALGERIA: [28.0, 1.7],
  TUNISIA: [33.9, 9.5], NIGERIA: [9.1, 8.7], KENYA: [-0.0, 37.9], ETHIOPIA: [9.1, 40.5],
  SOUTH_AFRICA: [-30.6, 22.9], GERMANY: [51.2, 10.5], FRANCE: [46.6, 2.2],
  BELGIUM: [50.5, 4.5], NETHERLANDS: [52.1, 5.3], SPAIN: [40.5, -3.7], PORTUGAL: [39.4, -8.2],
  ITALY: [42.8, 12.6], SWITZERLAND: [46.8, 8.2], AUSTRIA: [47.5, 14.6], POLAND: [51.9, 19.1],
  UKRAINE: [48.4, 31.2], BELARUS: [53.7, 27.9], ROMANIA: [45.9, 25.0], BULGARIA: [42.7, 25.5],
  HUNGARY: [47.2, 19.5], CZECH_REPUBLIC: [49.8, 15.5], SLOVAKIA: [48.7, 19.7],
  SLOVENIA: [46.2, 15.0], CROATIA: [45.1, 15.2], SERBIA: [44.0, 21.0], GREECE: [39.1, 21.8],
  SWEDEN: [60.1, 18.6], NORWAY: [60.5, 8.5], FINLAND: [64.0, 26.0], DENMARK: [56.3, 9.5],
  ICELAND: [64.9, -19.0], ESTONIA: [58.6, 25.0], LATVIA: [56.9, 24.6], LITHUANIA: [55.2, 23.9],
  LUXEMBOURG: [49.8, 6.1], MALTA: [35.9, 14.4], CYPRUS: [35.1, 33.4],
  INDIA: [22.0, 79.0], PAKISTAN: [30.4, 69.3], BANGLADESH: [23.7, 90.4],
  AFGHANISTAN: [33.9, 67.7], KAZAKHSTAN: [48.0, 66.9], INDONESIA: [-0.8, 113.9],
  VIETNAM: [14.1, 108.3], THAILAND: [15.9, 100.9], PHILIPPINES: [12.9, 121.8],
  MALAYSIA: [4.2, 101.9], SINGAPORE: [1.35, 103.8], TAIWAN: [23.7, 121.0],
  HONG_KONG: [22.3, 114.2], AUSTRALIA: [-25.3, 133.8], NEW_ZEALAND: [-41.5, 172.8],
  BRAZIL: [-14.2, -51.9], ARGENTINA: [-38.4, -63.6], CHILE: [-35.7, -71.5],
  COLOMBIA: [4.6, -74.3], PERU: [-9.2, -75.0], VENEZUELA: [6.4, -66.6],
  MEXICO: [23.6, -102.5], CUBA: [21.5, -77.8],
};

// ---------------------------------------------------------------------------
// Pure data-aggregation logic — no DOM, no Leaflet, fully unit-testable
// ---------------------------------------------------------------------------

const AFFECTED_TYPES = new Set(['AFFECTED_LOCATION', 'VICTIM_ORGANISATION']);
const ACTOR_TYPES = new Set(['THREAT_ACTOR', 'SUSPECTED_ORIGIN']);

/** Picks the first value that's neither null nor our "Unknown" display sentinel. */
function firstKnownValue(...values) {
  for (const v of values) {
    if (v && v !== 'Unknown') return v;
  }
  return null;
}

/**
 * Turns raw location + threatRecord rows into map-ready marker groups.
 * @returns {{ markers: Array, unmapped: Array }}
 *   markers: [{ bucket, lat, lng, count, severityLabel, place, threats: [{title, severityLabel, confidenceLabel, sourceCitationIds}] }]
 *   unmapped: location records that couldn't be placed on the map (no coordinates, unrecognised country)
 */
export function groupLocationsForMap(locations, threatRecords) {
  const threatById = new Map(threatRecords.map((t) => [t.threatId, t]));
  const groups = new Map(); // key -> { bucket, lat, lng, place, threatIds: Set }
  const unmapped = [];

  for (const loc of locations) {
    const bucket = AFFECTED_TYPES.has(loc.locationType) ? 'affected'
      : ACTOR_TYPES.has(loc.locationType) ? 'actor'
      : null;
    if (!bucket) continue; // REPORT_SCOPE and other meta-location types are excluded by design

    let lat = loc.latitude;
    let lng = loc.longitude;
    if (lat == null || lng == null) {
      const centroid = loc.country ? COUNTRY_CENTROIDS[loc.country] : null;
      if (!centroid) {
        unmapped.push(loc);
        continue;
      }
      [lat, lng] = centroid;
    }

    const key = `${bucket}:${lat.toFixed(1)}:${lng.toFixed(1)}`;
    if (!groups.has(key)) {
      groups.set(key, {
        bucket, lat, lng,
        place: humanize(firstKnownValue(loc.city, loc.country)) || 'Unknown location',
        threatIds: new Set(),
      });
    }
    if (loc.parentThreatId) groups.get(key).threatIds.add(loc.parentThreatId);
  }

  const markers = [...groups.values()].map((group) => {
    const threats = [...group.threatIds]
      .map((id) => threatById.get(id))
      .filter(Boolean);
    const highestSeverityScore = threats.reduce((max, t) => Math.max(max, t.severityScore || 0), 0);
    const highestSeverityThreat = threats.find((t) => (t.severityScore || 0) === highestSeverityScore);
    return {
      bucket: group.bucket,
      lat: group.lat,
      lng: group.lng,
      place: group.place,
      count: threats.length,
      severityLabel: highestSeverityThreat ? highestSeverityThreat.severityLabel : 'Informational',
      threats: threats.map((t) => ({
        title: t.threatTitle,
        severityLabel: t.severityLabel,
        confidenceLabel: t.confidenceLabel,
        sourceCitationIds: t.sourceCitationIds,
      })),
    };
  }).filter((m) => m.count > 0);

  return { markers, unmapped };
}

// ---------------------------------------------------------------------------
// Leaflet rendering
// ---------------------------------------------------------------------------

function markerRadius(count) {
  return Math.min(4 + Math.sqrt(count) * 2.5, 16);
}

const MARKER_TYPE_COLOR_VAR = {
  affected: '--accent-high',    // orange
  actor: '--accent-critical',   // red
};

function markerTypeColor(bucket) {
  const varName = MARKER_TYPE_COLOR_VAR[bucket] || MARKER_TYPE_COLOR_VAR.affected;
  return getComputedStyle(document.documentElement).getPropertyValue(varName).trim() || '#cc6a2e';
}

function tooltipHtml(marker) {
  const bucketLabel = marker.bucket === 'affected' ? 'Affected location' : 'Threat-actor location';
  return `
    <div class="map-tooltip">
      <div class="map-tooltip-title">
        <span class="map-tooltip-swatch map-tooltip-${marker.bucket}"></span>${escapeHtml(marker.place)}
      </div>
      <div class="map-tooltip-meta">${bucketLabel} &middot; ${marker.count} threat${marker.count === 1 ? '' : 's'}</div>
    </div>
  `;
}

function popupHtml(marker) {
  const bucketLabel = marker.bucket === 'affected' ? 'Affected location' : 'Threat-actor location';
  const threatsHtml = marker.threats.slice(0, 6).map((t) => `
    <div class="map-popup-threat">
      ${severityChip(t)} ${citeChip(t.sourceCitationIds)}
      <div>${escapeHtml(t.title)}</div>
    </div>
  `).join('');
  const more = marker.threats.length > 6 ? `<p class="map-popup-more">+ ${marker.threats.length - 6} more</p>` : '';

  return `
    <div class="map-popup">
      <p class="map-popup-title">
        <span class="map-tooltip-swatch map-tooltip-${marker.bucket}"></span>${escapeHtml(marker.place)}
      </p>
      <p class="map-popup-meta">${bucketLabel} &middot; ${marker.count} threat${marker.count === 1 ? '' : 's'}</p>
      ${threatsHtml}
      ${more}
    </div>
  `;
}

export async function renderWorldMap(container) {
  const [locations, threatRecords] = await Promise.all([
    dbGetAll('locations'),
    dbGetAll('threatRecords'),
  ]);

  if (locations.length === 0) {
    container.innerHTML = '<p class="tile-placeholder-note">No reports imported yet. Use "Import report" above to load one.</p>';
    return;
  }

  const { markers, unmapped } = groupLocationsForMap(locations, threatRecords);

  container.classList.add('tile-body-map');
  container.innerHTML = `
    <div class="map-canvas" id="map-canvas-${Date.now()}"></div>
    <div class="map-legend">
      <span><span class="map-legend-swatch map-legend-circle"></span> Affected</span>
      <span><span class="map-legend-swatch map-legend-diamond"></span> Threat actor</span>
      <span class="map-legend-note">Size = number of threats &middot; colour = highest severity there</span>
    </div>
    ${unmapped.length > 0
      ? `<p class="map-unmapped-note">${unmapped.length} location${unmapped.length === 1 ? '' : 's'} couldn't be placed on the map (no recognised country/coordinates).</p>`
      : ''}
  `;

  const mapEl = container.querySelector('.map-canvas');
  const worldBounds = L.latLngBounds([-85, -180], [85, 180]);
  const map = L.map(mapEl, {
    scrollWheelZoom: false,
    minZoom: 2,
    maxBounds: worldBounds,
    maxBoundsViscosity: 1.0,
  }).setView([20, 10], 2);
  map.attributionControl.setPrefix(false); // drop Leaflet's own self-link, keep only the required credits below

  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
    subdomains: 'abcd',
    maxZoom: 19,
    noWrap: true,
  }).addTo(map);

  markers.forEach((marker) => {
    const color = markerTypeColor(marker.bucket);
    const radius = markerRadius(marker.count);
    let layer;

    if (marker.bucket === 'affected') {
      layer = L.circleMarker([marker.lat, marker.lng], {
        radius,
        color,
        fillColor: color,
        fillOpacity: 0.65,
        weight: 1.5,
      });
    } else {
      const side = radius * 1.6;
      const icon = L.divIcon({
        className: 'map-diamond-icon',
        html: `<span style="width:${side}px; height:${side}px; background:${color};"></span>`,
        iconSize: [side, side],
      });
      layer = L.marker([marker.lat, marker.lng], { icon });
    }

    layer.bindTooltip(tooltipHtml(marker));
    layer.bindPopup(popupHtml(marker));
    layer.addTo(map);
  });

  // Leaflet measures its container's width/height once at creation time. This
  // tile sits in a CSS grid and fades in on an animation, and the dashboard's
  // custom web fonts can still be loading, so that first measurement is
  // sometimes taken before layout has fully settled — the usual symptom is
  // exactly what showed up here: correct height, but blank strips down the
  // sides because Leaflet thinks the container is narrower than it really is.
  // Re-measuring shortly after, and again on any future resize, fixes it.
  requestAnimationFrame(() => map.invalidateSize());
  setTimeout(() => map.invalidateSize(), 300);
  new ResizeObserver(() => map.invalidateSize()).observe(mapEl);
}