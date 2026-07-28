/**
 * helpers.js — small display helpers shared across app.js and every
 * js/widgets/*.js file. Nothing here touches storage — pure formatting only.
 */

const SEVERITY_KEY_BY_LABEL = {
  Critical: 'critical',
  High: 'high',
  Moderate: 'moderate',
  Low: 'low',
  Informational: 'informational',
};

export function severityChip({ severityLabel, confidenceLabel }) {
  const key = SEVERITY_KEY_BY_LABEL[severityLabel] || 'informational';
  const solid = confidenceLabel === 'Very High' ? ' confidence-solid' : '';
  const title = `Confidence: ${confidenceLabel || 'Unknown'}`;
  return `<span class="severity-chip severity-${key}${solid}" title="${title}">${severityLabel || 'Unrated'}</span>`;
}

export function citeChip(citationIds) {
  const count = (citationIds || []).length;
  if (count === 0) return '';
  return `<span class="cite-chip" title="${count} source${count === 1 ? '' : 's'} cited">[${count} source${count === 1 ? '' : 's'}]</span>`;
}

export function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}

/** DEFENCE_SUPPLY_CHAIN -> "Defence Supply Chain". Display-only — never touches stored data. */
export function humanize(token) {
  if (!token) return token;
  return token
    .split('_')
    .join(' ')
    .toLowerCase()
    .replace(/(^|[\s-])([a-z])/g, (match, sep, letter) => sep + letter.toUpperCase());
}

/** Maps a severity label to the raw colour token used for map markers etc. (not a CSS class). */
export const SEVERITY_COLOR_VAR = {
  Critical: '--accent-critical',
  High: '--accent-high',
  Moderate: '--accent-moderate',
  Low: '--accent-low',
  Informational: '--accent-informational',
};

/**
 * YYYY-MM-DD -> DD/MM/YYYY, YYYY-MM -> MM/YYYY, YYYY -> YYYY, unchanged otherwise.
 * Display-only — every date stays stored/compared as ISO (YYYY-MM-DD etc.)
 * everywhere else; this only reformats what's shown to the person.
 */
export function formatDateUK(dateStr) {
  if (!dateStr || dateStr === 'Unknown') return 'Unknown';
  const full = dateStr.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (full) {
    const [, y, m, d] = full;
    return `${d}/${m}/${y}`;
  }
  const monthOnly = dateStr.match(/^(\d{4})-(\d{2})$/);
  if (monthOnly) {
    const [, y, m] = monthOnly;
    return `${m}/${y}`;
  }
  if (/^\d{4}$/.test(dateStr)) return dateStr;
  return dateStr; // unexpected shape — show as-is rather than mangle it
}