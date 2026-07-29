/**
 * db.js — IndexedDB storage layer for the CTI Visualisation Tool.
 *
 * This file is purely mechanical storage plumbing. It knows nothing about
 * threats, reports or MITRE techniques specifically — it just knows how to
 * open the database, define the stores/indexes from the schema doc, and
 * offer generic get/put/delete/bulk-write helpers that everything else
 * (the parser, the import review screen, the widgets) builds on top of.
 *
 * See docs/schema.md section 5 for the store/index design this mirrors.
 *
 * IMPORTANT: if you add or change a store or index below, you MUST bump
 * DB_VERSION, or the browser will keep using the old structure and your
 * change will silently not apply. onupgradeneeded only fires when the
 * version number goes up.
 */

// ---------------------------------------------------------------------------
// Database identity and store/index definitions
// ---------------------------------------------------------------------------

const DB_NAME = 'cti-visualisation-tool';
const DB_VERSION = 1;

const STORE_DEFINITIONS = [
  {
    name: 'reports',
    keyPath: 'reportId',
    indexes: [
      { name: 'primarySector', keyPath: 'primarySector' },
      { name: 'primaryLocation', keyPath: 'primaryLocation' },
      { name: 'importDate', keyPath: 'importDate' },
    ],
  },
  {
    name: 'threatRecords',
    keyPath: 'threatId',
    indexes: [
      { name: 'parentReportId', keyPath: 'parentReportId' },
      { name: 'primarySector', keyPath: 'primarySector' },
      { name: 'threatStatus', keyPath: 'threatStatus' },
      { name: 'severityScore', keyPath: 'severityScore' },
      { name: 'clientTags', keyPath: 'clientTags', multiEntry: true },
    ],
  },
  {
    name: 'locations',
    keyPath: 'locationId',
    indexes: [
      { name: 'parentThreatId', keyPath: 'parentThreatId' },
      { name: 'locationType', keyPath: 'locationType' },
      { name: 'country', keyPath: 'country' },
    ],
  },
  {
    name: 'incidents',
    keyPath: 'incidentId',
    indexes: [
      { name: 'parentThreatId', keyPath: 'parentThreatId' },
      { name: 'incidentDate', keyPath: 'incidentDate' },
    ],
  },
  {
    name: 'intelligenceItems',
    keyPath: 'itemId',
    indexes: [
      { name: 'parentThreatId', keyPath: 'parentThreatId' },
      { name: 'associatedIncidentIds', keyPath: 'associatedIncidentIds', multiEntry: true },
      { name: 'itemType', keyPath: 'itemType' },
      { name: 'itemDate', keyPath: 'itemDate' },
    ],
  },
  {
    name: 'threatActors',
    keyPath: 'actorId',
    indexes: [
      { name: 'parentThreatId', keyPath: 'parentThreatId' },
      { name: 'actorName', keyPath: 'actorName' },
    ],
  },
  {
    name: 'vulnerabilities',
    keyPath: 'vulnerabilityId',
    indexes: [
      { name: 'parentThreatId', keyPath: 'parentThreatId' },
      { name: 'cveId', keyPath: 'cveId' },
    ],
  },
  {
    name: 'malwareTools',
    keyPath: 'malwareToolId',
    indexes: [
      { name: 'parentThreatId', keyPath: 'parentThreatId' },
    ],
  },
  {
    name: 'mitreMappings',
    keyPath: 'mappingId',
    indexes: [
      { name: 'parentThreatId', keyPath: 'parentThreatId' },
      { name: 'techniqueId', keyPath: 'techniqueId' },
    ],
  },
  {
    name: 'exerciseConsiderations',
    keyPath: 'exerciseItemId',
    indexes: [
      { name: 'parentThreatId', keyPath: 'parentThreatId' },
      { name: 'considerationType', keyPath: 'considerationType' },
    ],
  },
  {
    name: 'forecasts',
    keyPath: 'forecastId',
    indexes: [
      { name: 'parentThreatIds', keyPath: 'parentThreatIds', multiEntry: true },
      { name: 'forecastStatus', keyPath: 'forecastStatus' },
      { name: 'forecastExpiryDate', keyPath: 'forecastExpiryDate' },
    ],
  },
  {
    name: 'citations',
    keyPath: 'citationId',
    indexes: [
      { name: 'parentReportId', keyPath: 'parentReportId' },
    ],
  },
  {
    name: 'clients',
    keyPath: 'clientName',
    indexes: [],
  },
  {
    name: 'auditLog',
    keyPath: 'id',
    autoIncrement: true,
    indexes: [
      { name: 'targetId', keyPath: 'targetId' },
      { name: 'timestamp', keyPath: 'timestamp' },
    ],
  },
];

const STORE_NAMES = STORE_DEFINITIONS.map((def) => def.name);

// ---------------------------------------------------------------------------
// Opening the database (creates/upgrades stores on first run or version bump)
// ---------------------------------------------------------------------------

let dbInstance = null;
let dbOpenPromise = null;

export function openDB() {
  if (dbInstance) return Promise.resolve(dbInstance);
  // Multiple widgets can call openDB() nearly simultaneously (e.g. via
  // Promise.all in a widget's render function) before the first indexedDB.open()
  // call has resolved. Without memoizing the in-flight promise itself, each of
  // those concurrent calls would independently open its own connection — only
  // the last one ends up tracked in dbInstance, and the others stay open and
  // untracked, which can later block deleteDatabase() (used by resetDatabase()
  // and backup restore) with a "blocked" error since something still holds a
  // live connection open.
  if (dbOpenPromise) return dbOpenPromise;

  dbOpenPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      for (const storeDef of STORE_DEFINITIONS) {
        if (db.objectStoreNames.contains(storeDef.name)) continue;
        const store = db.createObjectStore(storeDef.name, {
          keyPath: storeDef.keyPath,
          autoIncrement: !!storeDef.autoIncrement,
        });
        for (const idx of storeDef.indexes) {
          store.createIndex(idx.name, idx.keyPath, { multiEntry: !!idx.multiEntry });
        }
      }
    };

    request.onsuccess = (event) => {
      dbInstance = event.target.result;
      dbOpenPromise = null;
      resolve(dbInstance);
    };

    request.onerror = (event) => {
      dbOpenPromise = null;
      reject(event.target.error);
    };
  });

  return dbOpenPromise;
}

// ---------------------------------------------------------------------------
// Generic single-store helpers
// ---------------------------------------------------------------------------

/** Insert or overwrite a record (upsert semantics — safe for re-imports/edits). */
export async function dbPut(storeName, record) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const request = tx.objectStore(storeName).put(record);
    request.onsuccess = () => resolve(request.result);
    request.onerror = (e) => reject(e.target.error);
  });
}

export async function dbGet(storeName, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const request = tx.objectStore(storeName).get(key);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = (e) => reject(e.target.error);
  });
}

export async function dbGetAll(storeName) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const request = tx.objectStore(storeName).getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = (e) => reject(e.target.error);
  });
}

/** Look up records via a named index — e.g. all threat records for a given report. */
export async function dbGetAllByIndex(storeName, indexName, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const request = tx.objectStore(storeName).index(indexName).getAll(value);
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = (e) => reject(e.target.error);
  });
}

export async function dbDelete(storeName, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const request = tx.objectStore(storeName).delete(key);
    request.onsuccess = () => resolve(true);
    request.onerror = (e) => reject(e.target.error);
  });
}

export async function dbClear(storeName) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const request = tx.objectStore(storeName).clear();
    request.onsuccess = () => resolve(true);
    request.onerror = (e) => reject(e.target.error);
  });
}

export async function dbCount(storeName) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const request = tx.objectStore(storeName).count();
    request.onsuccess = () => resolve(request.result || 0);
    request.onerror = (e) => reject(e.target.error);
  });
}

// ---------------------------------------------------------------------------
// Cross-store bulk write — the one the import pipeline will actually use
// ---------------------------------------------------------------------------

/**
 * Writes an entire approved import in a single atomic transaction spanning
 * every store involved. If anything fails partway through, IndexedDB aborts
 * the whole transaction — nothing partial gets left behind.
 *
 * @param {Object} recordsByStore - e.g.
 *   {
 *     reports: [reportObj],
 *     threatRecords: [tr1, tr2, ...],
 *     locations: [...],
 *     intelligenceItems: [...],
 *     ...
 *   }
 *   Any store name not present is simply skipped.
 */
export async function bulkWriteRecords(recordsByStore) {
  const db = await openDB();
  const storeNames = Object.keys(recordsByStore).filter((name) => STORE_NAMES.includes(name));

  if (storeNames.length === 0) return true;

  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeNames, 'readwrite');

    tx.oncomplete = () => resolve(true);
    tx.onerror = (e) => reject(e.target.error);
    tx.onabort = (e) => reject(e.target.error || new Error('Import transaction aborted'));

    for (const storeName of storeNames) {
      const store = tx.objectStore(storeName);
      for (const record of recordsByStore[storeName] || []) {
        store.put(record);
      }
    }
  });
}

// ---------------------------------------------------------------------------
// ID namespacing (see schema doc section 1 — keeps IDs unique across reports)
// ---------------------------------------------------------------------------

export function namespaceId(reportId, localId) {
  if (!reportId || !localId) return null;
  return `${reportId}::${localId}`;
}

// ---------------------------------------------------------------------------
// Audit log convenience
// ---------------------------------------------------------------------------

export async function addAuditLogEntry(entry) {
  return dbPut('auditLog', {
    timestamp: new Date().toISOString(),
    ...entry,
  });
}

// ---------------------------------------------------------------------------
// Dev/maintenance utilities
// ---------------------------------------------------------------------------

/** Wipes the entire database. Used by Settings > Clear all data (with a UI-level confirm). */
export function resetDatabase() {
  return new Promise((resolve, reject) => {
    if (dbInstance) {
      dbInstance.close();
      dbInstance = null;
    }
    dbOpenPromise = null;
    const request = indexedDB.deleteDatabase(DB_NAME);
    request.onsuccess = () => resolve(true);
    request.onerror = (e) => reject(e.target.error);
    request.onblocked = () =>
      reject(new Error('Database deletion blocked — close other tabs using this app and try again.'));
  });
}

/** Rough storage usage, for the Settings > storage-usage display. Returns null if unsupported. */
export async function getStorageEstimate() {
  if (!navigator.storage || !navigator.storage.estimate) return null;
  const { usage, quota } = await navigator.storage.estimate();
  return { usageBytes: usage, quotaBytes: quota };
}

export { STORE_DEFINITIONS, STORE_NAMES, DB_NAME, DB_VERSION };
