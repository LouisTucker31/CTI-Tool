/**
 * backup.js — full-database export and restore.
 *
 * Everything in this tool lives only in the browser's local IndexedDB —
 * there's no server, no sync, nothing backing it up. This is the safety
 * net: export dumps every store into one JSON file; restore reads that
 * file back in, replacing whatever's currently stored.
 *
 * Deliberately a full replace, not a merge, on restore — "restore a
 * backup" means "get back to exactly this saved state", which is a
 * different, simpler operation than "import a new report" (which adds to
 * what's already there and runs through duplicate detection). Trying to
 * make restore merge intelligently with existing data would just
 * reintroduce the same duplicate-handling complexity for no real benefit,
 * since the whole point of a backup is to BE the source of truth again.
 */

import { STORE_NAMES, dbGetAll, bulkWriteRecords, resetDatabase } from './db.js';

export async function exportAllData() {
  const stores = {};
  for (const storeName of STORE_NAMES) {
    stores[storeName] = await dbGetAll(storeName);
  }
  return {
    exportedAt: new Date().toISOString(),
    schemaVersion: 1,
    stores,
  };
}

export function downloadJson(obj, filename) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/**
 * @returns {Object} counts written per store, for a confirmation message
 * @throws if the file doesn't look like a valid backup
 */
export async function restoreFromBackup(backupObject) {
  if (!backupObject || typeof backupObject !== 'object' || typeof backupObject.stores !== 'object') {
    throw new Error("This file doesn't look like a valid backup.");
  }

  await resetDatabase();

  const recordsByStore = {};
  for (const storeName of STORE_NAMES) {
    if (Array.isArray(backupObject.stores[storeName])) {
      recordsByStore[storeName] = backupObject.stores[storeName];
    }
  }

  await bulkWriteRecords(recordsByStore);

  return Object.fromEntries(
    Object.entries(recordsByStore).map(([store, records]) => [store, records.length])
  );
}
