// Disk <-> plain-object adapter for overrides.json — the user's edits to the harvest override layer
// (synthesized levels/versions, and an all-zero verified-boot key/hash). A flat { field: value } map in
// the machine form the daemon merges: the level integer, 64 hex chars for a boot key/hash. Ids are NOT
// written here — spoofing an id is a per-profile concern in config.json.
//
// This is the only module that knows overrides live at a path. Values are written verbatim; the daemon
// (Harvester.applyUserOverrides) validates and ignores anything it does not recognize, so a stale or
// hand-edited key can never corrupt a push. Written through the same atomic shell bridge as config.json,
// so the daemon's DATA_DIR watcher re-merges and re-pushes on save.

import { OVERRIDES, readFile, writeFileAtomic, deleteFile } from "../bridge/shell.js";

// Load overrides.json into a plain { field: value } object.
//   { ok: true,  overrides }   - a plain object (empty when the file is absent)
//   { ok: false, error }       - present but unparseable (caller must NOT overwrite)
export async function load() {
  const raw = await readFile(OVERRIDES);
  if (!raw || raw.trim() === "") return { ok: true, overrides: {} };
  let overrides;
  try {
    overrides = JSON.parse(raw);
  } catch (e) {
    return { ok: false, error: "overrides.json is not valid JSON: " + e.message };
  }
  if (!overrides || typeof overrides !== "object" || Array.isArray(overrides)) {
    return { ok: false, error: "overrides.json root must be a JSON object." };
  }
  return { ok: true, overrides };
}

// Serialize and atomically write. When the map is empty, remove the file so the daemon falls straight
// back to its computed defaults rather than merging an empty object.
//   { ok: true } | { ok: false, error }
export async function save(overrides) {
  const keys = Object.keys(overrides || {});
  if (keys.length === 0) return deleteFile(OVERRIDES);
  const text = JSON.stringify(overrides, null, 2) + "\n";
  return writeFileAtomic(OVERRIDES, text);
}
