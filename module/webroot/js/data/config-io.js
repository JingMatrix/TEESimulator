// Disk <-> plain-object adapter for config.json. No validation of field values
// (that is domain/validate.js) and no DOM. This is the only module that knows
// the config lives at a path and how it is serialized; everything above it works
// with a plain JS object.

import { CONFIG, DIR, readFile, writeFileAtomic, listXml } from "../bridge/shell.js";

// Load and structurally sanity-check config.json.
//   { ok: true,  config }        - a plain object with version 1 and a profiles map
//   { ok: false, error, raw }    - missing, empty, unparseable, or wrong shape
//
// The anti-corruption guarantee lives here: on any ok:false the caller must NOT
// write, so a file we could not understand is never overwritten. `raw` is the
// bytes we saw, handed back so the caller can tell "empty/missing" (offer to
// seed) from "there is content we refuse to clobber".
export async function load() {
  const raw = await readFile(CONFIG);

  if (!raw || raw.trim() === "") {
    return { ok: false, error: "No config.json found (or it is empty).", raw: raw || "" };
  }

  let config;
  try {
    config = JSON.parse(raw);
  } catch (e) {
    return { ok: false, error: "config.json is not valid JSON: " + e.message, raw };
  }

  if (!config || typeof config !== "object" || Array.isArray(config)) {
    return { ok: false, error: "config.json root must be a JSON object.", raw };
  }
  if (config.version !== 1) {
    return { ok: false, error: "Unsupported config version (expected 1).", raw };
  }
  if (!config.profiles || typeof config.profiles !== "object" || Array.isArray(config.profiles)) {
    return { ok: false, error: "config.json is missing a profiles object.", raw };
  }

  return { ok: true, config };
}

// Serialize and atomically write. Pretty-printed so the file stays human-diffable.
//   { ok: true } | { ok: false, error }
export async function save(config) {
  const text = JSON.stringify(config, null, 2) + "\n";
  return writeFileAtomic(CONFIG, text);
}

// The keybox files the picker can choose from: every *.xml under /data/adb/teesim.
export async function listKeyboxes() {
  return listXml(DIR);
}
