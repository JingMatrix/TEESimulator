// Disk <-> keybox-file adapter. The keybox *.xml files live beside config.json
// under /data/adb/teesim; this is the only module that turns a keybox name into
// a path and asks the shell to move, remove, or write one. Every name is forced
// to a safe basename BEFORE any path is built (see safeName), so even though
// bridge/shell.js already quotes every argument, a hostile name can never escape
// the module directory. No DOM.

import { DIR, writeFileAtomic, renameFile, deleteFile, listXml } from "../bridge/shell.js";
import { KEYBOX_RE } from "../domain/schema.js";

// Coerce a raw name to a safe *.xml basename, or null if it cannot be one.
//   1. Trim, then drop everything up to the last "/" or "\" so no directory
//      component survives — a name is a basename, never a path.
//   2. Append ".xml" if it is not already present.
//   3. Reject anything containing "..", then require the whole thing to match
//      the keybox whitelist (^[A-Za-z0-9._-]+\.xml$).
// The path is ALWAYS built from this returned value, never from the raw input,
// so the daemon directory is the one and only place a keybox can land.
export function safeName(raw) {
  if (raw == null) return null;
  let name = String(raw).trim().split(/[/\\]/).pop();
  if (!name) return null;
  if (!name.endsWith(".xml")) name += ".xml";
  if (name.includes("..")) return null;
  if (!KEYBOX_RE.test(name)) return null;
  return name;
}

// The keybox files present: every *.xml under /data/adb/teesim.
export async function listKeyboxes() {
  return listXml(DIR);
}

// Import (copy in / overwrite) a keybox from raw XML text.
//   name       the desired filename (validated to a safe basename here)
//   xmlText    the file's contents
//   existing   the current basenames, so a collision can be refused
//   overwrite  when true, an existing name is replaced instead of refused
// A light content sanity check keeps a stray file from being stored as a keybox.
// On a name collision returns { ok:false, exists:true, name } so the caller can
// offer to overwrite. { ok, name? , error? }.
export async function importKeybox(name, xmlText, existing = [], overwrite = false) {
  const safe = safeName(name);
  if (!safe) return { ok: false, error: "Invalid keybox name. Use letters, digits, . _ - and an .xml suffix." };

  const text = xmlText == null ? "" : String(xmlText);
  if (!text.includes("<AndroidAttestation") && !text.includes("<Keybox")) {
    return { ok: false, error: "That file does not look like a keybox (no <AndroidAttestation> or <Keybox>)." };
  }

  if (!overwrite && existing.includes(safe)) {
    return { ok: false, exists: true, name: safe, error: `A keybox named ${safe} already exists.` };
  }

  const r = await writeFileAtomic(DIR + "/" + safe, text);
  return r.ok ? { ok: true, name: safe } : { ok: false, error: r.error };
}

// Rename a keybox. Both names are validated to safe basenames before any path is
// built. A no-op when the names are equal; refused when the target exists.
export async function renameKeybox(oldName, newName, existing = []) {
  const from = safeName(oldName);
  const to = safeName(newName);
  if (!from) return { ok: false, error: "Invalid current keybox name." };
  if (!to) return { ok: false, error: "Invalid new keybox name. Use letters, digits, . _ - and an .xml suffix." };
  if (from === to) return { ok: true, name: to };
  if (existing.includes(to)) return { ok: false, error: `A keybox named ${to} already exists.` };

  const r = await renameFile(DIR + "/" + from, DIR + "/" + to);
  return r.ok ? { ok: true, name: to } : { ok: false, error: r.error };
}

// Delete a keybox. The name is validated to a safe basename before the path is
// built, so rm only ever sees a file inside the module directory.
export async function deleteKeybox(name) {
  const safe = safeName(name);
  if (!safe) return { ok: false, error: "Invalid keybox name." };

  const r = await deleteFile(DIR + "/" + safe);
  return r.ok ? { ok: true, name: safe } : { ok: false, error: r.error };
}
