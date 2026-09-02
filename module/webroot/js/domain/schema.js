// The single source of truth for a config profile's shape.
//
// The form, the validator, and the on-disk persistence all read from FIELDS.
// Adding a profile field is one new descriptor in the array below — it then
// renders, validates, and saves automatically. A brand-new *widget type* also
// needs one case in ui/field.js; an existing type needs nothing else.
//
// Pure data only: no DOM, no I/O. Its one import (domain/path.js) is itself pure,
// which is what keeps the domain layer unit-testable device-free.

import { setPath } from "./path.js";

export const VERSION = 1;

// Whitelists. A value has to match its regex before it may be saved, and the
// same regexes double as the shell-injection backstop (defence in depth — even
// unmatched input stays quoted by bridge/shell.js).
export const PKG_RE = /^[A-Za-z0-9_.]+$/;
// A package name optionally suffixed with the Android user it lives in: "com.foo" is the app as
// installed for the primary user, "com.foo@10" the same app inside user 10 — a work profile or a
// secondary user, whose copy runs under its own uid and is a separate caller to keystore.
export const PKG_USER_RE = /^[A-Za-z0-9_.]+@\d+$/;
// A raw-uid targeting token (advanced): "uid:" followed by one or more digits, e.g.
// "uid:10123". It lets a profile target a caller uid directly — a shared-uid app, or an
// app whose package name is unknown — bypassing package-name resolution. An apps[] entry
// is valid when it is a package name, a package@user name, OR a uid token; APP_ENTRY_RE is that
// union and is the per-item check the schema/validator use in place of the package-only PKG_RE.
export const UID_RE = /^uid:\d+$/;
export const APP_ENTRY_RE = /^([A-Za-z0-9_.]+(@\d+)?|uid:\d+)$/;

// The package half and the user half of an apps[] entry. A bare package name is user 0, which is
// what it has always meant; anything unparseable comes back as user 0 with the whole string as the
// name, so a caller never has to special-case a malformed entry that validation already rejects.
export function splitEntry(entry) {
  const s = String(entry == null ? "" : entry);
  const at = s.indexOf("@");
  if (at < 0) return { pkg: s, userId: 0 };
  const digits = s.slice(at + 1);
  if (!digits || !/^\d+$/.test(digits)) return { pkg: s, userId: 0 };
  return { pkg: s.slice(0, at), userId: Number(digits) };
}

/** The apps[] entry naming `pkg` inside `userId` — the mirror of splitEntry, and of Scope.entryToken. */
export function entryToken(pkg, userId) {
  return userId ? pkg + "@" + userId : pkg;
}
export const PROFILE_RE = /^[A-Za-z0-9_-]{1,32}$/;
export const KEYBOX_RE = /^[A-Za-z0-9._-]+\.xml$/;
// harvested | system_property | today | no | YYYY-MM | YYYY-MM-DD, with month 01-12
// and day 01-31 so impossible calendar values (month 00/13, day 00/32+) are rejected.
// The literal tokens YYYY / MM / DD are also allowed in a date and resolved to today by
// the daemon, so "YYYY-MM-05" means "the 5th of the current month" -- or of the previous one
// while that day has not arrived yet, since a patch level may never be dated in the future.
// `harvested` reuses the
// value harvested from the device (captured from the real TEE, or fabricated when the harvest
// could not read one); `system_property` reads the build property.
export const PATCH_RE = /^(today|no|harvested|system_property|(\d{4}|YYYY)-(0[1-9]|1[0-2]|MM)(-(0[1-9]|[12]\d|3[01]|DD))?)$/;
// harvested | system_property | "16" | "16.0.0" | packed integer like "160000"
export const OSVER_RE = /^(harvested|system_property|\d+(\.\d+){0,2})$/;
// Per-profile operation mode.
export const MODE_RE = /^(patch|generation)$/;

// Field descriptors, in render order. Each one is:
//   key      unique id, also the inline-error key
//   path     where the value lives inside a profile object (supports nesting)
//   label    human label for the form
//   group    which fieldset it renders under
//   type     which widget renders it (see ui/field.js)
//   options  choices for a 'select'
//   default  value emptyProfile() seeds
//   re       format regex (per-item for 'applist'); a value is checked ONLY when
//            present, so re means "format-validate", never "required"
//   required whether a blank value is an error; independent of re, so a field can
//            be optional-but-format-validated or required-but-format-free
//   help     optional hint under the field
export const FIELDS = [
  // --- attestation record -------------------------------------------------
  {
    key: "keybox", path: ["keybox"], label: "Keybox", group: "attestation",
    type: "keybox", re: KEYBOX_RE, required: true, default: "keybox.xml",
    help: "An *.xml keybox under /data/adb/teesim to sign attestations with.",
  },
  {
    key: "mode", path: ["mode"], label: "Operation mode", group: "attestation",
    type: "select", options: ["patch", "generation"], required: true, default: "patch",
    re: MODE_RE,
    help:
      "patch: keep the real hardware key and re-sign only its attestation with the keybox " +
      "(fewer detection points; needs a working hardware level). generation: mint the whole key " +
      "in software. A level whose hardware is unavailable always falls back to generation.",
  },
  // --- patch & OS levels (folded away in the editor to keep it concise). Empty means
  //     "use the harvested value" — so these are optional, not required. ---
  {
    key: "patchSystem", path: ["patchLevel", "system"], label: "System patch",
    group: "levels", type: "patch", re: PATCH_RE, required: false, default: "today",
    picks: ["system_property", "today", "no"],
  },
  {
    key: "patchVendor", path: ["patchLevel", "vendor"], label: "Vendor patch",
    group: "levels", type: "patch", re: PATCH_RE, required: false, default: "YYYY-MM-05",
    picks: ["system_property", "@month05", "today", "no"],
  },
  {
    key: "patchBoot", path: ["patchLevel", "boot"], label: "Boot patch",
    group: "levels", type: "patch", re: PATCH_RE, required: false, default: "YYYY-MM-05",
    picks: ["system_property", "@month05", "today", "no"],
  },
  {
    key: "osVersion", path: ["osVersion"], label: "OS version",
    group: "levels", type: "patch", re: OSVER_RE, required: false, default: "",
    picks: ["system_property"],
  },
  // --- device identity (all optional: blank means "don't provision this id") ---
  { key: "brand", path: ["brand"], label: "Brand", group: "identity", type: "text", required: false, default: "" },
  { key: "device", path: ["device"], label: "Device", group: "identity", type: "text", required: false, default: "" },
  { key: "product", path: ["product"], label: "Product", group: "identity", type: "text", required: false, default: "" },
  { key: "manufacturer", path: ["manufacturer"], label: "Manufacturer", group: "identity", type: "text", required: false, default: "" },
  { key: "model", path: ["model"], label: "Model", group: "identity", type: "text", required: false, default: "" },
  { key: "serial", path: ["serial"], label: "Serial", group: "identity", type: "text", required: false, default: "" },
  { key: "imei", path: ["imei"], label: "IMEI", group: "identity", type: "text", required: false, default: "" },
  { key: "meid", path: ["meid"], label: "MEID", group: "identity", type: "text", required: false, default: "" },
  { key: "imei2", path: ["imei2"], label: "IMEI2", group: "identity", type: "text", required: false, default: "" },
  // --- targeting ----------------------------------------------------------
  {
    key: "apps", path: ["apps"], label: "Apps", group: "apps", type: "scope",
    re: APP_ENTRY_RE, required: true, default: [],
    help: "The apps this profile attests for.",
  },
  {
    key: "autoIncludeNewApps", path: ["autoIncludeNewApps"], label: "Auto-include new apps",
    group: "apps", type: "toggle", required: false, default: false,
    help: "Targets apps installed after now; existing apps stay untouched. New apps are discovered " +
      "on a rescan, not watched for live.",
  },
];

// Clone a default so two profiles never share the same array/object reference.
const cloneDefault = (v) => (Array.isArray(v) ? v.slice() : v && typeof v === "object" ? JSON.parse(JSON.stringify(v)) : v);

// Build a blank profile from the descriptor defaults, honouring nested paths.
export function emptyProfile() {
  const p = {};
  for (const f of FIELDS) setPath(p, f.path, cloneDefault(f.default));
  return p;
}

// Build a blank, valid-shaped config.
export function emptyConfig() {
  return { version: VERSION, profiles: {} };
}
