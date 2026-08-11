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
import { t } from "../i18n.js";

export const VERSION = 1;

// Whitelists. A value has to match its regex before it may be saved, and the
// same regexes double as the shell-injection backstop (defence in depth — even
// unmatched input stays quoted by bridge/shell.js).
export const PKG_RE = /^[A-Za-z0-9_.]+$/;
export const PROFILE_RE = /^[A-Za-z0-9_-]{1,32}$/;
export const KEYBOX_RE = /^[A-Za-z0-9._-]+\.xml$/;
// harvested | system_property | today | no | YYYY-MM | YYYY-MM-DD, with month 01-12
// and day 01-31 so impossible calendar values (month 00/13, day 00/32+) are rejected.
// The literal tokens YYYY / MM / DD are also allowed in a date and resolved to today by
// the daemon, so "YYYY-MM-05" means "the 5th of the current month". `harvested` reuses
// the value captured from the real TEE; `system_property` reads the build property.
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
    key: "keybox", path: ["keybox"], label: t("schema_kb_label"), group: "attestation",
    type: "keybox", re: KEYBOX_RE, required: true, default: "keybox.xml",
    help: t("schema_kb_help"),
  },
  {
    key: "mode", path: ["mode"], label: t("schema_mode_label"), group: "attestation",
    type: "select", options: ["patch", "generation"], required: true, default: "patch",
    re: MODE_RE,
    help: t("schema_mode_help"),
  },
  // --- patch & OS levels (folded away in the editor to keep it concise). Empty means
  //     "use the harvested value" — so these are optional, not required. ---
  {
    key: "patchSystem", path: ["patchLevel", "system"], label: t("schema_system_patch"),
    group: "levels", type: "patch", re: PATCH_RE, required: false, default: "today",
    picks: ["system_property", "today", "no"],
  },
  {
    key: "patchVendor", path: ["patchLevel", "vendor"], label: t("schema_vendor_patch"),
    group: "levels", type: "patch", re: PATCH_RE, required: false, default: "YYYY-MM-05",
    picks: ["system_property", "@month05", "today", "no"],
  },
  {
    key: "patchBoot", path: ["patchLevel", "boot"], label: t("schema_boot_patch"),
    group: "levels", type: "patch", re: PATCH_RE, required: false, default: "YYYY-MM-05",
    picks: ["system_property", "@month05", "today", "no"],
  },
  {
    key: "osVersion", path: ["osVersion"], label: t("schema_os_version"),
    group: "levels", type: "patch", re: OSVER_RE, required: false, default: "",
    picks: ["system_property"],
  },
  // --- device identity (all optional: blank means "don't provision this id") ---
  { key: "brand", path: ["brand"], label: t("schema_brand"), group: "identity", type: "text", required: false, default: "" },
  { key: "device", path: ["device"], label: t("schema_device"), group: "identity", type: "text", required: false, default: "" },
  { key: "product", path: ["product"], label: t("schema_product"), group: "identity", type: "text", required: false, default: "" },
  { key: "manufacturer", path: ["manufacturer"], label: t("schema_manufacturer"), group: "identity", type: "text", required: false, default: "" },
  { key: "model", path: ["model"], label: t("schema_model"), group: "identity", type: "text", required: false, default: "" },
  { key: "serial", path: ["serial"], label: t("schema_serial"), group: "identity", type: "text", required: false, default: "" },
  { key: "imei", path: ["imei"], label: t("schema_imei"), group: "identity", type: "text", required: false, default: "" },
  { key: "meid", path: ["meid"], label: t("schema_meid"), group: "identity", type: "text", required: false, default: "" },
  { key: "imei2", path: ["imei2"], label: t("schema_imei2"), group: "identity", type: "text", required: false, default: "" },
  // --- targeting ----------------------------------------------------------
  {
    key: "apps", path: ["apps"], label: t("schema_apps_label"), group: "apps", type: "applist",
    re: PKG_RE, required: true, default: [],
    help: t("schema_apps_help"),
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
