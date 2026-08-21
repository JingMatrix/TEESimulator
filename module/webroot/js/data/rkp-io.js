// Remote-key-provisioning knobs adapter. It reads the handful of system properties that decide how
// keystore2 sources attestation keys, and changes them through the daemon, so the Keyboxes screen can
// show and manage them. The property NAMES here are fixed literals, never derived from user input;
// the daemon re-validates every name. No DOM.
//
// The two `rkp_only` props are deletable: the daemon removes the prop live and records a persistent
// delete-intent, re-enforced each boot (a vendor .prop can re-apply them). A deleted prop reads back
// as unset — indistinguishable from one the device never shipped — so the daemon's delete-intent list
// is what tells the view to offer a Restore control instead of hiding the row. `enable_rkpd` is
// persist.device_config and survives on its own, so it stays a plain toggle.

import { getProp, setProp } from "../bridge/shell.js";
import { keyAdmin } from "./keyadmin.js";

// The properties we surface, in display order. `key` is a stable id for the view; `name` is the real
// system property; `label`/`help` describe it. `kind` is "deletable" for the two rkp_only knobs (the
// view renders a trash/restore control) or "toggle" for enable_rkpd (an on/off switch).
export const RKP_PROPS = [
  {
    key: "teeRkpOnly",
    name: "remote_provisioning.tee.rkp_only",
    label: "TEE RKP-only",
    help: "When present, the TEE level provisions attestation keys only via RKP, with no batch-key fallback. Delete it to let keystore2 fall back to the keybox.",
    kind: "deletable",
  },
  {
    key: "strongboxRkpOnly",
    name: "remote_provisioning.strongbox.rkp_only",
    label: "StrongBox RKP-only",
    help: "When present, the StrongBox level provisions attestation keys only via RKP, with no batch-key fallback. Delete it to let keystore2 fall back to the keybox.",
    kind: "deletable",
  },
  {
    key: "enableRkpd",
    name: "persist.device_config.remote_key_provisioning_native.enable_rkpd",
    label: "Enable rkpd",
    help: "Whether the native remote key provisioning daemon (rkpd) runs on this device.",
    kind: "toggle",
  },
];

const isTrue = (v) => v === "true" || v === "1";

// The daemon's current RKP-only delete intents, as a { name: valueAtDeletion } map. Empty on any
// failure (daemon not ready, etc.) so a read error just means "nothing is marked deleted".
async function readDeleteIntents() {
  try {
    const r = await keyAdmin("rkpList");
    return (r && r.ok && r.deleted) || {};
  } catch (_) {
    return {};
  }
}

// Read every knob and return the rows the view should paint. For a "toggle" prop, an empty getprop
// value means the device does not define it, so the row is omitted. For a "deletable" prop, order of
// precedence: a recorded delete-intent => a "deleted" row (Restore control), carrying the value to
// put back; else a present value => an "active" row (trash control); else (absent, no intent) the
// device never shipped it => omitted. So a deleted knob stays visible as Restore, while a knob the
// device genuinely lacks shows nothing.
export async function readRkpProps() {
  const deleted = await readDeleteIntents();
  const rows = [];
  for (const p of RKP_PROPS) {
    if (p.kind === "toggle") {
      const value = await getProp(p.name);
      if (!value) continue; // absent / unset => not a knob on this device
      rows.push({ ...meta(p), kind: "toggle", value, on: isTrue(value) });
      continue;
    }
    // deletable rkp_only prop
    if (Object.prototype.hasOwnProperty.call(deleted, p.name)) {
      rows.push({ ...meta(p), kind: "deleted", value: deleted[p.name] || "true" });
      continue;
    }
    const value = await getProp(p.name);
    if (!value) continue; // absent and not deleted by us => device never shipped it
    rows.push({ ...meta(p), kind: "active", value });
  }
  return rows;
}

const meta = (p) => ({ key: p.key, name: p.name, label: p.label, help: p.help });

// Delete one rkp_only property through the daemon (live resetprop --delete + persistent delete-intent,
// one atomic lock-ordered step). Never throws: on any failure returns { ok:false, error } so the
// caller's re-read just leaves the row as it was.
export async function deleteRkpProp(name) {
  try {
    return await keyAdmin("rkpDelete", { name });
  } catch (e) {
    return { ok: false, error: e && e.message };
  }
}

// Restore one deleted rkp_only property through the daemon (set it back to the remembered value +
// clear the intent). Never throws, same contract as deleteRkpProp.
export async function restoreRkpProp(name) {
  try {
    return await keyAdmin("rkpRestore", { name });
  } catch (e) {
    return { ok: false, error: e && e.message };
  }
}

// Flip the enable_rkpd toggle, written as canonical "true"/"false". It is persist.device_config, so a
// direct resetprop sticks on its own — no daemon round-trip needed. Callers re-read afterwards so the
// switch reflects the value the device actually took.
export async function setRkpProp(name, on) {
  return setProp(name, on ? "true" : "false");
}
