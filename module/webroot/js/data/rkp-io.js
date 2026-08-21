// Remote-key-provisioning knobs adapter. It reads the handful of system properties that decide how
// keystore2 sources attestation keys, and flips them through the daemon (POST /rkp), so the Keyboxes
// screen can show and toggle them. The property NAMES here are fixed literals, never derived from user
// input; the daemon re-validates the name and sets it live + persists it atomically. No DOM.

import { getProp } from "../bridge/shell.js";
import { keyAdmin } from "./keyadmin.js";

// The properties we surface, in display order. `key` is a stable id for the view; `name` is the real
// system property; `label`/`help` describe it. The two rkp_only knobs force a security level down the
// RKP-only path (no batch-key fallback); enable_rkpd toggles the native provisioner itself.
export const RKP_PROPS = [
  {
    key: "teeRkpOnly",
    name: "remote_provisioning.tee.rkp_only",
    label: "TEE RKP-only",
    help: "When on, the TEE security level provisions attestation keys only via RKP, with no batch-key fallback.",
  },
  {
    key: "strongboxRkpOnly",
    name: "remote_provisioning.strongbox.rkp_only",
    label: "StrongBox RKP-only",
    help: "When on, the StrongBox security level provisions attestation keys only via RKP, with no batch-key fallback.",
  },
  {
    key: "enableRkpd",
    name: "persist.device_config.remote_key_provisioning_native.enable_rkpd",
    label: "Enable rkpd",
    help: "Whether the native remote key provisioning daemon (rkpd) runs on this device.",
  },
];

const isTrue = (v) => v === "true" || v === "1";

// Read every knob and return only the ones this device actually defines. A property whose getprop
// value is non-empty is "present" and shown; an empty value means the device does not define it and
// the row (and, if all three are empty, the whole section) is omitted. The returned rows carry the
// raw value plus a derived boolean for the switch.
export async function readRkpProps() {
  const rows = [];
  for (const p of RKP_PROPS) {
    const value = await getProp(p.name);
    if (!value) continue; // absent / unset => not a knob on this device
    rows.push({ key: p.key, name: p.name, label: p.label, help: p.help, value, on: isTrue(value) });
  }
  return rows;
}

// Flip one knob. The daemon owns both the live write and the persist: POST /rkp sets the property with
// resetprop and records the choice in rkp.json as one atomic, lock-ordered step, so a concurrent re-push
// can never read a half-updated file and revert the toggle. The rkp_only props are plain (not persist.*)
// and would otherwise revert on reboot; the persisted value is what App.applyRkpProps re-forces each boot.
//
// Never throws: on any failure it returns { ok:false, error } so the caller's re-read simply snaps the
// switch back to the value the device actually took (the daemon leaves the old value on a failed set).
export async function setRkpProp(name, on) {
  try {
    return await keyAdmin("setRkp", { name, on });
  } catch (e) {
    return { ok: false, error: e && e.message };
  }
}
