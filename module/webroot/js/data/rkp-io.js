// Remote-key-provisioning knobs adapter. It reads and writes the handful of system properties that
// decide how keystore2 sources attestation keys, so the Keyboxes screen can show and flip them. The
// property NAMES here are fixed literals, never derived from user input; only the boolean the user
// toggles reaches setProp (as canonical "true"/"false"). No DOM.

import { getProp, setProp } from "../bridge/shell.js";

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

// Flip one knob, written as canonical "true"/"false". Callers re-read afterwards so the UI reflects
// the value the device actually took (a failed write leaves the old value and the switch snaps back).
export async function setRkpProp(name, on) {
  return setProp(name, on ? "true" : "false");
}
