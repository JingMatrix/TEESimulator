// The "Remote Key Provision" section on the Keyboxes screen. It sits at the same title level as
// "Keyboxes": a panel-head with an h1.panel-title, then one card of rows, one per property the device
// defines (or that the user has deleted). Stateless — it renders from the rows the controller passes.
// Pure DOM through el(); all text is textContent, never innerHTML. It imports only ./dom.
//
// Each row is one of three kinds:
//   "active"  an rkp_only prop that is present  -> a trash button that deletes it (actions.del)
//   "deleted" an rkp_only prop the user deleted -> a Restore button that puts it back (actions.restore)
//   "toggle"  enable_rkpd                       -> an on/off switch (actions.toggle)
//
// renderRkpSection(host, state, actions)
//   state   = { rows }   rows = [{ key, name, label, help, kind, value?, on? }]
//   actions = { del(name), restore(name), toggle(name, on) }

import { el, clear, svgIcon } from "./dom.js";

// A trash-can glyph in the same 24x24, stroke-only style as dom.js's ICON_SEARCH/ICON_SORT.
const ICON_TRASH = [
  { d: "M3 6h18" },
  { d: "M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" },
  { d: "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" },
  { d: "M10 11v6" },
  { d: "M14 11v6" },
];

export function renderRkpSection(host, state, actions) {
  clear(host);
  const rows = (state && state.rows) || [];
  if (!rows.length) return; // no RKP properties on this device => no section

  host.appendChild(el("div", { class: "panel-head" }, [
    el("h1", { class: "panel-title", text: "Remote Key Provision" }),
  ]));

  // These knobs almost never need touching: the module already handles remote provisioning so the
  // keybox stays in effect. Deleting them is an escape hatch for the rare device where keybox
  // attestation explicitly fails — hence the calm, informational tone. Only shown while there is a
  // still-present rkp_only prop left to delete.
  if (rows.some((r) => r.kind === "active")) {
    host.appendChild(el("div", { class: "card" }, [el("div", { class: "banner" }, [
      el("div", { text: "You usually don't need to change these." }),
      el("div", { class: "muted small", text:
        "The module handles remote provisioning while these stay in place. Only if a device explicitly " +
        "fails keybox attestation — a rare case — should you delete the rkp-only properties to force " +
        "keystore2 onto the keybox. A deleted property is re-removed on every boot until you restore it." }),
    ])]));
  }

  const card = el("div", { class: "card" });
  for (const r of rows) card.appendChild(rkpRow(r, actions));
  host.appendChild(card);
}

function rkpRow(r, actions) {
  if (r.kind === "toggle") return toggleRow(r, actions);
  if (r.kind === "deleted") return deletedRow(r, actions);
  return activeRow(r, actions);
}

// enable_rkpd — an iOS-style on/off switch.
function toggleRow(r, actions) {
  const id = "rkp-" + r.key;
  const input = el("input", {
    id, class: "switch-input", type: "checkbox", checked: r.on,
    role: "switch", "aria-checked": r.on ? "true" : "false",
    onchange: (e) => actions.toggle(r.name, e.target.checked),
  });
  const sw = el("span", { class: "switch" + (r.on ? " on" : "") }, [
    input,
    el("span", { class: "switch-track", "aria-hidden": "true" }, [el("span", { class: "switch-thumb" })]),
  ]);
  return el("div", { class: "field toggle-field" }, [
    el("div", { class: "toggle-row" }, [
      el("label", { class: "toggle-main", for: id }, [
        el("span", { class: "field-label", text: r.label }),
        el("span", { class: "field-help", text: r.help }),
        el("span", { class: "field-help mono", text: r.name + " = " + r.value }),
      ]),
      sw,
    ]),
  ]);
}

// A present rkp_only prop — a square trash button that deletes it.
function activeRow(r, actions) {
  const btn = el("button", {
    class: "rkp-del", type: "button",
    title: "Delete " + r.name, "aria-label": "Delete " + r.name,
    onclick: () => actions.del(r.name),
  }, [svgIcon(ICON_TRASH, { size: 18 })]);
  return el("div", { class: "field toggle-field rkp-row" }, [
    el("div", { class: "toggle-row" }, [
      el("div", { class: "toggle-main" }, [
        el("span", { class: "field-label", text: r.label }),
        el("span", { class: "field-help", text: r.help }),
        el("span", { class: "field-help mono", text: r.name + " = " + r.value }),
      ]),
      btn,
    ]),
  ]);
}

// An rkp_only prop the user deleted — dimmed, with a "removed" chip and a Restore button that sets
// it back to its remembered value.
function deletedRow(r, actions) {
  const back = r.value || "true";
  const btn = el("button", {
    class: "btn small ghost", type: "button",
    title: "Restore " + r.name, "aria-label": "Restore " + r.name,
    onclick: () => actions.restore(r.name),
    text: "Restore",
  });
  return el("div", { class: "field toggle-field rkp-row deleted" }, [
    el("div", { class: "toggle-row" }, [
      el("div", { class: "toggle-main" }, [
        el("span", { class: "field-label", text: r.label }),
        el("span", { class: "field-help", text:
          "Re-removed on every boot. Restore to set " + r.name + " back to \"" + back + "\"." }),
        el("span", { class: "chip warn small", text: "removed" }),
      ]),
      btn,
    ]),
  ]);
}
