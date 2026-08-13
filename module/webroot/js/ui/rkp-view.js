// The "Remote Key Provision" section on the Keyboxes screen. It sits at the same title level as
// "Keyboxes": a panel-head with an h1.panel-title, then one card of labelled iOS-style switches, one
// per property the device defines. Stateless — it renders from the rows the controller passes and
// emits toggles through actions.toggle(name, on). When there are no rows it paints nothing, so a
// device without any of these knobs shows no section at all. Pure DOM through el(); all text is
// textContent, never innerHTML. It imports no data/* or bridge/*.
//
// renderRkpSection(host, state, actions)
//   state   = { rows }   rows = [{ key, name, label, help, value, on }]
//   actions = { toggle(name, on) }

import { el, clear } from "./dom.js";

export function renderRkpSection(host, state, actions) {
  clear(host);
  const rows = (state && state.rows) || [];
  if (!rows.length) return; // no RKP properties on this device => no section

  host.appendChild(el("div", { class: "panel-head" }, [
    el("h1", { class: "panel-title", text: "Remote Key Provision" }),
  ]));

  const card = el("div", { class: "card" });
  for (const r of rows) card.appendChild(rkpRow(r, actions));
  host.appendChild(card);
}

function rkpRow(r, actions) {
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
