// The "StrongBox" section on the Keyboxes screen, a sibling of "Remote Key Provision": one switch,
// shaped like the enable_rkpd row next door. Stateless — it renders from the state the controller
// passes and emits intents through `actions`. Pure DOM through el(); all text is textContent. It
// imports only ./dom.
//
// The decision it carries: each security level of a device is provisioned with its own batch key,
// and that key's certificate names the level it belongs to (`title=TEE` on a factory-provisioned
// key — the keybox format — or `O=TEE` on an RKP-issued one, against StrongBox for the other
// level). The certificate issues every leaf it signs, so a profile serving StrongBox from its TEE
// keybox leaves one certificate whose issuer names the TEE while the record inside it says
// StrongBox. A profile answers that with a StrongBox keybox of its own; this answers it for every
// profile that has none, by taking the level away.
//
// renderStrongBoxSection(host, state, actions)
//   state   = { forceBroken, available }
//   actions = { setForceBroken(on) }

import { el, clear } from "./dom.js";

export function renderStrongBoxSection(host, state, actions) {
  clear(host);
  const { forceBroken = false, available = true } = state || {};

  host.appendChild(el("div", { class: "panel-head" }, [
    el("h1", { class: "panel-title", text: "StrongBox" }),
    forceBroken ? el("span", { class: "chip warn", text: "broken" }) : null,
  ]));

  const id = "sb-broken";
  const input = el("input", {
    id, class: "switch-input", type: "checkbox", checked: forceBroken,
    role: "switch", "aria-checked": forceBroken ? "true" : "false",
    onchange: (e) => actions.setForceBroken(e.target.checked),
  });
  host.appendChild(el("div", { class: "card" }, [
    el("div", { class: "field toggle-field" }, [
      el("div", { class: "toggle-row" }, [
        el("label", { class: "toggle-main", for: id }, [
          el("span", { class: "field-label", text: "Force broken StrongBox" }),
          el("span", { class: "field-help", text:
            "Refuse attested StrongBox keys for targeted apps, so they fall back to the TEE. Use " +
            "it when a profile has no StrongBox keybox: a batch certificate names its level, so " +
            "signing StrongBox with a TEE keybox is detectable from a single key." }),
        ]),
        el("span", { class: "switch" + (forceBroken ? " on" : "") }, [
          input,
          el("span", { class: "switch-track", "aria-hidden": "true" }, [el("span", { class: "switch-thumb" })]),
        ]),
      ]),
    ]),
    // On a device whose StrongBox never reports in, no app reaches the level anyway.
    available ? null : el("div", { class: "field" }, [
      el("span", { class: "field-help", text: "This device has no working StrongBox." }),
    ]),
  ]));
}
