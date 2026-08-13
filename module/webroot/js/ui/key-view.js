// Render the "stored keys" panel: the keys THIS MODULE minted for the target apps, read
// from keystore2's database on Android 12+, or a hint on Android 10/11 where there is no
// keystore2 database to read. Rows are multi-selectable (a checkbox each, plus select-all),
// filterable by alias/app/keybox, and removable — every intent goes through the injected
// handler(action, arg). It never imports data/keyadmin.js (the controller wires the two).
// The Delete-selected button is rendered inline because its label carries the live selection
// count; the panel head otherwise holds the Spoofed/All scope control.
//
// renderKeys(mount, state, handler)
//   state = { keys, available, apiLevel, unavailable, loading, deleting, filter, selected, menuOpen, spoofedOnly }
//     keys        [{ id, alias, uid, package, state, class, created?, keybox?, keyAlgorithm?, purposes? }] from keystore2's DB
//     available   true when the daemon could read keystore2's database (API >= 31)
//     apiLevel    the device SDK_INT the daemon reported (0 before the first fetch)
//     unavailable true when the daemon key endpoint isn't reachable yet
//     loading     true while a fetch is in flight
//     deleting    true while a delete is in flight
//     filter      the current filter text
//     selected    Set of selected key ids
//     menuOpen    true while the in-field selection menu is open
//   handler(action, arg): "filter"(text) | "toggle"(id) | "toggleMenu" | "closeMenu" | "toggleSpoofed" |
//                         "selectFiltered"(ids[]) | "selectAll" | "unselectAll" | "inverse" | "deleteSelected"
//
// The search box sits in its own card above the list card. Its trailing icon opens a small
// menu (select filtered / all / none / inverse); per-row checkboxes still pick individual keys.
// The filter re-renders on every keystroke, so focus + caret are captured before the rebuild
// and restored after — the caret never jumps mid-type.

import { el, clear } from "./dom.js";
import { t } from "../i18n.js";

export function renderKeys(mount, state, handler) {
  // Capture filter-box focus before the teardown so a keystroke re-render doesn't drop the caret.
  const active = document.activeElement;
  const hadFilterFocus = !!active && active.id === "keyfilter";
  const caret = hadFilterFocus ? active.selectionStart : null;
  const restoreFocus = () => {
    if (!hadFilterFocus) return;
    const input = document.getElementById("keyfilter");
    if (!input) return;
    input.focus({ preventScroll: true });
    try {
      const p = caret == null ? input.value.length : caret;
      input.setSelectionRange(p, p);
    } catch { /* not selectable */ }
  };

  clear(mount);
  const {
    keys = [], available = false, apiLevel = 0, unavailable = false,
    loading = false, deleting = false, filter = "", selected = new Set(), menuOpen = false,
    spoofedOnly = true,
  } = state;

  // Panel head: Delete-selected (only when something is checked; its label counts the selection).
  // The scope control is appended below, once the counts it reports have been computed.
  const actionBtns = [];
  if (selected.size) {
    actionBtns.push(el("button", {
      class: "btn danger", disabled: deleting,
      text: deleting ? t("key_deleting") : t("key_delete_selected") + " (" + selected.size + ")",
      onclick: () => handler("deleteSelected"),
    }));
  }
  const panelActions = el("div", { class: "panel-actions" }, actionBtns);
  mount.appendChild(el("div", { class: "panel-head" }, [
    el("h1", { class: "panel-title", text: t("key_title") }),
    panelActions,
  ]));

  if (loading) {
    mount.appendChild(el("div", { class: "card" }, [el("p", { class: "muted", text: t("loading") })]));
    return;
  }

  if (unavailable) {
    mount.appendChild(el("div", { class: "card" }, [el("div", { class: "banner" }, [
      el("div", { text: t("key_daemon_unavailable") }),
      el("div", { class: "muted small", text: t("key_daemon_unreachable") }),
    ])]));
    return;
  }

  // Android 10/11 (or no keystore2 DB): there is no per-app database to inspect.
  if (apiLevel < 31 || !available) {
    mount.appendChild(el("div", { class: "card" }, [el("div", { class: "banner" }, [
      el("div", { text: t("key_unsupported") }),
      el("div", { class: "muted small", text:
        t("key_unsupported_hint") +
        (apiLevel ? "  (Android API " + apiLevel + ")" : "") }),
    ])]));
    return;
  }

  if (!keys.length) {
    mount.appendChild(el("div", { class: "card empty" }, [
      el("p", { class: "muted", text: t("key_empty") }),
    ]));
    return;
  }

  // Matching is a case-insensitive substring over alias / app / keybox. Spoofed keys
  // (generated / delegated / patched) sort ahead of untouched ones; the sort is stable,
  // so within a class the daemon's namespace+alias order is preserved.
  const q = filter.trim().toLowerCase();
  const matchedAll = q ? keys.filter((k) => matchesFilter(k, q)) : keys;
  // The apps' own untouched (real hardware) keys are hidden by default so the list shows only what we
  // spoofed; the "All" segment reveals them for inspection or deletion. Both counts are taken over the
  // same filtered population, so the two segments describe it from opposite sides — "Spoofed" reports
  // what it is holding back, "All" reports how much of what you are looking at we actually touched.
  const spoofedCount = matchedAll.filter(isSpoofed).length;
  const hiddenReal = matchedAll.length - spoofedCount;
  const matched = spoofedOnly ? matchedAll.filter(isSpoofed) : matchedAll;
  const shown = matched.slice().sort((a, b) => classRank(a) - classRank(b));

  // The scope control takes the slot Refresh used to hold. Reloading is already a pull-to-refresh
  // away (keyadmin-controller binds it to this mount), so the header is better spent on the one
  // control that changes what the screen is showing.
  panelActions.appendChild(scopeControl(spoofedOnly, spoofedCount, hiddenReal, handler));

  // Search card: the filter box and the selection menu.
  mount.appendChild(searchCard(filter, shown, menuOpen, handler));

  // List card: one row per shown key, each with its own checkbox.
  const listCard = el("div", { class: "card keypanel" });
  if (!shown.length) {
    const msg = hiddenReal
      ? hiddenReal + " " + t("key_hidden_switch")
      : keys.length ? t("key_no_match") + " \u201c" + filter + "\u201d." : t("key_no_keys");
    listCard.appendChild(el("p", { class: "muted keyempty", text: msg }));
    mount.appendChild(listCard);
    restoreFocus();
    return;
  }
  const list = el("ul", { class: "keylist" });
  for (const k of shown) {
    const checked = selected.has(k.id);
    const check = el("input", { type: "checkbox", checked, onchange: () => handler("toggle", k.id) });
    list.appendChild(el("li", { class: "keyrow" + (checked ? " selected" : "") }, [
      el("label", { class: "keycheck" }, [check]),
      el("div", { class: "keymeta" }, [
        el("div", { class: "keyalias" }, [
          el("span", { class: "mono", text: k.alias || t("key_no_alias") }),
          classChip(k),
          el("span", { class: "chip", text: appLabel(k) }),
          ...abnormalChips(k),
        ]),
        ...purposeChips(k),
        ...metaLines(k),
      ]),
    ]));
  }
  listCard.appendChild(list);
  mount.appendChild(listCard);
  restoreFocus();
}

// The search card: a field that looks like an input, holding the borderless filter box and a
// trailing icon button. The button opens an in-field menu of bulk-selection actions; a full-screen
// backdrop below the menu dismisses it on an outside tap.
function searchCard(filter, shown, menuOpen, handler) {
  const filterInput = el("input", {
    id: "keyfilter", class: "filter-input", type: "text", value: filter,
    placeholder: t("key_filter_placeholder"),
    autocapitalize: "off", autocorrect: "off", spellcheck: "false",
    oninput: (e) => handler("filter", e.target.value),
  });
  const field = el("div", { class: "filter-field" }, [
    filterInput,
    el("button", {
      class: "filter-menu-btn", type: "button", "aria-label": t("key_selection_actions"),
      "aria-expanded": menuOpen ? "true" : "false", onclick: () => handler("toggleMenu"),
    }, [el("span", { class: "sel-icon", "aria-hidden": "true" })]),
  ]);
  if (menuOpen) {
    field.appendChild(el("div", { class: "selmenu-backdrop", onclick: () => handler("closeMenu") }));
    const item = (label, action, arg) =>
      el("button", { type: "button", text: label, onclick: () => handler(action, arg) });
    field.appendChild(el("div", { class: "selmenu", role: "menu" }, [
      item(t("key_select_filtered"), "selectFiltered", shown.map((k) => k.id)),
      item(t("key_select_all"), "selectAll"),
      item(t("key_unselect_all"), "unselectAll"),
      item(t("key_inverse"), "inverse"),
    ]));
  }

  return el("div", { class: "card keysearch" }, [field]);
}

// Scope control, in the panel head: "Spoofed" (default) lists only keys this module spoofed; "All"
// also shows the apps' own real device keys. Both segments drive the same toggleSpoofed action —
// clicking the active one is a no-op.
//
// The caption underneath is the whole point of pairing them: each mode names what the OTHER one
// holds. In Spoofed the list is a subset, so it says how many real keys it is hiding; in All the
// list is everything, so it says how much of it we actually touched. Either way the number that is
// off-screen (or mixed in) is stated rather than left to be inferred from the row styling.
function scopeControl(spoofedOnly, spoofedCount, hiddenReal, handler) {
  const seg = (label, on, title, onclick) =>
    el("button", {
      class: "seg" + (on ? " on" : ""), type: "button", text: label,
      "aria-pressed": on ? "true" : "false", title, onclick,
    });
  const scope = el("div", { class: "segmented keyscope", role: "group", "aria-label": "Which keys to list" }, [
    seg(t("key_spoofed"), spoofedOnly, t("key_spoofed_title"),
      () => { if (!spoofedOnly) handler("toggleSpoofed"); }),
    seg(t("key_all"), !spoofedOnly, t("key_all_title"),
      () => { if (spoofedOnly) handler("toggleSpoofed"); }),
  ]);

  const caption = spoofedOnly
    ? (hiddenReal ? hiddenReal + " " + t("key_real_keys_hidden") : t("key_no_real_keys_hidden"))
    : spoofedCount + " " + t("key_spoofed_count");

  return el("div", { class: "keyscope-box" }, [
    scope,
    el("span", { class: "keyscope-hint muted", text: caption }),
  ]);
}

function matchesFilter(k, q) {
  return (k.alias || "").toLowerCase().includes(q)
    || (k.package || "").toLowerCase().includes(q)
    || (k.keybox || "").toLowerCase().includes(q);
}

// The app that owns the key: its package when the daemon could resolve one, else the raw uid.
function appLabel(k) {
  return k.package || ("uid " + (k.uid != null ? k.uid : "?"));
}

// keystore2 KeyLifeCycle (1 Live) — the ordinary case is Live, so a chip is only shown to FLAG
// the unusual, keeping rows scannable. (KeyType is not shown: our keys are always Client.)
function abnormalChips(k) {
  const chips = [];
  if (k.state != null && Number(k.state) !== 1) chips.push(el("span", { class: "chip warn", text: stateLabel(k.state) }));
  return chips;
}

function stateLabel(s) {
  return ({ 0: t("key_creating"), 1: t("key_live"), 2: t("key_orphaned") })[Number(s)] || ("state " + s);
}

// The four key classes the daemon reports, in the order spoofed-before-untouched, each with its
// display label and badge modifier class. An unknown/absent class is treated as "untouched".
const KEY_CLASSES = {
  generated: { label: t("key_generated"), cls: "kclass-generated", rank: 0 },
  delegated: { label: t("key_delegated"), cls: "kclass-delegated", rank: 1 },
  patched: { label: t("key_patched"), cls: "kclass-patched", rank: 2 },
  untouched: { label: t("key_untouched"), cls: "kclass-untouched", rank: 3 },
};

function keyClass(k) {
  return KEY_CLASSES[k.class] || KEY_CLASSES.untouched;
}

function classRank(k) {
  return keyClass(k).rank;
}

// A colored badge naming how the key was spoofed (or that it is the app's own untouched key).
function classChip(k) {
  const c = keyClass(k);
  return el("span", { class: "chip kclass " + c.cls, text: c.label });
}

// A key we spoofed (generated / delegated / patched), as opposed to the app's own untouched real key.
// Every listed key belongs to a target app and may be deleted; real ones are just hidden by default.
function isSpoofed(k) {
  return (k.class || "untouched") !== "untouched";
}

// The key's KeyPurpose labels (from the daemon's Tag::PURPOSE read) as small chips, with ATTEST_KEY
// accented since an attestation-capable app key is notable. No chips when the key reports no purposes.
function purposeChips(k) {
  if (!Array.isArray(k.purposes) || !k.purposes.length) return [];
  return [el("div", { class: "keypurposes" }, k.purposes.map((p) =>
    el("span", { class: "chip small purpose" + (p === "AttestKey" ? " attest" : ""), text: p })))];
}

function metaLines(k) {
  const lines = [];
  if (k.keyAlgorithm) lines.push(metaLine(t("key_algorithm"), k.keyAlgorithm));
  // Only attributed keys carry a keybox; omit the line entirely for untouched real keys.
  if (k.keybox) lines.push(metaLine("Keybox", k.keybox));
  if (k.created) lines.push(metaLine(t("key_created"), fmtDate(k.created)));
  return lines;
}

function metaLine(label, value) {
  return el("div", { class: "kmeta" }, [el("b", { text: label + ": " }), value]);
}

function fmtDate(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return "—";
  try { return new Date(n).toISOString().slice(0, 10); } catch { return String(ms); }
}
