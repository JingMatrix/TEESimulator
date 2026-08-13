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

  // Panel head: the title and, on the right, the scope control. The scope control is filled into this
  // stable slot once the counts it reports are known (below). It lives here alone so it never moves —
  // the Delete-selected action is a separate bar, so selecting keys can't shift the toggle.
  const scopeSlot = el("div", { class: "panel-actions" });
  mount.appendChild(el("div", { class: "panel-head" }, [
    el("h1", { class: "panel-title", text: t("key_title") }),
    scopeSlot,
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

  // Delete-selected: a full-width button shown only when keys are checked. Kept out of the panel head
  // (below the title, above the list) so its appearing and disappearing never moves the scope toggle.
  // Its label counts the selection, which the controller keeps pruned to what's on screen.
  if (selected.size) {
    mount.appendChild(el("button", {
      class: "btn danger block", disabled: deleting,
      text: deleting ? t("key_deleting") : t("key_delete_selected") + " (" + selected.size + ")",
      onclick: () => handler("deleteSelected"),
    }));
  }

  // Play Integrity signs with the Play Store's dedicated key (com.android.vending,
  // integrity.api.key.alias). While that key is untouched its attestation roots in the genuine TEE —
  // outside anything this module rewrote — so the verdict is decided without the keybox. Warn over ALL
  // keys (untouched ones are hidden by default), and point at the fix: delete it so the next
  // attestation is forced through a key this module controls.
  const vendingUntouched = keys.filter(isUntouchedVendingSignKey);
  if (vendingUntouched.length) {
    mount.appendChild(el("div", { class: "card" }, [el("div", { class: "banner warn" }, [
      el("div", { text: t("key_vending_warning_title") }),
      el("div", { class: "muted small", text: t("key_vending_warning_sub") }),
    ])]));
  }

  // Matching is a structured query (free-text substring over alias/app/keybox, plus tappable
  // class:/app:/purpose: badge tokens — see parseKeyFilter). Spoofed keys (generated / delegated /
  // patched) sort ahead of untouched ones; the sort is stable, so within a class the daemon's
  // namespace+alias order is preserved.
  const query = parseKeyFilter(filter);
  const matchedAll = query.empty ? keys : keys.filter((k) => matchesFilter(k, query));
  // The apps' own untouched (real hardware) keys are hidden by default so the list shows only what we
  // spoofed; the "All" segment reveals them for inspection or deletion. Both counts are taken over the
  // same filtered population, so the two segments describe it from opposite sides — "Spoofed" reports
  // what it is holding back, "All" reports how much of what you are looking at we actually touched.
  const spoofedCount = matchedAll.filter(isSpoofed).length;
  const hiddenReal = matchedAll.length - spoofedCount;
  const matched = spoofedOnly ? matchedAll.filter(isSpoofed) : matchedAll;
  const shown = matched.slice().sort((a, b) => classRank(a) - classRank(b));

  // Fill the stable scope-control slot now the counts are known (see panel head above). Reloading is a
  // pull-to-refresh away, so the header is spent on the one control that changes what the screen shows.
  scopeSlot.appendChild(scopeControl(spoofedOnly, spoofedCount, hiddenReal, handler));

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
  // Which filter tokens are currently active, so a tapped badge can show it is in effect. Every raw
  // token, lowercased; the badges' tokens are lowercased too, so typed and tapped filters agree.
  const activeTokens = new Set(filter.trim().toLowerCase().split(/\s+/).filter(Boolean));
  const ctx = { handler, active: activeTokens };

  const list = el("ul", { class: "keylist" });
  for (const k of shown) {
    const checked = selected.has(k.id);
    const check = el("input", { type: "checkbox", checked, onchange: () => handler("toggle", k.id) });
    list.appendChild(el("li", { class: "keyrow" + (checked ? " selected" : "") }, [
      el("label", { class: "keycheck" }, [check]),
      el("div", { class: "keymeta" }, [
        el("div", { class: "keyalias" }, [
          el("span", { class: "mono", text: k.alias || t("key_no_alias") }),
          classChip(k, ctx),
          appChip(k, ctx),
          ...abnormalChips(k),
        ]),
        ...purposeChips(k, ctx),
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
    placeholder: t("key_filter_placeholder_syntax"),
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

// Field aliases the filter syntax accepts, each mapped to its canonical field.
const FILTER_FIELDS = { class: "class", status: "class", app: "app", pkg: "app", package: "app", purpose: "purpose" };

// Parse the filter box into a structured query. Whitespace-separated tokens: a `field:value` token
// (field ∈ class/status, app/pkg/package, purpose) is a typed term; anything else is free text. Typed
// terms of the SAME field are OR'd, DIFFERENT fields are AND'd, and every free term must match — so two
// app badges widen within apps while adding a purpose narrows across. Tapping a badge writes exactly
// this syntax (see filterChip), which the user can equally type by hand.
export function parseKeyFilter(text) {
  const free = [];
  const fields = { class: [], app: [], purpose: [] };
  for (const tok of (text || "").trim().toLowerCase().split(/\s+/)) {
    if (!tok) continue;
    const i = tok.indexOf(":");
    const field = i > 0 ? FILTER_FIELDS[tok.slice(0, i)] : null;
    if (field) fields[field].push(tok.slice(i + 1));
    else free.push(tok);
  }
  return { free, fields, empty: !free.length && !fields.class.length && !fields.app.length && !fields.purpose.length };
}

// True iff a key satisfies the parsed query (see parseKeyFilter for the AND/OR rules).
function matchesFilter(k, q) {
  const pkg = (k.package || "").toLowerCase();
  const hay = (k.alias || "").toLowerCase() + "\n" + pkg + "\n" + (k.keybox || "").toLowerCase();
  for (const t of q.free) if (!hay.includes(t)) return false;
  if (q.fields.class.length && !q.fields.class.includes((k.class || "untouched").toLowerCase())) return false;
  if (q.fields.app.length && !q.fields.app.some((v) => pkg.includes(v))) return false;
  if (q.fields.purpose.length) {
    const ps = (Array.isArray(k.purposes) ? k.purposes : []).map((p) => String(p).toLowerCase());
    if (!q.fields.purpose.some((v) => ps.includes(v))) return false;
  }
  return true;
}

// The app that owns the key: its package when the daemon could resolve one, else the raw uid.
function appLabel(k) {
  return k.package || ("uid " + (k.uid != null ? k.uid : "?"));
}

// A badge that doubles as a filter toggle. Tapping it toggles its token in the filter box — toggle by
// VALUE, so tapping the same badge on another row never duplicates the token, it removes it. It shows
// an active state while its token is in effect. A real <button> for keyboard/AT reach; the token is
// canonical lowercase (the fields are closed sets / package names), so taps and typed syntax agree.
function filterChip(token, extraCls, label, ctx) {
  const on = ctx.active.has(token.toLowerCase());
  return el("button", {
    type: "button",
    class: "chip chip-tap " + extraCls + (on ? " active" : ""),
    "aria-pressed": on ? "true" : "false",
    title: (on ? t("key_filter_chip_clear") : t("key_filter_chip_set")) + token,
    text: label,
    onclick: () => ctx.handler("toggleToken", token),
  });
}

// The owning-app badge: a filter toggle on app:<package> when the package is known, else a plain,
// unfilterable chip for a bare uid (nothing well-defined to group by).
function appChip(k, ctx) {
  if (!k.package) return el("span", { class: "chip", text: appLabel(k) });
  return filterChip("app:" + k.package, "", appLabel(k), ctx);
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

// A colored badge naming how the key was spoofed (or that it is the app's own untouched key). Also a
// filter toggle on class:<class>.
function classChip(k, ctx) {
  const c = keyClass(k);
  return filterChip("class:" + (k.class || "untouched"), "kclass " + c.cls, c.label, ctx);
}

// A key we spoofed (generated / delegated / patched), as opposed to the app's own untouched real key.
// Every listed key belongs to a target app and may be deleted; real ones are just hidden by default.
function isSpoofed(k) {
  return (k.class || "untouched") !== "untouched";
}

// The Play Integrity signing key we never touched: the one case that lets Play Integrity attest
// through the real TEE. It is the Play Store's dedicated integrity key — alias integrity.api.key.alias
// — left untouched (not spoofed). Other com.android.vending sign keys aren't the integrity signer, so
// they don't get flagged.
const INTEGRITY_KEY_ALIAS = "integrity.api.key.alias";
function isUntouchedVendingSignKey(k) {
  return !isSpoofed(k)
    && k.package === "com.android.vending"
    && k.alias === INTEGRITY_KEY_ALIAS;
}

// The key's KeyPurpose labels (from the daemon's Tag::PURPOSE read) as small chips, with ATTEST_KEY
// accented since an attestation-capable app key is notable. Each is a filter toggle on purpose:<label>.
// No chips when the key reports no purposes.
function purposeChips(k, ctx) {
  if (!Array.isArray(k.purposes) || !k.purposes.length) return [];
  return [el("div", { class: "keypurposes" }, k.purposes.map((p) =>
    filterChip("purpose:" + String(p).toLowerCase(), "small purpose" + (p === "AttestKey" ? " attest" : ""), p, ctx)))];
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
