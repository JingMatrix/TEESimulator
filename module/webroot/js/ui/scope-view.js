// The Scope picker: a full-screen drill-in that turns a profile's opaque list of
// package strings into a browsable, searchable, sortable view of the LIVE device app list.
// It is the counterpart to config-view's editor drill-in and follows the exact same
// contract — stateless, rebuilt on every call, no imports from data/* or bridge/*. The
// controller owns all state (the fetched /packages result, the search text, the filter, the
// sort, this profile's DRAFT apps array) and hands a fresh snapshot in on every intent; this
// file only paints it and calls back through `actions`. It never writes into the profile —
// the controller mutates a draft and asks to save on the way out.
//
//   renderScope(host, state, actions)
//     host    the overlay content node (an .editor-host div)
//     state   { profileName, apps, packages, claimedByOther, firstAppUid,
//               search, filter, sort, loading, error, iconUrl }
//               - apps            the DRAFT entry strings (packages + uid: tokens)
//               - packages        the keyAdmin("packages") result, or null while loading; each
//                                 row carries uid/packages/label/system/launchable/enabled plus
//                                 the usage columns installTime/freq/lastUsed/recent
//               - claimedByOther  Map(entry -> owning profile name) for entries already claimed
//                                 by ANOTHER profile (greyed out and inert here)
//               - firstAppUid     Process.FIRST_APPLICATION_UID; uids below it warn
//               - filter          "recent" | "user" | "system" | "selected" (Recent is default)
//               - sort            "freq" | "recent" | "name" | "install"
//               - iconUrl         fn(pkg) -> a daemon /icon URL string, or null before the admin
//                                 token is in hand; the row <img> falls back to a letter-avatar
//     actions { onClose (leave — asks to keep changes if any), onDone (commit + leave),
//               onToggleApp(entry), onSetSearch(text), onSearchSubmit(),
//               onSetFilter(id), onOpenSort(), onClearUsage(),
//               onSelectAllVisible(entries), onClearVisible(entries), onInvertVisible(entries) }
//
// Selecting a normal app toggles its PACKAGE-NAME entry (the primary, sorted package), never a
// uid: token — uid tokens are advanced and only ever added/removed manually, or removed from
// the pinned "In scope" section here. The three bulk ops act on the CURRENTLY visible rows
// only: the view computes that set and hands it to the controller as { add, cur } descriptors.

import { el, clear, svgIcon, ICON_SEARCH, ICON_SORT } from "./dom.js";
import { UID_RE } from "../domain/schema.js";
import { t } from "../i18n.js";

const SEARCH_ID = "scope-search-input";

function getFilters() {
  return [
    { id: "recent", label: t("scope_filter_recent") },
    { id: "user", label: t("scope_filter_user") },
    { id: "system", label: t("scope_filter_system") },
    { id: "selected", label: t("scope_filter_selected") },
  ];
}

// A stable, pleasant avatar colour from any string: a tiny rolling hash into a hue, with fixed
// saturation/lightness so white avatar text always reads. This is the one place a literal colour
// is computed (an hsl()) rather than read from a token — an avatar tint is inherently per-item
// and cannot come from the small theme palette.
function hashColor(str) {
  let h = 0;
  const s = String(str || "");
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return `hsl(${h % 360} 52% 42%)`;
}

// The avatar glyph: first letter of the label (or package, or "?"), uppercased.
function avatarLetter(label, pkg) {
  const src = (label && label.trim()) || pkg || "?";
  const ch = src.trim().charAt(0);
  return /[a-z0-9]/i.test(ch) ? ch.toUpperCase() : "#";
}

export function renderScope(host, state, actions) {
  const focus = captureFocus(host);
  clear(host);

  const {
    profileName, apps = [], packages = null, claimedByOther = new Map(),
    firstAppUid = 10000, search = "", filter = "recent", sort = "freq",
    loading = false, error = null,
  } = state;
  const iconUrl = typeof state.iconUrl === "function" ? state.iconUrl : () => null;

  const appsSet = new Set(apps);

  // ---- header ----------------------------------------------------------
  host.appendChild(el("div", { class: "drill-head" }, [
    el("button", { class: "iconbtn", type: "button", "aria-label": t("scope_back_to_profile"), onclick: () => actions.onClose() }, [
      el("span", { class: "chevron-left", "aria-hidden": "true" }),
    ]),
    el("h1", { class: "drill-title", text: t("scope_title") + " — " + profileName, tabindex: "-1" }),
  ]));

  const body = el("div", { class: "drill-body" });

  // ---- search row: a leading search-icon button inside the field, a trailing sort button ----
  const searchInput = el("input", {
    id: SEARCH_ID, class: "input scope-search-input", type: "search", value: search,
    placeholder: t("scope_search_placeholder"),
    autocapitalize: "off", autocorrect: "off", spellcheck: "false",
    oninput: (e) => actions.onSetSearch(e.target.value),
    onkeydown: (e) => { if (e.key === "Enter") { e.preventDefault(); actions.onSearchSubmit(); } },
  });
  body.appendChild(el("div", { class: "scope-search" }, [
    el("div", { class: "scope-search-field" }, [
      el("button", { type: "button", class: "scope-search-btn", "aria-label": t("scope_search"), onclick: () => actions.onSearchSubmit() }, [
        svgIcon(ICON_SEARCH, { size: 18 }),
      ]),
      searchInput,
      el("button", { type: "button", class: "scope-sort-btn", "aria-label": t("scope_sort_order"), onclick: () => actions.onOpenSort() }, [
        svgIcon(ICON_SORT, { size: 18 }),
      ]),
    ]),
  ]));

  // ---- group filter: full-width segmented, each seg spanning evenly -----
  body.appendChild(el("div", { class: "segmented scope-filters" },
    getFilters().map((f) => el("button", {
      type: "button", class: "seg" + (filter === f.id ? " on" : ""),
      "aria-pressed": filter === f.id ? "true" : "false",
      onclick: () => actions.onSetFilter(f.id),
    }, f.label))));

  // ---- loading / error short-circuits ---------------------------------
  if (loading) {
    body.appendChild(el("div", { class: "scope-status" }, [
      el("span", { class: "spinner" }), el("span", { class: "muted", text: t("scope_reading_apps") }),
    ]));
  } else if (error) {
    body.appendChild(el("div", { class: "banner error" }, [
      el("div", { text: t("scope_read_apps_error") }),
      el("div", { class: "muted small", text: String(error) }),
    ]));
  }

  // The installed inventory, for both the pinned "orphan" computation and the main list.
  const installed = (packages && Array.isArray(packages.apps)) ? packages.apps : [];
  const installedPkgs = new Set();
  const installedUids = new Set();
  for (const row of installed) {
    installedUids.add(row.uid);
    (row.packages || []).forEach((p) => installedPkgs.add(p));
  }

  // The visible rows: search + group filter, then sorted. Computed once so the ops row and the
  // list share exactly the same set (the ops act only on what the user can see).
  const q = search.trim().toLowerCase();
  const rows = installed
    .filter((row) => matchSearch(row, q))
    .filter((row) => matchFilter(row, filter, isSelected(row, appsSet)))
    // Selected rows always float to the top of every group (and of a search result), with the chosen
    // sort applied within the selected and unselected partitions alike — so what you've picked is
    // right there, and the rest stays ordered underneath.
    .sort((a, b) => {
      const sa = isSelected(a, appsSet) ? 0 : 1;
      const sb = isSelected(b, appsSet) ? 0 : 1;
      return sa - sb || compareRows(a, b, sort);
    });

  // The bulk-op targets: every visible row NOT claimed by another profile AND not a privileged
  // (system/shell) uid — those are excluded so Select-all/Invert can never add a uid < firstAppUid
  // without the deliberate per-row confirm that onToggleApp enforces. Each is { add, cur }: the entry
  // a select would add, and the entry (if any) currently selecting it (to remove).
  const visibleEntries = rows
    .filter((row) => !claimOf(row, claimedByOther) && row.uid >= firstAppUid)
    .map((row) => {
      const pkgs = row.packages || [];
      const add = pkgs[0] || ("uid:" + row.uid);
      const cur = pkgs.find((p) => appsSet.has(p)) || (appsSet.has("uid:" + row.uid) ? "uid:" + row.uid : null);
      return { add, cur };
    });

  // ---- ops row: Select all / Clear / Invert (+ Clear usage in Recent) --
  if (!loading && packages) {
    const selectedCount = apps.length;
    const ops = el("div", { class: "scope-ops" }, [
      el("div", { class: "scope-ops-btns" }, [
        el("button", { type: "button", class: "linklike", text: t("scope_select_all"), onclick: () => actions.onSelectAllVisible(visibleEntries) }),
        el("button", { type: "button", class: "linklike", text: t("scope_clear"), onclick: () => actions.onClearVisible(visibleEntries) }),
        el("button", { type: "button", class: "linklike", text: t("scope_invert"), onclick: () => actions.onInvertVisible(visibleEntries) }),
        filter === "recent"
          ? el("button", { type: "button", class: "linklike danger", text: t("scope_clear_usage"), onclick: () => actions.onClearUsage() })
          : null,
      ]),
      el("span", { class: "muted small", text: selectedCount + " " + t("scope_selected_count") }),
    ]);
    body.appendChild(ops);
  }

  // ---- pinned "In scope" section: selected entries with no visible row -
  // A selected package that is not installed, or a raw uid: token whose uid is not in the live
  // list, has no row below to show it checked — so pin it at the top, always visible, flagged,
  // with a remove ✕. (Installed selections just show checked in the list.)
  const orphans = apps.filter((entry) => {
    if (UID_RE.test(entry)) return !installedUids.has(Number(entry.slice(4)));
    return !installedPkgs.has(entry);
  });
  if (orphans.length) {
    body.appendChild(el("div", { class: "scope-pinned" }, [
      el("div", { class: "scope-section-title", text: t("scope_in_scope") }),
      el("div", { class: "applist" }, orphans.map((entry) => {
        const isUid = UID_RE.test(entry);
        return el("span", {
          class: "chip removable scope-chip" + (isUid ? " advanced" : " warn"),
          title: isUid ? t("scope_advanced_uid_prefix") + entry.slice(4) : entry + " " + t("scope_not_installed_suffix"),
        }, [
          isUid ? el("span", { class: "chip-avatar-uid", "aria-hidden": "true", text: "#" }) : null,
          el("span", { class: "chip-text" + (isUid ? " mono" : ""), text: entry }),
          el("span", { class: "chip-sub", text: isUid ? t("scope_advanced_uid_chip") : t("scope_not_installed_chip") }),
          el("button", { type: "button", class: "chip-x", "aria-label": t("field_remove") + " " + entry, text: "✕", onclick: () => actions.onToggleApp(entry) }),
        ]);
      })),
    ]));
  }

  // ---- the main list ---------------------------------------------------
  if (!loading && packages) {
    // Suppress the "nothing here" card when the Selected group's only picks are orphans — they are
    // already shown, checked, in the pinned "In scope" section right above, so an empty card would
    // contradict it.
    const orphansShown = filter === "selected" && !q && orphans.length > 0;
    if (!rows.length && !orphansShown) {
      body.appendChild(el("div", { class: "card empty" }, [
        el("p", { class: "muted", text: emptyText(filter, installed.length, q) }),
      ]));
    } else if (rows.length) {
      const list = el("div", { class: "scope-list" });
      for (const row of rows) {
        list.appendChild(scopeRow(row, { appsSet, claimedByOther, firstAppUid, iconUrl }, actions));
      }
      body.appendChild(list);
    }
  }

  host.appendChild(body);

  // ---- footer: live count + Done --------------------------------------
  host.appendChild(el("div", { class: "drill-foot" }, [
    el("span", { class: "status" }, [
      el("span", { class: "dot ok" }),
      el("span", { class: "muted small", text: apps.length + " " + t("scope_selected_count") }),
    ]),
    el("button", { class: "btn primary", text: t("btn_done"), onclick: () => actions.onDone() }),
  ]));

  restoreFocus(focus);
}

// The empty-list line, worded for the active group so it never reads as an error.
function emptyText(filter, total, q) {
  if (!total) return t("scope_empty_no_apps");
  if (q) return t("scope_empty_no_match_prefix") + q + t("scope_empty_no_match_suffix");
  if (filter === "recent") return t("scope_empty_no_recent");
  if (filter === "selected") return t("scope_empty_no_selected");
  return t("scope_empty_no_match_generic");
}

// Is this uid-row currently in scope — by any of its package names, or by a uid: token?
function isSelected(row, appsSet) {
  if (appsSet.has("uid:" + row.uid)) return true;
  return (row.packages || []).some((p) => appsSet.has(p));
}

function matchSearch(row, q) {
  if (!q) return true;
  if (row.label && row.label.toLowerCase().includes(q)) return true;
  if (String(row.uid).includes(q)) return true;
  return (row.packages || []).some((p) => p.toLowerCase().includes(q));
}

function matchFilter(row, filter, selected) {
  if (filter === "selected") return selected;
  if (filter === "recent") return row.recent === true;
  const isUser = row.launchable && !row.system;
  if (filter === "user") return isUser;
  if (filter === "system") return row.system || !row.launchable;
  return true;
}

// Whom does this row belong to elsewhere? Any of its packages or its uid token; null if free.
function claimOf(row, claimedByOther) {
  for (const p of (row.packages || [])) if (claimedByOther.has(p)) return claimedByOther.get(p);
  if (claimedByOther.has("uid:" + row.uid)) return claimedByOther.get("uid:" + row.uid);
  return null;
}

// The list order, per the chosen sort. Frequency and install/recency are numeric with a label
// tiebreak so equal-usage apps still read alphabetically; Name is a pure locale compare. The
// Recent GROUP is a filter, not a sort — it can be viewed in any of these orders.
function compareRows(a, b, sort) {
  if (sort === "name") return byLabel(a, b);
  if (sort === "recent") return (b.lastUsed || 0) - (a.lastUsed || 0) || byLabel(a, b);
  if (sort === "install") return (b.installTime || 0) - (a.installTime || 0) || byLabel(a, b);
  return (b.freq || 0) - (a.freq || 0) || byLabel(a, b); // "freq" (default)
}

function byLabel(a, b) {
  return String(a.label || "").localeCompare(String(b.label || ""));
}

// One tappable row for a uid. Selecting toggles the primary package-name entry (or, when the row
// is already selected via a specific package / uid token, that same entry, so a tap truly
// un-selects). A row already owned by another profile is greyed out and inert.
function scopeRow(row, ctx, actions) {
  const { appsSet, claimedByOther, firstAppUid, iconUrl } = ctx;
  const pkgs = (row.packages || []).slice();
  const primary = pkgs[0] || ("uid:" + row.uid);
  const label = row.label || primary;

  const selectedByPkg = pkgs.find((p) => appsSet.has(p));
  const selectedByUid = appsSet.has("uid:" + row.uid);
  const selected = !!selectedByPkg || selectedByUid;

  const claimedBy = claimOf(row, claimedByOther);
  const lowUid = row.uid < firstAppUid;

  // The entry a tap acts on: the package/token that is selected (to remove it) or the primary
  // package (to add it).
  const toggleEntry = selectedByPkg || (selectedByUid ? ("uid:" + row.uid) : primary);

  const pkgLine = pkgs.length
    ? (pkgs.length === 1 ? pkgs[0] : pkgs[0] + " +" + (pkgs.length - 1))
    : "uid:" + row.uid;

  const pills = [];
  if (lowUid) pills.push(el("span", { class: "pill warn scope-pill", text: t("scope_pill_system_uid") }));
  if (claimedBy) pills.push(el("span", { class: "chip small scope-claimed", text: t("scope_pill_claimed_prefix") + claimedBy }));
  if (row.recent) pills.push(el("span", { class: "scope-recent-dot", title: t("scope_recent_title"), "aria-label": "recent" }));
  if (row.freq > 0) pills.push(el("span", { class: "scope-freq", title: row.freq + " " + t("scope_freq_title_suffix"), text: fmtFreq(row.freq) }));

  const cls = "scope-row" + (selected ? " selected" : "") + (claimedBy ? " claimed" : "");

  return el("button", {
    type: "button", class: cls, disabled: !!claimedBy,
    "aria-pressed": selected ? "true" : "false",
    title: claimedBy ? t("scope_already_targeted_prefix") + claimedBy : label,
    onclick: claimedBy ? null : () => actions.onToggleApp(toggleEntry),
  }, [
    iconEl(row, primary, label, iconUrl),
    el("span", { class: "scope-meta" }, [
      el("span", { class: "scope-label" }, [
        el("span", { class: "scope-name", text: label }),
        ...pills,
      ]),
      el("span", { class: "scope-pkg mono", text: pkgLine + "  ·  uid " + row.uid + (row.enabled === false ? "  ·  " + t("scope_disabled_suffix") : "") }),
    ]),
    el("span", { class: "scope-check" + (selected ? " on" : ""), "aria-hidden": "true" }),
  ]);
}

// The lazy app icon: an <img loading="lazy"> pointing at the daemon's /icon route, with a
// letter-avatar as the fallback both before a URL exists and when the image fails to decode
// (no such icon, 404). The avatar is swapped in on error so a broken icon never shows.
function iconEl(row, primary, label, iconUrl) {
  const wrap = el("span", { class: "scope-ico", "aria-hidden": "true" });
  const avatar = () => el("span", {
    class: "scope-avatar", style: "background:" + hashColor(label + "/" + row.uid), text: avatarLetter(row.label, primary),
  });
  const pkg = (row.packages || [])[0];
  const url = pkg ? iconUrl(pkg) : null;
  if (!url) { wrap.appendChild(avatar()); return wrap; }
  const img = el("img", {
    class: "scope-ico-img", loading: "lazy", decoding: "async", alt: "", src: url,
    onerror: () => { const a = avatar(); if (img.parentNode) img.replaceWith(a); },
  });
  wrap.appendChild(img);
  return wrap;
}

// A compact frequency label: raw under 1k, else "1.2k" so a busy app's badge stays narrow.
function fmtFreq(n) {
  if (n < 1000) return String(n);
  return (n / 1000).toFixed(n < 10000 ? 1 : 0).replace(/\.0$/, "") + "k";
}

// ---- focus retention across the stateless rebuild -----------------------
// Only the search input needs it (typing re-renders the whole page); mirror the config-view
// pattern so the caret and selection survive.
function captureFocus(container) {
  const active = document.activeElement;
  const id = active && container.contains(active) ? active.id : null;
  let selStart = null, selEnd = null;
  try { selStart = active.selectionStart; selEnd = active.selectionEnd; } catch { /* not a text input */ }
  return { id, selStart, selEnd };
}

function restoreFocus(f) {
  if (!f.id) return;
  const again = document.getElementById(f.id);
  if (!again) return;
  again.focus({ preventScroll: true });
  try { if (f.selStart != null) again.setSelectionRange(f.selStart, f.selEnd); } catch { /* not selectable */ }
}
