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
//               search, filter, userFilter, sort, loading, error, iconUrl,
//               autoOwner, autoInfo, autoCount, pendingSave }
//               - apps            the DRAFT entry strings (packages, pkg@user names + uid: tokens)
//               - autoOwner       Map(uid -> profile name) for uids the DAEMON includes automatically
//                                 (autoIncludeNewApps). These are NEVER in `apps` — config.json does
//                                 not name them — so this is the only way the picker can know. The
//                                 rule itself lives solely in Scope.kt; this file paints its answer.
//               - autoInfo        { baselineReady, epoch } from the daemon's snapshot, or null when
//                                 /scope is unavailable (older daemon) — then no auto state is shown
//               - autoCount       how many uids THIS profile auto-includes, per the last resolve
//               - pendingSave     the draft differs from the saved config, so the daemon's auto set
//                                 is one save behind what is on screen
//
// Row state precedence: selected > claimed (explicit, another profile) > auto > default. A row is
// never both selected and auto: pinning an app removes it from the daemon's auto set on the next
// resolve (Scope.kt drops uids the profile now names explicitly).
//               - packages        the keyAdmin("packages") result, or null while loading; each
//                                 row carries uid/userId/packages/label/system/launchable/enabled
//                                 plus the usage columns installTime/freq/lastUsed/recent, and
//                                 packages.users lists the device's Android users
//               - claimedByOther  Map(entry -> owning profile name) for entries already claimed
//                                 by ANOTHER profile (greyed out and inert here)
//               - firstAppUid     Process.FIRST_APPLICATION_UID; a uid whose APP id (uid % 100000,
//                                 so the test holds in a secondary user too) is below it warns
//               - filter          "recent" | "user" | "system" | "selected" (Recent is default)
//               - userFilter      an Android user id to show alone, or null for every user
//               - sort            "freq" | "recent" | "name" | "install"
//               - iconUrl         fn(pkg, userId) -> a daemon /icon URL string, or null before the
//                                 admin token is in hand; the row <img> falls back to a letter-avatar
//     actions { onClose (leave — asks to keep changes if any), onDone (commit + leave),
//               onToggleApp(entry), onSetSearch(text), onSearchSubmit(),
//               onSetFilter(id), onSetUserFilter(id|null), onOpenSort(), onClearUsage(),
//               onSelectAllVisible(entries), onClearVisible(entries), onInvertVisible(entries) }
//
// One app installed in several Android users is several rows — its work-profile copy runs under its
// own uid and is a separate caller to keystore, so it is targeted separately. A row therefore
// selects the entry naming ITS user: "com.foo" in the primary user, "com.foo@10" in user 10.
//
// Selecting a normal app toggles that PACKAGE-NAME entry (the primary, sorted package), never a
// uid: token — uid tokens are advanced and only ever added/removed manually, or removed from
// the pinned "In scope" section here. The three bulk ops act on the CURRENTLY visible rows
// only: the view computes that set and hands it to the controller as { add, cur } descriptors.

import { el, clear, svgIcon, ICON_SEARCH, ICON_SORT } from "./dom.js";
import { UID_RE, entryToken, splitEntry } from "../domain/schema.js";

const SEARCH_ID = "scope-search-input";

// Recent is first and default: the apps that have asked for a key since this boot are what a
// user most likely wants to target. The rest split into user apps, system, and current picks.
const FILTERS = [
  { id: "recent", label: "Recent" },
  { id: "user", label: "User" },
  { id: "system", label: "System" },
  { id: "selected", label: "Selected" },
];

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

// The apps[] entries that would select this row — one per package it groups, each naming the row's
// Android user. The first is the primary: what a plain tap adds.
function rowEntries(row) {
  return (row.packages || []).map((p) => entryToken(p, row.userId || 0));
}

// The user a row belongs to, as the picker shows it. `users` is the daemon's list; an id missing
// from it (a profile removed between two fetches) still gets an honest "user N" rather than nothing.
function userOf(row, users) {
  const id = row.userId || 0;
  const found = (users || []).find((u) => u.id === id);
  return found || { id, name: id === 0 ? "Owner" : "User " + id, managed: false };
}

export function renderScope(host, state, actions) {
  const focus = captureFocus(host);
  clear(host);

  const {
    profileName, apps = [], packages = null, claimedByOther = new Map(),
    firstAppUid = 10000, search = "", filter = "recent", userFilter = null, sort = "freq",
    loading = false, error = null,
    // Defaulted so an older daemon (no /scope route) renders exactly the previous UI.
    autoOwner = new Map(), autoInfo = null, autoCount = 0, pendingSave = false,
  } = state;
  const iconUrl = typeof state.iconUrl === "function" ? state.iconUrl : () => null;
  // An older daemon answers /packages without `users`; then every row is user 0 and no user
  // segmented control is drawn, which is exactly the single-user device's view too.
  const users = (packages && Array.isArray(packages.users)) ? packages.users : [];

  const appsSet = new Set(apps);
  // "In scope automatically, for THIS profile, and not already pinned." A pinned row is selected,
  // never auto — the two states are exclusive by construction.
  const autoMine = (row) => autoOwner.get(row.uid) === profileName && !isSelected(row, appsSet);

  // ---- header ----------------------------------------------------------
  host.appendChild(el("div", { class: "drill-head" }, [
    el("button", { class: "iconbtn", type: "button", "aria-label": "Back to profile", onclick: () => actions.onClose() }, [
      el("span", { class: "chevron-left", "aria-hidden": "true" }),
    ]),
    el("h1", { class: "drill-title", text: "Scope — " + profileName, tabindex: "-1" }),
  ]));

  const body = el("div", { class: "drill-body" });

  // ---- search row: a leading search-icon button inside the field, a trailing sort button ----
  const searchInput = el("input", {
    id: SEARCH_ID, class: "input scope-search-input", type: "search", value: search,
    placeholder: "Search apps, packages, users, or uid…",
    autocapitalize: "off", autocorrect: "off", spellcheck: "false",
    oninput: (e) => actions.onSetSearch(e.target.value),
    onkeydown: (e) => { if (e.key === "Enter") { e.preventDefault(); actions.onSearchSubmit(); } },
  });
  body.appendChild(el("div", { class: "scope-search" }, [
    el("div", { class: "scope-search-field" }, [
      el("button", { type: "button", class: "scope-search-btn", "aria-label": "Search", onclick: () => actions.onSearchSubmit() }, [
        svgIcon(ICON_SEARCH, { size: 18 }),
      ]),
      searchInput,
      el("button", { type: "button", class: "scope-sort-btn", "aria-label": "Sort order", onclick: () => actions.onOpenSort() }, [
        svgIcon(ICON_SORT, { size: 18 }),
      ]),
    ]),
  ]));

  // ---- group filter: full-width segmented, each seg spanning evenly -----
  body.appendChild(el("div", { class: "segmented scope-filters" },
    FILTERS.map((f) => el("button", {
      type: "button", class: "seg" + (filter === f.id ? " on" : ""),
      "aria-pressed": filter === f.id ? "true" : "false",
      onclick: () => actions.onSetFilter(f.id),
    }, f.label))));

  // ---- user filter: only on a device that HAS more than one user ---------
  // A work profile roughly doubles the list, and the same app then appears once per user, so the
  // narrowing control earns its row there — and is absent (identical to the old UI) everywhere else.
  if (users.length > 1) {
    const segs = [{ id: null, label: "All users" }].concat(
      users.map((u) => ({ id: u.id, label: u.name })));
    body.appendChild(el("div", { class: "segmented scope-users" },
      segs.map((s) => el("button", {
        type: "button", class: "seg" + (userFilter === s.id ? " on" : ""),
        "aria-pressed": userFilter === s.id ? "true" : "false",
        title: s.id == null ? "Show apps from every Android user" : "Show only user " + s.id,
        onclick: () => actions.onSetUserFilter(s.id),
      }, s.label))));
  }

  // ---- loading / error short-circuits ---------------------------------
  if (loading) {
    body.appendChild(el("div", { class: "scope-status" }, [
      el("span", { class: "spinner" }), el("span", { class: "muted", text: "Reading installed apps…" }),
    ]));
  } else if (error) {
    body.appendChild(el("div", { class: "banner error" }, [
      el("div", { text: "Could not read the device app list" }),
      el("div", { class: "muted small", text: String(error) }),
    ]));
  }

  // The installed inventory, for both the pinned "orphan" computation and the main list.
  const installed = (packages && Array.isArray(packages.apps)) ? packages.apps : [];
  // Entries, not bare package names: "com.foo" is installed only if user 0 has it, and the pinned
  // section below decides what to show from exactly that distinction.
  const installedEntries = new Set();
  const installedUids = new Set();
  for (const row of installed) {
    installedUids.add(row.uid);
    rowEntries(row).forEach((e) => installedEntries.add(e));
  }

  // The visible rows: search + group filter, then sorted. Computed once so the ops row and the
  // list share exactly the same set (the ops act only on what the user can see).
  const q = search.trim().toLowerCase();
  // "In scope" means pinned OR auto-included here — an auto row genuinely IS in this profile's
  // scope, so the Selected tab must list it and the float-to-top must lift it.
  const inScope = (row) => isSelected(row, appsSet) || autoMine(row);
  const rows = installed
    .filter((row) => userFilter == null || (row.userId || 0) === userFilter)
    .filter((row) => matchSearch(row, q, userOf(row, users)))
    .filter((row) => matchFilter(row, filter, inScope(row)))
    // Selected rows always float to the top of every group (and of a search result), with the chosen
    // sort applied within the selected and unselected partitions alike — so what you've picked is
    // right there, and the rest stays ordered underneath.
    .sort((a, b) => {
      const sa = inScope(a) ? 0 : 1;
      const sb = inScope(b) ? 0 : 1;
      return sa - sb || compareRows(a, b, sort);
    });

  // Counted over the WHOLE inventory, not the filtered rows, so the badge doesn't jump as the user
  // searches or switches tabs.
  const autoMineShown = installed.filter(autoMine).length;

  // The bulk-op targets: every visible row NOT claimed by another profile AND not a privileged
  // (system/shell) uid — those are excluded so Select-all/Invert can never add a uid < firstAppUid
  // without the deliberate per-row confirm that onToggleApp enforces. Each is { add, cur }: the entry
  // a select would add, and the entry (if any) currently selecting it (to remove).
  // Auto rows are excluded too: they cannot be deselected (there is no per-app exclusion), so
  // Clear and Invert have no meaning on them, and Select-all pinning the whole auto set in one tap
  // is never what the gesture was asking for. Only a deliberate per-row tap pins one.
  const visibleEntries = rows
    // The privileged test is on the APP id: user 10's system uid is 1001000, above firstAppUid yet
    // no less privileged than user 0's 1000.
    .filter((row) => !claimOf(row, claimedByOther) && row.uid % 100000 >= firstAppUid && !autoOwner.has(row.uid))
    .map((row) => {
      const entries = rowEntries(row);
      const add = entries[0] || ("uid:" + row.uid);
      const cur = entries.find((e) => appsSet.has(e)) || (appsSet.has("uid:" + row.uid) ? "uid:" + row.uid : null);
      return { add, cur };
    });

  // ---- ops row: Select all / Clear / Invert (+ Clear usage in Recent) --
  if (!loading && packages) {
    const selectedCount = apps.length;
    const ops = el("div", { class: "scope-ops" }, [
      el("div", { class: "scope-ops-btns" }, [
        el("button", { type: "button", class: "linklike", text: "Select all", onclick: () => actions.onSelectAllVisible(visibleEntries) }),
        el("button", { type: "button", class: "linklike", text: "Clear", onclick: () => actions.onClearVisible(visibleEntries) }),
        el("button", { type: "button", class: "linklike", text: "Invert", onclick: () => actions.onInvertVisible(visibleEntries) }),
        filter === "recent"
          ? el("button", { type: "button", class: "linklike danger", text: "Clear usage", onclick: () => actions.onClearUsage() })
          : null,
      ]),
      el("span", { class: "muted small", text: selectedCount + " selected" + (autoMineShown ? " · " + autoMineShown + " auto" : "") }),
    ]);
    body.appendChild(ops);

    // Say what the dashed rows are. Discovery is the daemon's, so this reports its state rather
    // than deriving anything: an unseeded baseline means the fail-safe in Scope.resolve is holding
    // auto-include back, which is otherwise visible only in logcat.
    const note = autoInfo && autoInfo.baselineReady === false
      ? "Auto-include is idle until the package baseline is seeded."
      : autoCount || autoMineShown
        ? "Auto-include is on — dashed apps are in scope automatically. Tap one to pin it here."
        : null;
    if (note) {
      const kids = [el("span", { text: note })];
      // The draft has diverged from what the daemon resolved, so the dashed set on screen is one
      // save behind. Say so rather than re-deriving the rule to predict it.
      if (pendingSave) kids.push(el("span", { class: "muted", text: " Auto-include updates when you save." }));
      body.appendChild(el("p", { class: "muted small scope-auto-note" }, kids));
    }
  }

  // ---- pinned "In scope" section: selected entries with no visible row -
  // A selected package that is not installed, or a raw uid: token whose uid is not in the live
  // list, has no row below to show it checked — so pin it at the top, always visible, flagged,
  // with a remove ✕. (Installed selections just show checked in the list.)
  const orphans = apps.filter((entry) => {
    if (UID_RE.test(entry)) return !installedUids.has(Number(entry.slice(4)));
    return !installedEntries.has(entry);
  });
  if (orphans.length) {
    body.appendChild(el("div", { class: "scope-pinned" }, [
      el("div", { class: "scope-section-title", text: "In scope" }),
      el("div", { class: "applist" }, orphans.map((entry) => {
        const isUid = UID_RE.test(entry);
        const { pkg, userId } = splitEntry(entry);
        // "Not installed" is a per-user answer: the app may well be on the device, just not in the
        // user this entry names, and saying so is the difference between a typo and a stale target.
        const where = userId ? " for " + userOf({ userId }, users).name : "";
        return el("span", {
          class: "chip removable scope-chip" + (isUid ? " advanced" : " warn"),
          title: isUid
            ? "Advanced: targets caller uid " + entry.slice(4)
            : pkg + " is not installed" + (where || " on this device"),
        }, [
          isUid ? el("span", { class: "chip-avatar-uid", "aria-hidden": "true", text: "#" }) : null,
          el("span", { class: "chip-text" + (isUid ? " mono" : ""), text: entry }),
          el("span", { class: "chip-sub", text: isUid ? "advanced uid" : "not installed" + where }),
          el("button", { type: "button", class: "chip-x", "aria-label": "Remove " + entry, text: "✕", onclick: () => actions.onToggleApp(entry) }),
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
        list.appendChild(scopeRow(row, { appsSet, claimedByOther, firstAppUid, iconUrl, autoOwner, profileName, users, showUser: users.length > 1 }, actions));
      }
      body.appendChild(list);
    }
  }

  host.appendChild(body);

  // ---- footer: live count + Done --------------------------------------
  host.appendChild(el("div", { class: "drill-foot" }, [
    el("span", { class: "status" }, [
      el("span", { class: "dot ok" }),
      el("span", { class: "muted small", text: apps.length + " selected" + (autoMineShown ? " · " + autoMineShown + " auto" : "") }),
    ]),
    el("button", { class: "btn primary", text: "Done", onclick: () => actions.onDone() }),
  ]));

  restoreFocus(focus);
}

// The empty-list line, worded for the active group so it never reads as an error.
function emptyText(filter, total, q) {
  if (!total) return "No apps found on the device.";
  if (q) return "No apps match “" + q + "”.";
  if (filter === "recent") return "No app has requested a key since boot yet.";
  if (filter === "selected") return "Nothing in scope yet — tap an app to add it.";
  return "No apps match.";
}

// Is this uid-row currently in scope — by one of its entries (each naming this row's user), or by
// a uid: token?
function isSelected(row, appsSet) {
  if (appsSet.has("uid:" + row.uid)) return true;
  return rowEntries(row).some((e) => appsSet.has(e));
}

function matchSearch(row, q, user) {
  if (!q) return true;
  if (row.label && row.label.toLowerCase().includes(q)) return true;
  if (String(row.uid).includes(q)) return true;
  // The user is searchable by name and by its entry suffix, so "@10" and "work" both narrow to it.
  if (user && user.name && user.name.toLowerCase().includes(q)) return true;
  return rowEntries(row).some((e) => e.toLowerCase().includes(q));
}

function matchFilter(row, filter, selected) {
  if (filter === "selected") return selected;
  if (filter === "recent") return row.recent === true;
  const isUser = row.launchable && !row.system;
  if (filter === "user") return isUser;
  if (filter === "system") return row.system || !row.launchable;
  return true;
}

// Whom does this row belong to elsewhere? Any of its entries or its uid token; null if free. The
// entries carry the row's user, so another profile holding the SAME app in a DIFFERENT user does
// not claim this row — two users' copies are two callers and may legitimately sit apart.
function claimOf(row, claimedByOther) {
  for (const e of rowEntries(row)) if (claimedByOther.has(e)) return claimedByOther.get(e);
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
//
// The third state is auto-include: the daemon already targets this uid, but config.json does not
// name it. Such a row is painted dashed with a hollow dot — deliberately NOT the solid tick — and
// stays TAPPABLE, because tapping pins it (Scope.resolve then drops it from the auto set, since the
// profile now names it explicitly). Un-pinning returns it to auto, not to excluded: there is no
// per-app exclusion, so the check is honestly a pin/unpin control whose "off" floor is "still in
// scope automatically". The title says exactly that, because the pill alone cannot.
function scopeRow(row, ctx, actions) {
  const {
    appsSet, claimedByOther, firstAppUid, iconUrl, autoOwner = new Map(), profileName,
    users = [], showUser = false,
  } = ctx;
  const pkgs = (row.packages || []).slice();
  const entries = rowEntries(row);
  const primary = entries[0] || ("uid:" + row.uid);
  const label = row.label || pkgs[0] || primary;
  const user = userOf(row, users);

  const selectedByPkg = entries.find((e) => appsSet.has(e));
  const selectedByUid = appsSet.has("uid:" + row.uid);
  const selected = !!selectedByPkg || selectedByUid;

  const claimedBy = claimOf(row, claimedByOther);
  // Asked of the app id, not the raw uid: user 10's system_server is uid 1001000, which is above
  // firstAppUid yet every bit as privileged as user 0's 1000.
  const lowUid = row.uid % 100000 < firstAppUid;

  // The entry a tap acts on: the package/token that is selected (to remove it) or the primary
  // package (to add it).
  const toggleEntry = selectedByPkg || (selectedByUid ? ("uid:" + row.uid) : primary);

  const pkgLine = entries.length
    ? (entries.length === 1 ? entries[0] : entries[0] + " +" + (entries.length - 1))
    : "uid:" + row.uid;

  const autoBy = autoOwner.get(row.uid) || null;
  const autoMine = !!autoBy && autoBy === profileName && !selected;
  const autoOther = !!autoBy && autoBy !== profileName;

  const pills = [];
  // Which user this copy of the app lives in — drawn only where the device actually has more than
  // one, so a single-user phone keeps the row it always had.
  if (showUser)
    pills.push(el("span", {
      class: "pill scope-user" + (user.managed ? " managed" : ""),
      title: "Installed for user " + user.id + (user.managed ? " (work profile)" : ""),
      text: user.name,
    }));
  if (lowUid) pills.push(el("span", { class: "pill warn scope-pill", text: "system uid" }));
  if (claimedBy) pills.push(el("span", { class: "chip small scope-claimed", text: "in " + claimedBy }));
  if (autoMine) pills.push(el("span", { class: "pill scope-auto", text: "auto" }));
  if (autoOther) pills.push(el("span", { class: "chip small scope-claimed", text: "auto in " + autoBy }));
  if (row.recent) pills.push(el("span", { class: "scope-recent-dot", title: "Requested a key since boot", "aria-label": "recent" }));
  if (row.freq > 0) pills.push(el("span", { class: "scope-freq", title: row.freq + " key requests recorded", text: fmtFreq(row.freq) }));

  const cls = "scope-row" + (selected ? " selected" : autoMine ? " auto" : "") + (claimedBy ? " claimed" : "");

  // Only an explicit claim by another profile disables a row. An auto row — mine or another's —
  // stays tappable: Scope.resolve excludes explicitly-named uids from auto-include, so an explicit
  // pick legally beats auto and the UI must not forbid what the daemon permits.
  const title = claimedBy ? "Already targeted by profile " + claimedBy
    : autoMine ? "In scope automatically — tap to pin it to " + profileName +
      ". To exclude it, turn off Auto-include new apps."
    : autoOther ? "Auto-included by profile " + autoBy + " — tap to pin it here instead."
    : label;

  return el("button", {
    type: "button", class: cls, disabled: !!claimedBy,
    // Left false for an auto row: the user did not press it. The pill and title carry that truth.
    "aria-pressed": selected ? "true" : "false",
    title,
    onclick: claimedBy ? null : () => actions.onToggleApp(toggleEntry),
  }, [
    iconEl(row, pkgs[0] || primary, label, iconUrl),
    el("span", { class: "scope-meta" }, [
      el("span", { class: "scope-label" }, [
        el("span", { class: "scope-name", text: label }),
        ...pills,
      ]),
      el("span", { class: "scope-pkg mono", text: pkgLine + "  ·  uid " + row.uid + (row.enabled === false ? "  ·  disabled" : "") }),
    ]),
    el("span", { class: "scope-check" + (selected ? " on" : autoMine ? " auto" : ""), "aria-hidden": "true" }),
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
  // The user rides along: an app that exists only in a work profile has no record in user 0 for the
  // daemon to read an icon out of.
  const url = pkg ? iconUrl(pkg, row.userId || 0) : null;
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
