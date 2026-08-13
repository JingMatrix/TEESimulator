// Owns config state and the load -> edit -> validate -> save cycle. This is the ONE
// place the config object lives; the list and the editor drill-in are handed a
// snapshot and hand intents back through the `actions` seams below. Nothing here
// reaches the shell except via data/config-io.js.
//
// Navigation: the resting screen is the profile LIST (rendered into the tab mount).
// Tapping a row (or Add) opens the profile EDITOR as a drill-in overlay via the
// shared openOverlay helper, so Android Back closes the editor back to the list
// (never exits mid-edit, never cycles). In-memory edits survive closing the editor
// unsaved — re-opening shows them, matching the old "re-activating never discards".

import { load as ioLoad, save as ioSave, listKeyboxes } from "../data/config-io.js";
import { getStatus } from "../data/status.js";
import { keyAdmin, API_BASE, adminToken } from "../data/keyadmin.js";
import { validateConfig } from "../domain/validate.js";
import { emptyProfile, emptyConfig, FIELDS, PROFILE_RE } from "../domain/schema.js";
import { setPath, getPath } from "../domain/path.js";
import { renderProfileList, renderProfileEditor } from "../ui/config-view.js";
import { renderScope } from "../ui/scope-view.js";
import { attachPullToRefresh } from "../ui/pull-refresh.js";
import { el, clear, toast, confirmDialog, promptDialog, openOverlay, openSheet } from "../ui/dom.js";

// How often the open Scope page re-fetches the device app list so fresh usage/recency data
// flows in without a manual reload. Pull-to-refresh forces one immediately.
const SCOPE_REFRESH_MS = 9000;

const IDENTITY_FIELDS = FIELDS.filter((f) => f.group === "identity");

export function create(mount) {
  let config = null;
  let keyboxFiles = [];
  let errors = [];
  let dirty = false;
  let loaded = false;

  // Editor drill-in state (null when the list is the resting view).
  let editing = null;        // profile name being edited
  let editorHost = null;     // the content element inside the overlay
  let editorOverlay = null;  // { close } from openOverlay
  let openGroups = {};       // per-group disclosure state, { groupId: bool }
  let harvest = null;        // the daemon's harvest record, for the resolution hints

  // Scope drill-in state (a second overlay opened ON TOP of the editor). Only one is open
  // at a time. `packagesCache` is the live device app list fetched lazily the first time the
  // Scope page opens; it is cached for the life of the page so a second open is instant and
  // the editor's chips can show real app labels once it exists.
  //
  // DRAFT model: the Scope page edits `scopeDraft`, a private copy of the profile's
  // apps, and never touches the profile directly. EVERY way out funnels through onScopeClosed,
  // which — when the draft changed and Done didn't already commit — asks whether to keep the
  // changes (committing into the in-memory profile; disk still only changes on the editor's Save).
  // Putting the confirm in onScopeClosed rather than on the buttons is what makes a hardware/gesture
  // Back ask too, not silently discard. Done pre-commits and sets `scopeCommitted` so it isn't asked.
  let scoping = null;        // profile name whose scope is being edited
  let scopeHost = null;      // content element inside the scope overlay
  let scopeOverlay = null;   // { close } from openOverlay
  let scopeDraft = [];       // the working copy of the profile's apps (committed only on confirm)
  let scopeCommitted = false; // Done pre-committed the draft, so onScopeClosed must not ask again
  let scopeSearch = "";      // the Scope page's search text
  let scopeSearchTimer = null; // debounce handle for search-driven re-renders
  let scopeFilter = "recent"; // "recent" (default) | "user" | "system" | "selected"
  let scopeSort = "freq";    // "freq" (default) | "recent" | "name" | "install"
  let scopeLoading = false;  // the /packages fetch is in flight
  let scopeError = null;     // the /packages fetch failed with this message
  let scopeRefreshTimer = null; // periodic /packages re-fetch while the page is open
  let packagesCache = null;  // the keyAdmin("packages") result, or null before first fetch
  let scopeFetchGen = 0;     // monotonic id of the newest /packages fetch, so stale replies are dropped
  let iconToken = null;      // the admin token, prefetched so /icon URLs build synchronously
  let scopePullBound = false; // pull-to-refresh listeners attached to scopeHost yet?

  function revalidate() {
    errors = validateConfig(config).errors;
  }

  // A label/installed index over the cached device app list, handed to the editor so a scope
  // chip can show the app's real name and flag a package that is not installed. Null until the
  // Scope page has been opened once (before that the chips just show raw package names).
  function scopeMeta() {
    if (!packagesCache || !Array.isArray(packagesCache.apps)) return null;
    const labelMap = new Map();
    const installedSet = new Set();
    for (const row of packagesCache.apps) {
      for (const p of (row.packages || [])) {
        installedSet.add(p);
        if (!labelMap.has(p)) labelMap.set(p, row.label || p);
      }
    }
    return { labelMap, installedSet };
  }

  // uid/package entries claimed by profiles OTHER than `name`, as entry -> owning profile.
  // The Scope page greys these out so an app can't be double-assigned.
  function claimedByOther(name) {
    const m = new Map();
    for (const other of Object.keys(config.profiles)) {
      if (other === name) continue;
      const a = config.profiles[other] && config.profiles[other].apps;
      if (!Array.isArray(a)) continue;
      for (const entry of a) if (!m.has(entry)) m.set(entry, other);
    }
    return m;
  }

  // Best-effort: what an empty (harvested) field resolves to, so the editor can show the
  // effective value or that the tag will be omitted. "Harvested" is two layers, mirroring
  // Harvester.Record.effective(): the raw values captured from the attested leaf, plus
  // harvest.overrides — the values the daemon actually presents, including the serial/imei/meid
  // ids a device-properties leaf never carries (source "supplement"). Both count as harvested.
  async function loadHarvest() {
    try {
      const st = await getStatus();
      harvest = (st && st.harvest) || null;
    } catch {
      /* keep whatever we had */
    }
  }

  function resolvedLevels() {
    const h = harvest || {};
    const ov = (h.overrides && typeof h.overrides === "object" && !Array.isArray(h.overrides)) ? h.overrides : {};
    // serial/imei/imei2/meid are the only ids the daemon resolves through Record.effective():
    // device-properties attestation omits them, so supplementDeviceIds reads them from the OS and
    // records them in harvest.overrides (source "supplement"), leaving the raw capture blank. Mirror
    // effective() here — the override value wins, else the raw capture — so an empty profile field
    // shows the fabricated value that WILL be attested (Resolver.putId) rather than "will be omitted".
    const eff = (key) => {
      const o = ov[key];
      return (o && o.value != null && o.value !== "") ? o.value : h[key];
    };
    return {
      // The patch/OS levels and brand/device/product/manufacturer/model are genuine captures with no
      // override layer; Resolver.kt reads them raw too (a fabricated-fallback level is written to the
      // raw record as well), so the raw value already equals the effective one.
      patchSystem: h.osPatchLevel, patchVendor: h.vendorPatchLevel, patchBoot: h.bootPatchLevel, osVersion: h.osVersion,
      brand: h.brand, device: h.device, product: h.product, manufacturer: h.manufacturer, model: h.model,
      serial: eff("serial"), imei: eff("imei"), meid: eff("meid"), imei2: eff("imei2"),
    };
  }

  function renderList() {
    renderProfileList(mount, { config, errors, dirty }, listActions);
  }

  // Which OTHER profile (if any) already owns auto-include, relative to `name`. Only one profile
  // may, so the editor greys this profile's toggle when another claims it.
  function autoTakenBy(name) {
    for (const other of Object.keys(config.profiles)) {
      if (other === name) continue;
      if (config.profiles[other] && config.profiles[other].autoIncludeNewApps === true) return other;
    }
    return null;
  }

  function renderEditor() {
    if (!editing || !editorHost) return;
    renderProfileEditor(
      editorHost,
      { config, name: editing, errors, keyboxFiles, openGroups, resolved: resolvedLevels(),
        scopeMeta: scopeMeta(), autoTakenBy: autoTakenBy(editing) },
      editorActions);
  }

  // ---- editor lifecycle -------------------------------------------------
  function openEditor(name) {
    if (!config.profiles[name]) return;
    editing = name;
    // Auto-expand the identity disclosure only when the profile already sets an id;
    // the patch/OS levels fold stays closed by default.
    openGroups = {
      identity: IDENTITY_FIELDS.some((f) => {
        const v = getPath(config.profiles[name], f.path);
        return v != null && v !== "";
      }),
    };
    editorHost = el("div", { class: "editor-host" });
    editorOverlay = openOverlay(editorHost, { variant: "panel", label: "Edit profile", onClose: onEditorClosed });
    renderEditor();
    const title = editorHost.querySelector(".drill-title");
    if (title) title.focus();
  }

  function onEditorClosed() {
    editing = null;
    editorHost = null;
    editorOverlay = null;
    renderList(); // the list may now show updated summaries / the unsaved bar
  }

  function closeEditor() {
    if (editorOverlay) editorOverlay.close();
  }

  // ---- scope drill-in lifecycle (opens on top of the editor) ------------
  // A URL for the daemon's /icon route. The admin token is prefetched into `iconToken` on open,
  // so this builds synchronously (a browser <img> cannot set the token header, so it rides the
  // query, exactly like the log-download route). Null until the token is in hand — the row then
  // shows a letter-avatar instead.
  function iconUrl(pkg) {
    if (!iconToken || !pkg) return null;
    return API_BASE + "/icon?pkg=" + encodeURIComponent(pkg) + "&token=" + encodeURIComponent(iconToken);
  }

  function renderScopeView() {
    if (!scoping || !scopeHost) return;
    const p = config.profiles[scoping];
    if (!p) { closeScope(); return; }
    const scrollTop = captureScopeScroll();
    renderScope(scopeHost, {
      profileName: scoping,
      apps: scopeDraft,
      packages: packagesCache,
      claimedByOther: claimedByOther(scoping),
      firstAppUid: (packagesCache && packagesCache.firstAppUid) || 10000,
      search: scopeSearch, filter: scopeFilter, sort: scopeSort,
      loading: scopeLoading, error: scopeError, iconUrl,
    }, scopeActions);
    restoreScopeScroll(scrollTop);
  }

  // Scroll retention across the stateless rebuild (a periodic refresh or a filter tap rebuilds
  // the whole body). Grab the scrolling body's offset before teardown and reinstate it after.
  function captureScopeScroll() {
    const body = scopeHost && scopeHost.querySelector(".drill-body");
    return body ? body.scrollTop : 0;
  }
  function restoreScopeScroll(top) {
    const body = scopeHost && scopeHost.querySelector(".drill-body");
    if (!body) return;
    body.scrollTop = top;
    requestAnimationFrame(() => { body.scrollTop = top; });
  }

  // Fetch the live app list and re-render. `initial` shows the spinner (first open); a periodic
  // or pull refresh replaces the cache silently, preserving the draft/search/filter/sort/scroll.
  function fetchPackages(initial) {
    if (initial) { scopeLoading = true; scopeError = null; renderScopeView(); }
    // Overlapping fetches (the 9s poll racing a pull-to-refresh, or a slow daemon) can resolve out of
    // order; stamp each with a generation and ignore any response that is not the latest, so an older
    // in-flight reply can never clobber a newer app list.
    const gen = ++scopeFetchGen;
    return keyAdmin("packages")
      .then((res) => {
        if (gen !== scopeFetchGen) return; // a newer fetch already superseded this one
        packagesCache = res || null;
        scopeError = null; // a later refresh that succeeds must clear a stale initial-load error banner
        const n = (res && Array.isArray(res.apps)) ? res.apps.length : 0;
        console.log("[config] scope: /packages returned %d uid entr(y/ies)%s", n, initial ? "" : " (refresh)");
      })
      .catch((e) => {
        if (gen !== scopeFetchGen) return;
        const msg = (e && e.message) || String(e);
        if (initial) scopeError = msg;
        console.warn("[config] scope: /packages failed:", msg);
      })
      .finally(() => {
        if (gen !== scopeFetchGen) return; // stale completion: leave state to the newer fetch
        scopeLoading = false;
        if (scoping) renderScopeView();
      });
  }

  // Opening the Scope page rescans before it fetches. The daemon is where the auto-include rule is
  // applied, against the installed-app set it re-reads during a resolve, so asking it to re-resolve
  // first means the picker opens on an already-current view rather than painting a stale one and
  // correcting itself a moment later. A failed rescan is not fatal — log it and fetch anyway, so a
  // daemon that is down still leaves the picker usable for editing.
  function rescanThenFetch() {
    return keyAdmin("rescan")
      .catch((e) => { console.warn("[config] scope: /rescan failed:", (e && e.message) || String(e)); })
      .then(() => fetchPackages(true));
  }

  function openScope(name) {
    if (!config.profiles[name]) return;
    scoping = name;
    scopeSearch = "";
    scopeFilter = "recent";
    scopeSort = "freq";
    scopeError = null;
    // Draft = a private copy of the profile's current picks. The Scope page mutates this alone;
    // the profile changes only when kept on the way out (onScopeClosed) or committed by Done.
    const cur = config.profiles[name].apps;
    scopeDraft = Array.isArray(cur) ? cur.slice() : [];
    scopeCommitted = false;
    scopePullBound = false;
    scopeHost = el("div", { class: "editor-host" });
    scopeOverlay = openOverlay(scopeHost, { variant: "panel", label: "Scope", onClose: onScopeClosed });

    // Prefetch the admin token so /icon URLs build synchronously as rows render.
    adminToken().then((t) => { iconToken = t || null; if (scoping === name) renderScopeView(); }).catch(() => {});

    // Rescan, then fetch the live app list. Always the spinner path, cache or not: the point is that
    // what the user first sees is post-rescan.
    scopeLoading = true;
    rescanThenFetch();
    renderScopeView();
    bindScopePull();

    // Periodic refresh so fresh usage/recency data flows in while the page stays open.
    clearInterval(scopeRefreshTimer);
    scopeRefreshTimer = setInterval(() => { if (scoping === name) fetchPackages(false); }, SCOPE_REFRESH_MS);

    const title = scopeHost.querySelector(".drill-title");
    if (title) title.focus();
  }

  // Pull-to-refresh scoped to the Scope page's own scroll container (the .drill-body), not the
  // document. Kept deliberately small: claim the gesture only when dragging down from the very
  // top, and force an immediate /packages refetch past a threshold. Listeners bind once to the
  // persistent scopeHost; the handler reads the current .drill-body each time (it is rebuilt on
  // every render).
  function bindScopePull() {
    if (scopePullBound || !scopeHost) return;
    scopePullBound = true;
    const THRESHOLD = 64;
    let startY = 0, pulling = false, dy = 0, busy = false;
    const bodyNow = () => scopeHost.querySelector(".drill-body");
    scopeHost.addEventListener("touchstart", (e) => {
      const b = bodyNow();
      pulling = false;
      if (busy || !b || e.touches.length !== 1 || b.scrollTop > 0) return;
      startY = e.touches[0].clientY; pulling = true; dy = 0;
    }, { passive: true });
    scopeHost.addEventListener("touchmove", (e) => {
      if (!pulling) return;
      const b = bodyNow();
      dy = e.touches[0].clientY - startY;
      if (dy <= 0 || !b || b.scrollTop > 0) { pulling = false; return; }
    }, { passive: true });
    const end = () => {
      if (!pulling) return;
      pulling = false;
      if (dy < THRESHOLD || busy) return;
      busy = true;
      console.log("[config] scope: pull-to-refresh");
      Promise.resolve(fetchPackages(false)).finally(() => { busy = false; });
    };
    scopeHost.addEventListener("touchend", end, { passive: true });
    scopeHost.addEventListener("touchcancel", () => { pulling = false; }, { passive: true });
  }

  // The SINGLE exit point every close funnels through — the ▸back button, a hardware/gesture Back
  // (both land here via the overlay's popstate close), and Done (which pre-commits, below). The
  // confirm lives HERE, not on the buttons, precisely so a hardware Back can't slip past it: when the
  // draft differs from the profile and Done didn't already commit, we ask — over the editor the page
  // just closed onto — whether to keep the changes. This is why onScopeClosed launches an async
  // confirm even though it runs from a sync popstate: the scope DOM is already gone, but the decision
  // is only "commit the draft into the in-memory profile or not" (disk still waits for the editor's
  // Save), which needs no scope DOM.
  function onScopeClosed() {
    clearTimeout(scopeSearchTimer); // a pending search render must not fire into a torn-down host
    clearInterval(scopeRefreshTimer);
    scopeRefreshTimer = null;
    const name = scoping;
    const draft = scopeDraft.slice();
    const committed = scopeCommitted; // Done already wrote the draft in; don't re-ask
    scoping = null;
    scopeHost = null;
    scopeOverlay = null;
    scopeDraft = [];
    scopeCommitted = false;

    const p = name && config.profiles[name];
    if (p && !committed && !sameEntries(draft, p.apps)) {
      // We are running inside the popstate that just closed this overlay. confirmDialog opens ANOTHER
      // overlay, which pushes a history entry — and history.pushState fired mid-popstate can be dropped
      // by the browser, desyncing the nav stack from history (a later Back would then over-pop). Defer
      // to a fresh task so the confirm's history push happens cleanly after this traversal finishes.
      setTimeout(() => {
        confirmDialog("Keep the app selection changes you made?", {
          confirmLabel: "Keep", cancelLabel: "Discard", danger: false,
        }).then((keep) => {
          if (keep && config.profiles[name]) {
            config.profiles[name].apps = draft;
            dirty = true;
            revalidate();
            console.log("[config] scope: kept %d pick(s) for %s", draft.length, name);
          } else {
            console.log("[config] scope: discarded draft changes for %s", name);
          }
          renderEditor();
        });
      }, 0);
      return;
    }
    renderEditor(); // the editor underneath now reflects the committed chips (or the unchanged ones)
  }

  function closeScope() {
    if (scopeOverlay) scopeOverlay.close();
  }

  // Done: an explicit "use these" — commit the draft into the in-memory profile straight away (no
  // ask — the tap IS the confirmation), flag it so onScopeClosed doesn't ask again, then close.
  function commitAndCloseScope() {
    const p = config.profiles[scoping];
    if (p && !sameEntries(scopeDraft, p.apps)) {
      p.apps = scopeDraft.slice();
      dirty = true;
      revalidate();
      console.log("[config] scope: committed %d pick(s) into %s (Done)", p.apps.length, scoping);
    }
    scopeCommitted = true;
    closeScope();
  }

  // Order-insensitive set comparison of two entry lists (a reorder is not a real change).
  function sameEntries(a, b) {
    const A = new Set(Array.isArray(a) ? a : []);
    const B = new Set(Array.isArray(b) ? b : []);
    if (A.size !== B.size) return false;
    for (const x of A) if (!B.has(x)) return false;
    return true;
  }

  // The uid an entry resolves to, from the cached device list — so a system/shell pick can be
  // confirmed before it lands. A uid: token carries its uid directly; a package is looked up in
  // the /packages inventory. Returns -1 when unknown (uninstalled package: no privileged risk).
  function uidForEntry(entry) {
    const m = /^uid:(\d+)$/.exec(entry);
    if (m) return Number(m[1]);
    if (packagesCache && Array.isArray(packagesCache.apps)) {
      for (const row of packagesCache.apps) {
        if ((row.packages || []).includes(entry)) return row.uid;
      }
    }
    return -1;
  }

  const scopeActions = {
    onClose() { closeScope(); },       // leave → onScopeClosed asks to keep changes if the draft moved
    onDone() { commitAndCloseScope(); }, // Done → commit the draft, then leave without re-asking
    async onToggleApp(entry) {
      if (scopeDraft.includes(entry)) {
        scopeDraft = scopeDraft.filter((a) => a !== entry);
        console.log("[config] scope: removed %s from draft", entry);
      } else {
        // Adding a privileged (system/shell) uid is almost never what a normal user wants —
        // confirm it explicitly so a mis-tap on a low uid can't silently target system_server.
        const uid = uidForEntry(entry);
        const firstAppUid = (packagesCache && packagesCache.firstAppUid) || 10000;
        if (uid >= 0 && uid < firstAppUid) {
          const ok = await confirmDialog(
            `Target privileged uid ${uid}?\n\nThis is a system/shell uid (e.g. shell, system_server), not a normal app. Only do this if you know exactly why.`,
            { confirmLabel: "Target it", danger: true });
          if (!ok) return;
        }
        scopeDraft = scopeDraft.concat([entry]);
        console.log("[config] scope: added %s to draft", entry);
      }
      renderScopeView();
    },
    // Search re-renders the whole page (a few hundred rows), so coalesce fast typing: keep the
    // value live immediately (so a pending render paints the right text) but defer the rebuild.
    onSetSearch(text) {
      scopeSearch = text;
      clearTimeout(scopeSearchTimer);
      scopeSearchTimer = setTimeout(() => renderScopeView(), 140);
    },
    // The in-field search button / Enter: render right now rather than on the debounce.
    onSearchSubmit() { clearTimeout(scopeSearchTimer); renderScopeView(); },
    onSetFilter(id) { scopeFilter = id; renderScopeView(); },
    onOpenSort() { openSortSheet(); },
    // The three bulk ops act on the visible entries the view computed, each { add, cur }:
    // `add` is the entry a select would add, `cur` the entry currently selecting the row.
    onSelectAllVisible(entries) {
      const set = new Set(scopeDraft);
      for (const e of entries) if (!e.cur) set.add(e.add);
      scopeDraft = Array.from(set);
      console.log("[config] scope: select-all over %d visible row(s)", entries.length);
      renderScopeView();
    },
    onClearVisible(entries) {
      const drop = new Set();
      for (const e of entries) if (e.cur) drop.add(e.cur);
      scopeDraft = scopeDraft.filter((a) => !drop.has(a));
      console.log("[config] scope: cleared %d visible pick(s)", drop.size);
      renderScopeView();
    },
    onInvertVisible(entries) {
      const set = new Set(scopeDraft);
      for (const e of entries) {
        if (e.cur) set.delete(e.cur);
        else set.add(e.add);
      }
      scopeDraft = Array.from(set);
      console.log("[config] scope: inverted %d visible row(s)", entries.length);
      renderScopeView();
    },
    async onClearUsage() {
      const ok = await confirmDialog(
        "Clear the recorded app-usage (frequency) memory?\n\nThis wipes the request counts used to sort and populate Recent. It does not change any profile.",
        { confirmLabel: "Clear usage", danger: true });
      if (!ok) return;
      try {
        const r = await keyAdmin("usageClear");
        toast("Cleared " + ((r && r.cleared) || 0) + " app" + (((r && r.cleared) || 0) === 1 ? "" : "s"));
        console.log("[config] scope: usage cleared (%o)", r);
      } catch (e) {
        toast("Clear failed: " + ((e && e.message) || e));
      }
      fetchPackages(false);
    },
  };

  // The sort bottom-sheet: four options, each with a one-line meaning. Selecting one
  // sets scopeSort and re-renders. It is a plain sheet built here (the controller owns dom.js).
  function openSortSheet() {
    const OPTIONS = [
      { id: "freq", label: "Frequency", meaning: "Most key requests first (default)." },
      { id: "recent", label: "Recently used", meaning: "Last requested first." },
      { id: "name", label: "Name", meaning: "A→Z." },
      { id: "install", label: "Install time", meaning: "Newest installs first." },
    ];
    let handle = null;
    const pick = (id) => { scopeSort = id; if (handle) handle.close(); renderScopeView(); };
    const content = el("div", { class: "sort-sheet" }, [
      el("div", { class: "sheet-head" }, [el("h2", { text: "Sort by" })]),
      el("div", { class: "sort-list" }, OPTIONS.map((o) => el("button", {
        type: "button", class: "sort-opt" + (scopeSort === o.id ? " on" : ""),
        "aria-pressed": scopeSort === o.id ? "true" : "false", onclick: () => pick(o.id),
      }, [
        el("span", { class: "sort-opt-main" }, [
          el("span", { class: "sort-opt-label", text: o.label }),
          el("span", { class: "sort-opt-meaning muted small", text: o.meaning }),
        ]),
        el("span", { class: "sort-opt-check" + (scopeSort === o.id ? " on" : ""), "aria-hidden": "true" }),
      ]))),
    ]);
    handle = openSheet(content, { label: "Sort order" });
  }

  // ---- the one save path (used by both the list bar and the editor) -----
  async function save() {
    revalidate(); // hard gate
    if (errors.length) {
      toast(errors[0].msg);
      editing ? renderEditor() : renderList();
      return;
    }
    await persist();
  }

  // Write the config to disk without the validation gate. A profile removal must persist even when a
  // DIFFERENT profile is currently invalid — deleting one profile cannot introduce invalidity, and the
  // whole-config gate in save() would otherwise reject the removal and leave the stale profile on disk.
  async function persist() {
    const r = await ioSave(config);
    if (r.ok) {
      dirty = false;
      toast("Saved");
      if (editing) closeEditor(); // returns to the freshly-repainted list
      else renderList();
    } else {
      toast("Save failed: " + (r.error || "unknown error"));
    }
  }

  const listActions = {
    async onAdd() {
      const name = await promptDialog("New profile name", "", { okLabel: "Create", placeholder: "profile-name" });
      if (name == null) return;
      const trimmed = name.trim();
      if (!trimmed) return;
      if (!PROFILE_RE.test(trimmed)) { toast("Name must be 1-32 chars: letters, digits, - or _."); return; }
      if (config.profiles[trimmed]) { toast("A profile named " + trimmed + " already exists."); return; }
      config.profiles[trimmed] = emptyProfile();
      dirty = true;
      revalidate();
      openEditor(trimmed);
    },
    onOpen(name) { openEditor(name); },
    onSave() { return save(); },
  };

  const editorActions = {
    onFieldChange(profile, path, value) {
      const p = config.profiles[profile];
      if (!p) return;
      setPath(p, path, value);
      dirty = true;
      revalidate();
      renderEditor();
    },

    onAddApp(profile, pkg) {
      const p = config.profiles[profile];
      if (!p) return;
      if (!Array.isArray(p.apps)) p.apps = [];
      if (!p.apps.includes(pkg)) p.apps.push(pkg);
      dirty = true;
      revalidate();
      renderEditor();
    },

    onRemoveApp(profile, pkg) {
      const p = config.profiles[profile];
      if (!p || !Array.isArray(p.apps)) return;
      p.apps = p.apps.filter((a) => a !== pkg);
      dirty = true;
      revalidate();
      renderEditor();
    },

    // Rename is a key reassignment carrying the SAME profile object across, so the
    // app list survives and the duplicate-app check never false-positives.
    onRename(oldName, newName) {
      if (!config.profiles[oldName] || config.profiles[newName]) return;
      const next = {};
      for (const k of Object.keys(config.profiles)) {
        next[k === oldName ? newName : k] = config.profiles[k];
      }
      config.profiles = next;
      if (editing === oldName) editing = newName;
      dirty = true;
      revalidate();
      renderEditor();
    },

    async onRemove(name) {
      if (!config.profiles[name]) return;
      if (!(await confirmDialog(`Remove profile "${name}"?`))) return;
      delete config.profiles[name];
      dirty = true;
      revalidate();
      closeEditor(); // the edited profile is gone; drop back to the list
      // Persist the removal to disk right away — a confirmed delete that only lived in memory left the
      // on-disk config (and its stale profile) untouched until the next unrelated Save. Bypass the
      // validation gate: a removal must persist even if another profile is currently invalid.
      await persist();
    },

    onToggleGroup(id) {
      openGroups[id] = !openGroups[id];
      renderEditor();
    },

    // The scope widget's "Configure scope" button: open the app-picker drill-in for this
    // profile on top of the editor.
    openScope(name) { openScope(name); },

    // The "empty means harvested — see Harvest" link: close the editor and jump to the
    // System screen, where the harvested values are shown.
    gotoSystem() {
      closeEditor();
      document.dispatchEvent(new CustomEvent("teesim:navigate", { detail: { panel: "system" } }));
    },

    onClose() { closeEditor(); },
    onSave() { return save(); },
  };

  // A load failure never touches the file on disk. When it is simply absent/empty
  // we offer to seed a starter config (nothing to overwrite = cannot corrupt).
  function renderLoadError(res) {
    clear(mount);
    const canSeed = !res.raw || res.raw.trim() === "";
    mount.appendChild(el("div", { class: "panel-head" }, [el("h1", { class: "panel-title", text: "Profiles" })]));
    const card = el("div", { class: "card" }, [
      el("div", { class: "banner error" }, [el("div", { text: res.error })]),
      canSeed
        ? el("p", { class: "muted small", text: "The module seeds config.json on install. You can create a starter config now." })
        : el("p", { class: "muted small", text: "Fix or remove the file on disk — the WebUI will not overwrite a config it cannot read." }),
    ]);
    if (canSeed) {
      card.appendChild(el("button", {
        class: "btn primary", text: "Create starter config",
        onclick: async () => {
          config = emptyConfig();
          const r = await ioSave(config);
          if (!r.ok) { toast("Could not create config: " + (r.error || "")); return; }
          loaded = true;
          keyboxFiles = await listKeyboxes();
          dirty = false;
          revalidate();
          renderList();
        },
      }));
    }
    mount.appendChild(card);
  }

  // Pull the Profiles list down to re-discover apps. The daemon runs no package observer — a
  // receiver registered from its bare app_process is rejected by AMS — so a newly installed app is
  // noticed only when something goes and looks. This is that ask: /rescan re-resolves the config
  // against the live device and re-pushes it, which is when a profile that auto-includes new apps
  // folds in anything installed since. The daemon also does this on its own at start and whenever
  // config.json changes; those three moments are the whole of discovery.
  //
  // Unsaved edits are never clobbered: config.json is re-read only when nothing is pending, the same
  // rule load() follows. The cached device app list is always dropped, since that is precisely what
  // the pull is meant to refresh.
  async function rescan() {
    let msg;
    try {
      const r = await keyAdmin("rescan");
      msg = (r && r.ok)
        ? "Rescanned — " + r.uids + (r.uids === 1 ? " app" : " apps") + " targeted"
        : "Rescan failed: " + ((r && r.error) || "unknown error");
    } catch (e) {
      msg = "Rescan failed: " + (e && e.message ? e.message : String(e));
    }

    packagesCache = null; // force the Scope page and the editor's chips to re-fetch
    if (!dirty) {
      const res = await ioLoad();
      if (res.ok) {
        config = res.config;
        loaded = true;
        revalidate();
      } else if (!config) {
        // Nothing on screen but the load-error card, and the re-read failed again: repaint that
        // rather than falling through to renderList(), which would throw on a null config.
        renderLoadError(res);
        toast(msg);
        return;
      }
    }
    keyboxFiles = await listKeyboxes();
    await loadHarvest();
    if (config) {
      renderList();
      if (editing) renderEditor();
    }
    toast(msg);
  }

  attachPullToRefresh(mount, rescan);

  return {
    async load() {
      // Re-activating the tab must not discard unsaved edits, but should pick up any
      // keyboxes imported (and a harvest completed) since it was last shown.
      if (loaded && config) {
        keyboxFiles = await listKeyboxes();
        await loadHarvest();
        renderList();
        return;
      }

      const res = await ioLoad();
      if (!res.ok) { renderLoadError(res); return; }

      config = res.config;
      keyboxFiles = await listKeyboxes();
      await loadHarvest();
      dirty = false;
      loaded = true;
      revalidate();
      renderList();
    },
  };
}
