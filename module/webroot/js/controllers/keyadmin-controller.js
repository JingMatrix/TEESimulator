// Wires key-view to the keyAdmin transport for the "stored keys" panel. On Android
// 12+ (API 31+) it reads keystore2's database — via the daemon's /keys/db route — to
// show the keys THIS MODULE minted for the target apps (identified by our blob marker),
// which the daemon's own AndroidKeyStore never sees. On Android 10/11 there is no
// keystore2 database, so the view shows a hint instead of a list.
//
// It owns the transient UI state the view is stateless about: the filter text, the scope toggle
// (spoofedOnly), and the set of selected key ids. Deletion goes back through /keys/db/delete, which
// the daemon re-verifies (a target app) before removing anything. Degrades gracefully: if the daemon
// isn't reachable yet it shows an "unavailable" panel instead of crashing.

import { keyAdmin } from "../data/keyadmin.js";
import { renderKeys } from "../ui/key-view.js";
import { confirmDialog, toast } from "../ui/dom.js";
import { attachPullToRefresh } from "../ui/pull-refresh.js";

// A key we spoofed vs the app's own untouched real key. Both are deletable; the "Spoofed" scope just
// hides the real ones by default, and bulk-select only ever touches what the scope currently shows.
const isSpoofed = (k) => (k.class || "untouched") !== "untouched";

export function create(mount) {
  let state = {
    keys: [], available: false, apiLevel: 0, unavailable: false,
    loading: false, deleting: false, filter: "", selected: new Set(), menuOpen: false,
    spoofedOnly: true,
  };

  // The keys currently shown given the scope (bulk-select operates on these, never on hidden keys).
  const visibleKeys = () => (state.spoofedOnly ? state.keys.filter(isSpoofed) : state.keys);

  function render() {
    renderKeys(mount, state, handler);
  }

  // `force` re-resolves the daemon's uid -> app mapping instead of reading its snapshot. Only the
  // pull-to-refresh passes it: a load or a post-delete reload wants the cheap answer, since deleting
  // a key changes the key list but never which apps are in scope.
  async function refresh(force = false) {
    state.loading = true;
    render();
    try {
      const res = await keyAdmin("keysDb", { refresh: force });
      state.keys = res && Array.isArray(res.keys) ? res.keys : [];
      state.available = !!(res && res.available);
      state.apiLevel = (res && Number(res.apiLevel)) || 0;
      state.unavailable = false;
      // Drop any selection for keys that no longer exist (e.g. after a delete or regen).
      const live = new Set(state.keys.map((k) => k.id));
      state.selected = new Set([...state.selected].filter((id) => live.has(id)));
    } catch {
      // Non-200/absent transport => empty + note, never an error crash.
      state.keys = [];
      state.available = false;
      state.apiLevel = 0;
      state.unavailable = true;
      state.selected = new Set();
    }
    state.loading = false;
    render();
  }

  async function deleteSelected() {
    const ids = [...state.selected];
    if (!ids.length) return;
    const what = ids.length === 1 ? "this key" : ids.length + " keys";
    const ok = await confirmDialog(
      `Delete ${what} from keystore2? The owning app will re-create the key (and re-attest it) on next use.`,
    );
    if (!ok) return;
    state.deleting = true;
    state.menuOpen = false;
    render();
    try {
      const res = await keyAdmin("keysDbDelete", { ids });
      const n = (res && Number(res.deleted)) || 0;
      toast(n ? `Deleted ${n} key${n === 1 ? "" : "s"}` : "No keys deleted");
    } catch (e) {
      toast("Delete failed: " + (e && e.message ? e.message : String(e)));
    }
    state.deleting = false;
    state.selected = new Set();
    return refresh();
  }

  function handler(action, arg) {
    switch (action) {
      case "filter":
        state.filter = arg;
        render();
        return;
      case "toggle": {
        if (state.selected.has(arg)) state.selected.delete(arg);
        else state.selected.add(arg);
        render();
        return;
      }
      case "toggleSpoofed": {
        state.spoofedOnly = !state.spoofedOnly;
        // Drop any selection that just became hidden, so the delete count only counts visible keys.
        const vis = new Set(visibleKeys().map((k) => k.id));
        state.selected = new Set([...state.selected].filter((id) => vis.has(id)));
        render();
        return;
      }
      case "toggleMenu":
        state.menuOpen = !state.menuOpen;
        render();
        return;
      case "closeMenu":
        state.menuOpen = false;
        render();
        return;
      case "selectFiltered": {
        (arg || []).forEach((id) => state.selected.add(id));
        state.menuOpen = false;
        render();
        return;
      }
      case "selectAll":
        visibleKeys().forEach((k) => state.selected.add(k.id));
        state.menuOpen = false;
        render();
        return;
      case "unselectAll":
        state.selected = new Set();
        state.menuOpen = false;
        render();
        return;
      case "inverse": {
        const next = new Set();
        visibleKeys().forEach((k) => { if (!state.selected.has(k.id)) next.add(k.id); });
        state.selected = next;
        state.menuOpen = false;
        render();
        return;
      }
      case "deleteSelected":
        return deleteSelected();
    }
  }

  attachPullToRefresh(mount, () => refresh(true));

  return {
    load() {
      return refresh();
    },
  };
}
