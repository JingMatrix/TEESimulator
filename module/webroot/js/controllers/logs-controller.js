// Polls the daemon's /logs endpoint while the Logs tab is visible and feeds the
// growing scrollback to the view. Owns the client-side filter (min level, a set of
// selected tags, and a message substring), applied in the view; the filter controls
// live in a bottom sheet. Keeps a cursor (nextAfter) so each poll pulls only lines newer
// than the last, and caps how many it retains so a long session doesn't grow without bound.

import { keyAdmin } from "../data/keyadmin.js";
import { renderLogs, renderLogFilters } from "../ui/logs-view.js";
import { toast, clear, openSheet } from "../ui/dom.js";

const POLL_MS = 1500;
const MAX_FETCH = 500;
const MAX_KEPT = 4000;

// Copy text to the clipboard, degrading gracefully. navigator.clipboard needs a
// secure context, which this WebUI running over plain http:// usually is NOT, so the
// API may be absent or its promise may reject. We fall back to a hidden <textarea> +
// execCommand("copy"), and always toast the outcome so "Copy" is never a silent no-op
// (and no unhandled promise rejection escapes).
function copyText(text) {
  const fallback = () => toast(legacyCopy(text) ? "Copied" : "Copy failed");
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => toast("Copied")).catch(fallback);
  } else {
    fallback();
  }
}

function legacyCopy(text) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, text.length);
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

export function create(mount) {
  let lines = [];
  let cursor = 0;
  let paused = false;
  let reachable = true;
  let error = null;
  let timer = null;
  let inFlight = false;

  let filter = { minLevel: "V", tags: new Set(), text: "" };
  let filterHost = null;    // content element inside the filter sheet
  let filterOverlay = null; // { close } while the sheet is open

  const filterActive = () => filter.minLevel !== "V" || filter.tags.size > 0 || filter.text !== "";
  const seenTags = () => {
    const s = new Set();
    for (const l of lines) if (l.tag) s.add(l.tag);
    return [...s].sort();
  };

  function render() {
    renderLogs(mount, { lines, paused, reachable, error, filter, filterActive: filterActive() }, actions);
  }

  async function poll() {
    if (inFlight || paused) return; // don't stack polls; honor pause
    inFlight = true;
    try {
      const res = await keyAdmin("logs", { after: cursor, max: MAX_FETCH });
      reachable = true;
      error = null;
      if (res && Array.isArray(res.lines) && res.lines.length) {
        lines.push(...res.lines);
        if (lines.length > MAX_KEPT) lines = lines.slice(-MAX_KEPT);
      }
      if (res && typeof res.nextAfter === "number") cursor = res.nextAfter;
    } catch (e) {
      reachable = false;
      error = e && e.message ? e.message : String(e);
    } finally {
      inFlight = false;
      render();
    }
  }

  // ---- filter sheet -----------------------------------------------------
  function renderFilterSheet() {
    if (!filterHost) return;
    clear(filterHost);
    filterHost.appendChild(renderLogFilters({ filter, tags: seenTags() }, filterActions));
  }

  function openFilters() {
    filterHost = document.createElement("div");
    filterHost.appendChild(renderLogFilters({ filter, tags: seenTags() }, filterActions));
    filterOverlay = openSheet(filterHost, { label: "Filter logs", onClose: () => { filterHost = null; filterOverlay = null; } });
  }

  function closeFilters() {
    if (filterOverlay) filterOverlay.close();
  }

  // Level, tag chips, and Reset rebuild the sheet (to repaint the segmented control and
  // the selected chips); focus is on a button then, so no caret is lost. The message
  // input only updates the filter and the pane — rebuilding the sheet would yank the
  // caret mid-type.
  const filterActions = {
    setLevel(v) { filter.minLevel = v; renderFilterSheet(); render(); },
    toggleTag(t) {
      if (filter.tags.has(t)) filter.tags.delete(t);
      else filter.tags.add(t);
      renderFilterSheet();
      render();
    },
    setText(v) { filter.text = v; render(); },
    reset() { filter = { minLevel: "V", tags: new Set(), text: "" }; renderFilterSheet(); render(); },
    close() { closeFilters(); },
  };

  const actions = {
    openFilters() { openFilters(); },
    togglePause() {
      paused = !paused;
      render();
      if (!paused) poll();
    },
    clear() {
      // Client-side clear only; the cursor is untouched so we never refetch old lines.
      lines = [];
      render();
    },
    copy() {
      copyText(lines.map((l) => l.text).join("\n"));
    },
  };

  function visible() {
    return mount.offsetParent !== null && document.visibilityState === "visible";
  }

  function startPolling() {
    if (timer) return;
    timer = setInterval(() => {
      if (visible()) poll();
    }, POLL_MS);
  }

  return {
    load() {
      render(); // paint the buffer we already have instantly
      startPolling();
      return poll();
    },
  };
}
