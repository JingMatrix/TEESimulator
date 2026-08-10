// Polls the daemon's /logs endpoint while the Logs tab is visible and feeds the
// growing scrollback to the view. Owns the client-side filter (min level, a set of
// selected tags, and a message substring), applied in the view; the filter controls
// live in a bottom sheet. Keeps a cursor (nextAfter) so each poll pulls only lines newer
// than the last, and caps how many it retains so a long session doesn't grow without bound.

import { keyAdmin } from "../data/keyadmin.js";
import { moduleVersion } from "../data/logs-io.js";
import { renderLogs, renderLogFilters, renderSaveSheet } from "../ui/logs-view.js";
import { toast, clear, openSheet } from "../ui/dom.js";

const POLL_MS = 1500;
const MAX_FETCH = 500;
const MAX_KEPT = 4000;
const SAVE_DIR_KEY = "teesim.logs.dir";
const DEFAULT_SAVE_DIR = "/sdcard/Download";

// The default export filename: TEESimulator-<version>-<variant>-<timestamp>.log. The module
// version already embeds the variant, e.g. "v4.0 (17-0375393-debug)"; sanitize it into a
// filename-safe token (drop parens, spaces/others -> dashes) and append a local timestamp.
function defaultLogName(version) {
  const tag =
    (version || "unknown")
      .replace(/[()]/g, "")
      .trim()
      .replace(/[^A-Za-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "unknown";
  return `TEESimulator-${tag}-${timestamp()}.log`;
}

function timestamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}` +
    `-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`
  );
}

export function create(mount) {
  let lines = [];
  let cursor = 0;
  let paused = false;
  let reachable = true;
  let error = null;
  let timer = null;
  let inFlight = false;
  let moduleVer = ""; // cached at load so the default save filename is ready without an await

  let filter = { minLevel: "V", tags: new Set(), text: "" };
  let filterHost = null;    // content element inside the filter sheet
  let filterOverlay = null; // { close } while the sheet is open
  let saveHost = null;      // content element inside the save sheet
  let saveOverlay = null;   // { close } while the save sheet is open

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

  // ---- save sheet -------------------------------------------------------
  // The Save button opens this sheet; the sheet's own Save click is the gesture that POSTs
  // the log text to the daemon, which (as root) writes it to the chosen folder/name and
  // returns the final path. The folder is remembered in localStorage for next time.
  function openSaveSheet() {
    if (!lines.length) { toast("No logs to save"); return; }
    const dir = localStorage.getItem(SAVE_DIR_KEY) || DEFAULT_SAVE_DIR;
    const name = defaultLogName(moduleVer);
    saveHost = document.createElement("div");
    saveHost.appendChild(renderSaveSheet({ dir, name }, saveActions));
    saveOverlay = openSheet(saveHost, { label: "Save logs", onClose: () => { saveHost = null; saveOverlay = null; } });
  }

  const saveActions = {
    async save(dir, name) {
      const text = lines.map((l) => l.text).join("\n");
      if (!text) { toast("No logs to save"); return; }
      const folder = (dir || "").trim() || DEFAULT_SAVE_DIR;
      try {
        const res = await keyAdmin("logsWrite", { dir: folder, name, text });
        if (res && res.ok) {
          localStorage.setItem(SAVE_DIR_KEY, folder);
          toast("Saved to " + res.path);
          if (saveOverlay) saveOverlay.close();
        } else {
          toast("Save failed: " + ((res && res.error) || "unknown error"));
        }
      } catch (e) {
        console.error("[logs.save] write failed:", e);
        toast("Save failed: " + (e && e.message ? e.message : String(e)));
      }
    },
    close() { if (saveOverlay) saveOverlay.close(); },
  };

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
    openSaveSheet() { openSaveSheet(); },
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
      // Prefetch the module version so the default save filename is ready without awaiting.
      moduleVersion()
        .then((v) => { moduleVer = v; console.log("[logs] module version prefetched: %o", v); })
        .catch((e) => console.error("[logs] moduleVersion prefetch failed:", e));
      render(); // paint the buffer we already have instantly
      startPolling();
      return poll();
    },
  };
}
