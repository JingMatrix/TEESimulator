// Polls the daemon's /logs endpoint while the Logs tab is visible and feeds the
// growing scrollback to the view. Owns the client-side filter (min level, a set of
// selected tags, and a message substring), applied in the view; the filter controls
// live in a bottom sheet. Keeps a cursor (nextAfter) so each poll pulls only lines newer
// than the last, and caps how many it retains so a long session doesn't grow without bound.

import { keyAdmin } from "../data/keyadmin.js";
import { moduleVersion } from "../data/logs-io.js";
import { renderLogs, renderLogFilters } from "../ui/logs-view.js";
import { toast, clear, openSheet } from "../ui/dom.js";

const POLL_MS = 1500;
const MAX_FETCH = 500;
const MAX_KEPT = 4000;

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
  let moduleVer = ""; // cached at load so Save stays synchronous (an await would kill the gesture)

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
    // Synchronous by design: the download must fire inside the click's user-gesture, or the WebView
    // silently blocks it and never raises the system Save-As dialog. So no await here — the module
    // version is prefetched at load(). A Blob URL works over plain http:// (unlike the clipboard API),
    // and `download` supplies the default filename the dialog opens with (rename + choose location).
    async save() {
      const text = lines.map((l) => l.text).join("\n");
      if (!text) {
        toast("No logs to save");
        return;
      }
      const name = defaultLogName(moduleVer);

      // Prefer the system "Save As" picker (choose location + rename) via the File System Access
      // API. It needs a secure context and a user gesture — this WebUI is https and we're inside the
      // click, and moduleVer is prefetched so nothing awaits before the picker call. Falls back to a
      // plain download when the API is absent (older WebView). "AbortError" = the user cancelled.
      if (typeof window.showSaveFilePicker === "function") {
        try {
          const handle = await window.showSaveFilePicker({
            suggestedName: name,
            types: [{ description: "Log file", accept: { "text/plain": [".log"] } }],
          });
          const w = await handle.createWritable();
          await w.write(text);
          await w.close();
          toast("Saved " + name);
          return;
        } catch (e) {
          if (e && e.name === "AbortError") return;
          console.warn("[logs.save] showSaveFilePicker failed; falling back to download:", e);
        }
      }

      // Fallback: hand the file to the browser as a download.
      console.log("[logs.save] downloading %o (%d bytes)", name, text.length);
      try {
        const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
        const a = document.createElement("a");
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
        toast("Saved " + name);
      } catch (e) {
        console.error("[logs.save] failed:", e);
        toast("Save failed: " + (e && e.message ? e.message : String(e)));
      }
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
      // Prefetch the module version for the Save filename so save() needn't await (see save()).
      moduleVersion()
        .then((v) => { moduleVer = v; console.log("[logs] module version prefetched: %o", v); })
        .catch((e) => console.error("[logs] moduleVersion prefetch failed:", e));
      render(); // paint the buffer we already have instantly
      startPolling();
      return poll();
    },
  };
}
