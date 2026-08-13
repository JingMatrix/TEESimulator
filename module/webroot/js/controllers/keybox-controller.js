// Wires keybox-view to the keybox-io transport. The resting screen is the list;
// Import opens a bottom sheet whose transient state (the pending import's name +
// content) lives here. Nothing reaches the shell except via data/keybox-io.js, and
// every name it forwards is re-validated there before a path is built.

import { listKeyboxes, importKeybox, renameKeybox, deleteKeybox } from "../data/keybox-io.js";
import { keyAdmin } from "../data/keyadmin.js";
import { readRkpProps, setRkpProp } from "../data/rkp-io.js";
import { renderKeyboxes, renderKeyboxImport, renderKeyboxInspect, fillKeyboxInspect } from "../ui/keybox-view.js";
import { renderRkpSection } from "../ui/rkp-view.js";
import { el, toast, confirmDialog, promptDialog, openSheet, openOverlay } from "../ui/dom.js";
import { attachPullToRefresh } from "../ui/pull-refresh.js";

export function create(mount) {
  let files = [];
  let importName = "";      // the filename the pending import will be written as
  let importContent = "";   // the chosen file's text, read in the browser
  let error = null;
  let sheetHost = null;     // content element inside the import sheet
  let sheetOverlay = null;  // { close } while the sheet is open
  let inspectOverlay = null; // { close } while the inspect drill-in is open
  let rkpRows = [];         // the Remote Key Provision knobs this device defines (empty => no section)
  let rkpWrap = null;       // the <section> hosting that panel, recreated on every full render

  function render() {
    renderKeyboxes(mount, { files }, actions); // clears mount, paints the Keyboxes panel
    // Append the Remote Key Provision section as a sibling flex child of the screen so it keeps the
    // screen's inter-panel gap and its own head/card spacing. renderKeyboxes just cleared the mount,
    // so recreate the wrapper — only when the device actually exposes one of the RKP properties.
    rkpWrap = rkpRows.length ? el("section", { class: "rkp-section" }) : null;
    if (rkpWrap) { mount.appendChild(rkpWrap); paintRkp(); }
  }

  function paintRkp() {
    if (rkpWrap) renderRkpSection(rkpWrap, { rows: rkpRows }, rkpActions);
  }

  async function refreshRkp() {
    rkpRows = await readRkpProps();
    // A toggle only ever changes a value (the knob stays present), so the wrapper is already there
    // and a repaint suffices; fall back to a full render only if the section has to appear/disappear.
    if (!!rkpRows.length === !!rkpWrap) paintRkp();
    else render();
  }

  function renderSheet() {
    if (!sheetHost) return;
    while (sheetHost.firstChild) sheetHost.removeChild(sheetHost.firstChild);
    sheetHost.appendChild(renderKeyboxImport({ importName, importContent, error }, actions));
  }

  async function refresh() {
    files = await listKeyboxes();
    rkpRows = await readRkpProps();
    render();
  }

  function openImport() {
    importName = "";
    importContent = "";
    error = null;
    sheetHost = document.createElement("div");
    sheetHost.appendChild(renderKeyboxImport({ importName, importContent, error }, actions));
    sheetOverlay = openSheet(sheetHost, { label: "Import keybox", onClose: () => { sheetHost = null; sheetOverlay = null; } });
  }

  function closeImport() {
    if (sheetOverlay) sheetOverlay.close();
  }

  // Inspect drill-in: fetch the parsed keybox from the daemon (BouncyCastle does the
  // real X.509 work root-side) and pretty-print its chains. Read-only.
  async function openInspect(name) {
    let data;
    try {
      data = await keyAdmin("keyboxInspect", { name });
    } catch (e) {
      toast("Inspect failed: " + (e && e.message ? e.message : String(e)));
      return;
    }
    const content = renderKeyboxInspect({ name, data }, { close: () => closeInspect() });
    const body = content.querySelector(".drill-body");
    let detachPtr = null;
    inspectOverlay = openOverlay(content, {
      variant: "panel", label: "Keybox",
      onClose: () => { if (detachPtr) detachPtr(); detachPtr = null; inspectOverlay = null; },
    });
    // Pull down on the detail page to re-fetch Google's revocation list and re-verify in place.
    // The spinner must clear the overlay (z-index 40), and detachPtr removes the fixed dot on close.
    detachPtr = attachPullToRefresh(body, () => refreshInspect(name, body), { scroller: body, zIndex: 41 });
    const title = content.querySelector(".drill-title");
    if (title) title.focus();
  }

  // Re-inspect with a forced, cache-busted revocation-list refresh, then refill the same body node.
  async function refreshInspect(name, body) {
    let data;
    try {
      data = await keyAdmin("keyboxInspect", { name, refresh: true });
    } catch (e) {
      toast("Refresh failed: " + (e && e.message ? e.message : String(e)));
      return;
    }
    fillKeyboxInspect(body, { name, data });
  }

  function closeInspect() {
    if (inspectOverlay) inspectOverlay.close();
  }

  const actions = {
    onImport() { openImport(); },
    inspect(name) { openInspect(name); },
    close() { closeImport(); },

    // Read the picked file entirely in the page (readAsText); no bytes touch the
    // shell here. Default the name to the file's basename unless one was typed.
    pickFile(file) {
      const reader = new FileReader();
      reader.onload = () => {
        importContent = reader.result == null ? "" : String(reader.result);
        if (!importName) importName = file.name || "";
        error = null;
        renderSheet();
      };
      reader.onerror = () => { error = "Could not read that file."; renderSheet(); };
      reader.readAsText(file);
    },

    // Keystrokes only update the field — no re-render, so the caret stays put.
    setImportName(v) {
      importName = v;
    },

    async import() {
      let r = await importKeybox(importName, importContent, files);
      if (!r.ok && r.exists) {
        if (!(await confirmDialog(`Overwrite existing keybox "${r.name}"?`))) return;
        r = await importKeybox(importName, importContent, files, true);
      }
      if (!r.ok) {
        error = r.error;
        toast("Import failed: " + (r.error || "unknown error"));
        renderSheet();
        return;
      }
      toast("Imported " + r.name);
      closeImport();
      return refresh();
    },

    async rename(name) {
      const next = await promptDialog(`Rename "${name}" to:`, name, { okLabel: "Rename" });
      if (next == null) return; // cancelled
      const r = await renameKeybox(name, next, files);
      if (!r.ok) { toast("Rename failed: " + (r.error || "unknown error")); return; }
      toast("Renamed to " + r.name);
      return refresh();
    },

    async delete(name) {
      if (!(await confirmDialog(`Delete keybox "${name}"? This cannot be undone.`))) return;
      const r = await deleteKeybox(name);
      if (!r.ok) { toast("Delete failed: " + (r.error || "unknown error")); return; }
      toast("Deleted " + (r.name || name));
      return refresh();
    },
  };

  const rkpActions = {
    async toggle(name, on) {
      // No toast: the switch is its own feedback, and refreshRkp re-reads so a failed write just
      // snaps the knob back to the value the device actually took.
      await setRkpProp(name, on);
      return refreshRkp();
    },
  };

  attachPullToRefresh(mount, refresh);

  return {
    load() {
      return refresh();
    },
  };
}
