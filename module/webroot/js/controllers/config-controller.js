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
import { validateConfig } from "../domain/validate.js";
import { emptyProfile, emptyConfig, FIELDS, PROFILE_RE } from "../domain/schema.js";
import { setPath, getPath } from "../domain/path.js";
import { renderProfileList, renderProfileEditor } from "../ui/config-view.js";
import { el, clear, toast, confirmDialog, promptDialog, openOverlay } from "../ui/dom.js";

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

  function revalidate() {
    errors = validateConfig(config).errors;
  }

  // Best-effort: what `harvested` (and, roughly, `system_property`) resolves to, so the
  // editor can show the effective value or that a tag will be omitted.
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
    return {
      patchSystem: h.osPatchLevel, patchVendor: h.vendorPatchLevel, patchBoot: h.bootPatchLevel, osVersion: h.osVersion,
      brand: h.brand, device: h.device, product: h.product, manufacturer: h.manufacturer, model: h.model,
      serial: h.serial, imei: h.imei, meid: h.meid, imei2: h.imei2,
    };
  }

  function renderList() {
    renderProfileList(mount, { config, errors, dirty }, listActions);
  }

  function renderEditor() {
    if (!editing || !editorHost) return;
    renderProfileEditor(editorHost, { config, name: editing, errors, keyboxFiles, openGroups, resolved: resolvedLevels() }, editorActions);
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

  // ---- the one save path (used by both the list bar and the editor) -----
  async function save() {
    revalidate(); // hard gate
    if (errors.length) {
      toast(errors[0].msg);
      editing ? renderEditor() : renderList();
      return;
    }
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
    },

    onToggleGroup(id) {
      openGroups[id] = !openGroups[id];
      renderEditor();
    },

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
