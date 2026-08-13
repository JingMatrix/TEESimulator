// The profile CRUD presentation, in two halves that share the schema-driven field
// machinery:
//
//   renderProfileList(mount, state, actions)     the resting screen — one calm
//       summary row per profile (name + keybox/level/app chips), an Add primary,
//       cross-profile errors, and an unsaved-changes Save bar.
//   renderProfileEditor(host, state, actions)    the drill-in — the three fieldsets
//       with Device identity behind a collapsed disclosure, plus a sticky Save.
//
// Both are stateless: the config lives only in the controller, which hands each a
// snapshot and takes intents back through `actions`. Neither imports data/* or
// bridge/*. Each rebuilds its target on every call and restores keyboard focus so
// live re-validation on a keystroke never steals the caret.

import { el, clear, disclosure } from "./dom.js";
import { renderField } from "./field.js";
import { FIELDS, PROFILE_RE } from "../domain/schema.js";
import { getPath } from "../domain/path.js";

// Groups render top to bottom. `fold: true` collapses the group behind a disclosure so
// the editor stays concise — only the essentials (keybox, operation mode, apps) are open,
// with the patch/OS levels and the many device-identity fields tucked away until needed.
const GROUPS = [
  { id: "attestation", title: "Attestation" },
  { id: "levels", title: "Patch & OS levels", fold: true },
  {
    id: "identity", title: "Device identity", fold: true,
    note: "Each overrides one attested device id. Leave a field empty to use the value harvested from the device.",
  },
  { id: "apps", title: "Target apps" },
];

const fieldId = (profile, key) => `f__${profile}__${key}`;
const renameId = (profile) => `rn__${profile}`;

// A fold header: the section title, an optional "N set / optional" tag for the identity
// group, and an error mark when any field inside has an error.
function foldSummary(group, fields, profile, hasErrors) {
  const nodes = [el("span", { text: group.title })];
  if (group.id === "identity") {
    const setCount = fields.reduce((n, f) => {
      const v = getPath(profile, f.path);
      return n + (v != null && v !== "" ? 1 : 0);
    }, 0);
    nodes.push(el("span", { class: "count-tag", text: setCount ? setCount + " set" : "optional" }));
  }
  if (hasErrors) nodes.push(el("span", { class: "chip warn small", text: "!" }));
  return nodes;
}

// A cue under a level / identity field: what an empty value resolves to — the harvested value,
// meaning the raw capture OR the value fabricated at harvest (e.g. a serial/imei/meid read from the
// OS because the leaf never carries it) — or, when neither exists, that the tag will be omitted. A
// `system_property` value gets its own cue. Mirrors the keybox "(missing)" cue.
function resolveHint(d, value, resolved) {
  if (!Object.prototype.hasOwnProperty.call(resolved, d.key)) return null;
  const v = value == null ? "" : String(value).trim();
  if (v === "") {
    const rv = resolved[d.key];
    const has = rv != null && rv !== "";
    return el("div", {
      class: "field-help resolve-hint" + (has ? "" : " missing"),
      text: has ? "harvested → " + rv : "not harvested — this tag will be omitted",
    });
  }
  if (v === "system_property") {
    return el("div", { class: "field-help resolve-hint", text: "from the device build property; omitted if unset" });
  }
  return null;
}

// ---- the resting list ---------------------------------------------------
export function renderProfileList(mount, state, actions) {
  clear(mount);
  const { config, errors = [], dirty = false } = state;
  const names = Object.keys(config.profiles);

  const global = errors.filter((e) => e.profile == null).map((e) => e.msg);
  const errorCount = new Map(); // profile -> count
  for (const e of errors) {
    if (e.profile == null) continue;
    errorCount.set(e.profile, (errorCount.get(e.profile) || 0) + 1);
  }

  mount.appendChild(el("div", { class: "panel-head" }, [
    el("h1", { class: "panel-title", text: "Profiles" }),
    el("button", { class: "btn primary", text: "Add profile", onclick: () => actions.onAdd() }),
  ]));

  if (global.length) {
    mount.appendChild(el("div", { class: "banner error" }, global.map((m) => el("div", { text: m }))));
  }

  if (!names.length) {
    mount.appendChild(el("div", { class: "card empty" },
      [el("p", { class: "muted", text: "No profiles yet. Add one to start attesting for apps." })]));
    return;
  }

  const list = el("div", { class: "list" });
  for (const name of names) {
    const profile = config.profiles[name];
    const apps = getPath(profile, ["apps"]);
    const appCount = Array.isArray(apps) ? apps.length : 0;
    const chips = el("span", { class: "chips" }, [
      el("span", { class: "chip", text: getPath(profile, ["keybox"]) || "no keybox" }),
      el("span", { class: "chip", text: appCount + (appCount === 1 ? " app" : " apps") }),
      errorCount.get(name) ? el("span", { class: "chip warn", text: errorCount.get(name) + " to fix" }) : null,
    ]);
    list.appendChild(el("button", { class: "list-row", type: "button", onclick: () => actions.onOpen(name) }, [
      el("span", { class: "list-main" }, [
        el("span", { class: "list-title mono", text: name }),
        chips,
      ]),
      el("span", { class: "list-chevron", "aria-hidden": "true" }),
    ]));
  }
  mount.appendChild(list);

  // The unsaved-changes bar: only when there are pending edits. Save is the single
  // primary here; it persists the whole config and is gated on zero errors.
  if (dirty) {
    mount.appendChild(el("div", { class: "card save-bar" }, [
      errors.length
        ? el("span", { class: "muted small", text: errors.length + " issue" + (errors.length === 1 ? "" : "s") + " to fix before saving" })
        : el("span", { class: "status" }, [el("span", { class: "dot off" }), el("span", { class: "muted small", text: "Unsaved changes" })]),
      el("button", { class: "btn primary", text: "Save", disabled: errors.length > 0, onclick: () => actions.onSave() }),
    ]));
  }
}

// ---- the editor drill-in ------------------------------------------------
export function renderProfileEditor(host, state, actions) {
  const focus = captureFocus(host);
  const scrollTop = captureScroll(host);
  clear(host);

  const { config, name, errors = [], keyboxFiles = [], openGroups = {}, resolved = {}, scopeMeta = null } = state;
  const profile = config.profiles[name];
  if (!profile) { actions.onClose(); return; }

  const byField = new Map();
  for (const e of errors) {
    if (e.profile !== name) continue;
    const k = e.field;
    if (!byField.has(k)) byField.set(k, []);
    byField.get(k).push(e.msg);
  }
  const errFor = (field) => byField.get(field) || [];

  // Header: a back control that closes the drill-in, and the section title.
  host.appendChild(el("div", { class: "drill-head" }, [
    el("button", { class: "iconbtn", type: "button", "aria-label": "Back to profiles", onclick: () => actions.onClose() }, [
      el("span", { class: "chevron-left", "aria-hidden": "true" }),
    ]),
    el("h1", { class: "drill-title", text: "Edit profile", tabindex: "-1" }),
  ]));

  const body = el("div", { class: "drill-body" });

  // Rename lives at the top of the body.
  const renameInput = el("input", {
    id: renameId(name), class: "input", type: "text", value: name,
    autocapitalize: "off", autocorrect: "off", spellcheck: "false",
  });
  const doRename = () => {
    const next = renameInput.value.trim();
    if (next === name) return;
    if (!PROFILE_RE.test(next) || config.profiles[next]) { renameInput.classList.add("invalid"); return; }
    actions.onRename(name, next);
  };
  renameInput.addEventListener("change", doRename);
  renameInput.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); doRename(); } });
  const renameField = el("div", { class: "field" }, [
    el("label", { class: "field-label", for: renameId(name), text: "Profile name" }),
    renameInput,
  ]);
  for (const m of errFor("__name")) renameField.appendChild(el("div", { class: "err", text: m }));
  body.appendChild(renameField);

  // One line for the whole editor: an empty patch / OS / identity field falls back to the
  // value harvested from this device, shown on the System screen.
  body.appendChild(el("p", { class: "field-help editor-note" }, [
    "Leave a patch, OS, or identity field empty to use the value ",
    el("button", { type: "button", class: "linklike", onclick: () => actions.gotoSystem() }, "harvested from this device"),
    ".",
  ]));

  // The attestation + apps groups render as open fieldsets; identity collapses.
  const makeField = (d) => {
    const value = getPath(profile, d.path);
    const ctx = {
      id: fieldId(name, d.key), keyboxFiles,
      addApp: (pkg) => actions.onAddApp(name, pkg),
      removeApp: (pkg) => actions.onRemoveApp(name, pkg),
      // The scope widget only shows the current picks and a button that opens the picker;
      // labelMap/installedSet let its chips show real app names and flag uninstalled ones,
      // and are null until the Scope page has been opened once (then the chips light up).
      openScope: () => actions.openScope(name),
      labelMap: scopeMeta && scopeMeta.labelMap,
      installedSet: scopeMeta && scopeMeta.installedSet,
    };
    const onChange = (path, v) => actions.onFieldChange(name, path, v);
    const fieldEl = renderField(d, value, onChange, ctx);
    const hint = resolveHint(d, value, resolved);
    if (hint) fieldEl.appendChild(hint);
    for (const m of errFor(d.key)) fieldEl.appendChild(el("div", { class: "err", text: m }));
    return fieldEl;
  };

  for (const group of GROUPS) {
    const groupFields = FIELDS.filter((f) => f.group === group.id);
    if (!groupFields.length) continue;

    if (group.fold) {
      const groupErrors = groupFields.some((f) => errFor(f.key).length);
      const foldBody = [];
      if (group.note) foldBody.push(el("p", { class: "field-help", text: group.note }));
      foldBody.push(...groupFields.map(makeField));
      body.appendChild(disclosure(foldSummary(group, groupFields, profile, groupErrors), foldBody, {
        open: !!openGroups[group.id] || groupErrors,
        onToggle: () => actions.onToggleGroup(group.id),
        id: "disc-" + group.id,
      }));
      continue;
    }

    const fs = el("fieldset", { class: "group" }, [el("legend", { text: group.title })]);
    for (const d of groupFields) fs.appendChild(makeField(d));
    body.appendChild(fs);
  }

  body.appendChild(el("button", {
    class: "btn danger ghost block", type: "button", text: "Remove profile",
    onclick: () => actions.onRemove(name),
  }));

  host.appendChild(body);

  // Sticky save bar pinned to the bottom of the drill-in.
  host.appendChild(el("div", { class: "drill-foot" }, [
    errors.length
      ? el("span", { class: "muted small", text: errors.length + " issue" + (errors.length === 1 ? "" : "s") + " to fix" })
      : el("span", { class: "status" }, [el("span", { class: "dot ok" }), el("span", { class: "muted small", text: "Ready to save" })]),
    el("button", { class: "btn primary", text: "Save", disabled: errors.length > 0, onclick: () => actions.onSave() }),
  ]));

  restoreFocus(focus);

  // Restore scroll LAST — a fold toggle rebuilds the whole editor, and the body only reaches its
  // final height once the header, body, and footer are all in place. Setting scrollTop earlier
  // (before the footer existed) wrote against a taller body, so the offset was clamped away and the
  // list snapped to the top. Do it here, then again on the next frame in case layout hadn't settled.
  body.scrollTop = scrollTop;
  requestAnimationFrame(() => { body.scrollTop = scrollTop; });
}

// ---- scroll retention across a stateless rebuild ------------------------
// The editor rebuilds its whole subtree on every change (a fold toggle included).
// Grab the scrollable body's offset before the teardown so it can be reinstated.
function captureScroll(container) {
  const body = container.querySelector(".drill-body");
  return body ? body.scrollTop : 0;
}

// ---- focus retention across a stateless rebuild -------------------------
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
  again.focus({ preventScroll: true }); // don't let focus fight the scroll restore
  try { if (f.selStart != null) again.setSelectionRange(f.selStart, f.selEnd); } catch { /* not selectable */ }
}
