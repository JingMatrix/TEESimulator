// The profile CRUD presentation, in two halves that share the schema-driven field
// machinery:
//
//   renderProfileList(mount, state, actions)     the resting screen — one calm
//       summary row per profile (name + keybox/level/app chips), an Add primary,
//       cross-profile errors, and an unsaved-changes Save bar.
//   renderProfileEditor(host, state, actions)    the drill-in — the profile name as an
//       editable title, then one card per group (patch levels and device identity behind a
//       collapsed disclosure), plus a sticky Save.
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
// with the patch levels and the many device-identity fields tucked away until needed.
//
// The OS version sits with device identity, not with the patch levels: it is attested about
// the device like the brand and the model, and it has to agree with them.
const GROUPS = [
  { id: "attestation", title: "Attestation" },
  { id: "levels", title: "Security patch levels", fold: true },
  { id: "identity", title: "Device identity", fold: true },
  { id: "apps", title: "Target apps" },
];

// A default longer than this gets its own line under the field instead of being greyed inside
// the box, where it would be clipped. One value needs it: the 64-character verified boot hash.
const INLINE_DEFAULT_MAX = 28;

// A keybox file name is often 32 hex characters: keep both ends, which is what tells two of
// them apart, and elide the middle so one profile row stays one line.
function elide(name, max = 26) {
  const s = String(name);
  if (s.length <= max) return s;
  const keep = Math.floor((max - 1) / 2);
  return s.slice(0, keep) + "…" + s.slice(-keep);
}

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

// What a field left empty will attest, and which of the two sources says it, as the pieces the
// field renders with: a tag beside the label naming the source, and the value itself — greyed
// inside the box when it fits, on its own line when it does not (the 64-character boot hash), and
// on a patch picker's own "default" option, which states it there instead.
//
// The keybox comes first — an RKP keybox records the device it was provisioned for, and attesting
// this device's own value under it contradicts the keybox signing the chain — then the harvest,
// meaning the raw capture OR the value fabricated at harvest (e.g. a serial/imei/meid read from
// the OS because the leaf never carries it). When neither has it, the tag says the tag is omitted.
//
// `resolved[key]` is { value, source }; source is "keybox" or "harvest".
function defaultCue(d, value, resolved) {
  if (!Object.prototype.hasOwnProperty.call(resolved, d.key)) return null;
  const v = value == null ? "" : String(value).trim();
  if (v !== "") return null;
  const rd = resolved[d.key] || {};
  const rv = rd.value == null ? "" : String(rd.value);
  if (rv === "") {
    return { tag: { text: "omitted", kind: "warn", title: "Nothing harvested, so this tag is left out of the attestation." } };
  }
  const keybox = rd.source === "keybox";
  return {
    value: humanDefault(d, rv),
    tag: {
      text: keybox ? "keybox" : "harvested",
      kind: keybox ? "keybox" : "",
      title: keybox
        ? "Stated by this profile's keybox, about the device it was provisioned for."
        : "Harvested from this device.",
    },
  };
}

// The daemon reports what it harvested the way the attestation carries it: a patch level packed
// as 202604 or 20260405, an OS version as 160000. This form speaks dates and dotted versions, so a
// default is shown — and seeded into "custom…" — in the syntax the field itself accepts.
function humanDefault(d, raw) {
  const v = String(raw == null ? "" : raw).trim();
  if (d.key === "osVersion") {
    if (!/^\d{5,6}$/.test(v)) return v;
    const n = Number(v);
    return Math.floor(n / 10000) + "." + (Math.floor(n / 100) % 100) + "." + (n % 100);
  }
  if (d.type !== "patch") return v;
  if (/^\d{8}$/.test(v)) return v.slice(0, 4) + "-" + v.slice(4, 6) + "-" + v.slice(6);
  if (/^\d{6}$/.test(v)) return v.slice(0, 4) + "-" + v.slice(4, 6);
  return v;
}

// The one value that is neither typed nor defaulted: read from the build property at push time.
function propertyHint(value) {
  const v = value == null ? "" : String(value).trim();
  if (v !== "system_property") return null;
  return el("div", { class: "field-help resolve-hint", text: "from the device build property; omitted if unset" });
}

// ---- the resting list ---------------------------------------------------
export function renderProfileList(mount, state, actions) {
  clear(mount);
  // autoCounts: Map(profile name -> how many apps the daemon auto-includes for it), from its
  // resolved snapshot. Empty when /scope is unavailable, in which case the rows read as before.
  const { config, errors = [], dirty = false, autoCounts = new Map() } = state;
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
    // The "N apps" count counts apps[] only, which under-reports an auto-including profile; the
    // auto count is the rest of the truth, and this is the resting screen where that lie was loudest.
    const autoN = autoCounts.get(name) || 0;
    const bad = errorCount.get(name) || 0;
    // One line of facts under the name: which keybox signs for it, and how many apps it covers.
    // The keybox file is often a 32-hex name, so it is elided in the middle — the ends are what
    // tells two of them apart.
    const sub = [elide(getPath(profile, ["keybox"]) || "no keybox")];
    // "0 apps · 7 auto" tells a profile covered entirely by auto-include that it covers nothing.
    if (appCount || !autoN) sub.push(appCount + (appCount === 1 ? " app" : " apps"));
    if (autoN) sub.push(autoN + " auto");
    list.appendChild(el("button", { class: "list-row", type: "button", onclick: () => actions.onOpen(name) }, [
      el("span", { class: "list-main" }, [
        el("span", { class: "list-head" }, [
          el("span", { class: "list-title mono", text: name }),
          el("span", { class: "chips" }, [
            el("span", { class: "chip small", text: getPath(profile, ["mode"]) || "patch" }),
            bad ? el("span", { class: "chip warn small", text: bad + " to fix" }) : null,
          ]),
        ]),
        el("span", { class: "list-sub", text: sub.join(" · ") }),
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

  const { config, name, errors = [], keyboxFiles = [], openGroups = {}, resolved = {}, scopeMeta = null, autoTakenBy = null, autoCount = 0 } = state;
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

  // Header: a back control that closes the drill-in, and the profile's own name as the title —
  // editable in place, which is both where a name belongs and one field fewer in the body.
  const renameInput = el("input", {
    id: renameId(name), class: "drill-title-input", type: "text", value: name,
    "aria-label": "Profile name", placeholder: "profile name",
    // Sized to the name it holds, so the rule under it reads as this field's underline and not
    // as a divider across the header.
    size: String(Math.max(8, Math.min(22, name.length + 1))),
    autocapitalize: "off", autocorrect: "off", spellcheck: "false",
  });
  const doRename = () => {
    const next = renameInput.value.trim();
    if (next === name) return;
    if (!PROFILE_RE.test(next) || config.profiles[next]) { renameInput.classList.add("invalid"); return; }
    actions.onRename(name, next);
  };
  renameInput.addEventListener("change", doRename);
  renameInput.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); renameInput.blur(); } });
  host.appendChild(el("div", { class: "drill-head" }, [
    el("button", { class: "iconbtn", type: "button", "aria-label": "Back to profiles", onclick: () => actions.onClose() }, [
      el("span", { class: "chevron-left", "aria-hidden": "true" }),
    ]),
    renameInput,
  ]));

  const body = el("div", { class: "drill-body" });
  for (const m of errFor("__name")) body.appendChild(el("div", { class: "err", text: m }));

  // One line for the whole editor: an empty patch / OS / identity field takes a default, and the
  // tag beside each one names it. Only the harvest gets a link — it is a screen in this UI; what a
  // keybox states is read off the keybox itself, in the Keyboxes panel.
  body.appendChild(el("p", { class: "field-help editor-note" }, [
    "A field left empty attests the value beside it: what this profile's keybox states, else what was ",
    el("button", { type: "button", class: "linklike", onclick: () => actions.gotoSystem() }, "harvested from this device"),
    ".",
  ]));

  // One field: the widget from the schema, plus whatever its empty-value default needs — a tag
  // beside the label, the value greyed inside the box, and a line of its own only for a default
  // too long to sit in one.
  const makeField = (d) => {
    const value = getPath(profile, d.path);
    const cue = defaultCue(d, value, resolved);
    const inBox = d.type === "text" && cue && cue.value && cue.value.length <= INLINE_DEFAULT_MAX;
    const fallback = resolved[d.key] ? humanDefault(d, resolved[d.key].value) : "";
    const ctx = {
      id: fieldId(name, d.key), keyboxFiles,
      tag: cue ? cue.tag : null,
      placeholder: inBox ? cue.value : "",
      // What this field falls back to, whatever it holds now: a patch picker names it on its own
      // "default" option, and "custom…" opens its box on it.
      defaultValue: fallback,
      addApp: (pkg) => actions.onAddApp(name, pkg),
      removeApp: (pkg) => actions.onRemoveApp(name, pkg),
      // The scope widget only shows the current picks and a button that opens the picker;
      // labelMap/installedSet let its chips show real app names and flag uninstalled ones,
      // and are null until the Scope page has been opened once (then the chips light up).
      openScope: () => actions.openScope(name),
      labelMap: scopeMeta && scopeMeta.labelMap,
      installedSet: scopeMeta && scopeMeta.installedSet,
      // So the scope face can say "auto-include on — new apps added automatically" instead of
      // "no apps" when the profile relies on auto-include rather than explicit picks.
      autoInclude: getPath(profile, ["autoIncludeNewApps"]) === true,
      // The auto-include toggle disables itself (with a note) when ANOTHER profile already owns
      // auto-include — only one profile may, so the conflict shows before Save rejects it.
      autoTakenBy,
      // How many apps the daemon currently auto-includes for this profile, from its resolved
      // snapshot — the count config.json cannot supply.
      autoCount,
    };
    const onChange = (path, v) => actions.onFieldChange(name, path, v);
    const fieldEl = renderField(d, value, onChange, ctx);
    // The default's value on a line of its own, for the one case nothing else carries it: a
    // default too long to sit greyed inside the box (the 64-character verified boot hash).
    if (cue && cue.value && !inBox && d.type === "text") {
      fieldEl.appendChild(el("div", {
        class: "field-help resolve-hint" + (cue.tag.kind === "keybox" ? " from-keybox" : ""),
        text: cue.value,
      }));
    }
    const prop = propertyHint(value);
    if (prop) fieldEl.appendChild(prop);
    for (const m of errFor(d.key)) fieldEl.appendChild(el("div", { class: "err", text: m }));
    return fieldEl;
  };

  for (const group of GROUPS) {
    const groupFields = FIELDS.filter((f) => f.group === group.id);
    if (!groupFields.length) continue;
    const groupErrors = groupFields.some((f) => errFor(f.key).length);
    const note = group.note ? el("p", { class: "field-help group-note", text: group.note }) : null;

    if (group.fold) {
      body.appendChild(disclosure(foldSummary(group, groupFields, profile, groupErrors), [
        note, ...groupFields.map(makeField),
      ], {
        open: !!openGroups[group.id] || groupErrors,
        onToggle: () => actions.onToggleGroup(group.id),
        id: "disc-" + group.id,
      }));
      continue;
    }

    // An open group is the same card as a folded one, minus the chevron: one header row, then the
    // fields. (A <fieldset> legend cuts a notch in its own border, which read as a different kind
    // of thing beside the folded sections.)
    const section = el("section", { class: "group" }, [
      el("h2", { class: "group-head", text: group.title }),
      note,
    ]);
    for (const d of groupFields) section.appendChild(makeField(d));
    body.appendChild(section);
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

  restoreFocus(focus, host);

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

function restoreFocus(f, container) {
  if (!f.id) {
    // Nothing was focused before the rebuild, so nothing should be after it. The webview focuses
    // the first text field of a freshly built subtree on its own, and the NEXT render — triggered
    // by a tap, so inside a user gesture — would then re-focus it and throw up the keyboard over
    // whatever the user actually tapped. Take it back once the webview has had its turn.
    if (container) {
      requestAnimationFrame(() => {
        const a = document.activeElement;
        if (a && a.tagName === "INPUT" && container.contains(a)) a.blur();
      });
    }
    return;
  }
  const again = document.getElementById(f.id);
  if (!again) return;
  again.focus({ preventScroll: true }); // don't let focus fight the scroll restore
  try { if (f.selStart != null) again.setSelectionRange(f.selStart, f.selEnd); } catch { /* not selectable */ }
}
