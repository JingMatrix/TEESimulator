// Render exactly one field from a descriptor. A descriptor.type -> widget switch,
// and nothing else. Stateless, no I/O, no imports beyond the DOM helpers.
//
// renderField(descriptor, value, onChange, context) -> HTMLElement
//   value    the current value, already read at descriptor.path by the caller
//   onChange (path, value) => ...  for scalar widgets (text/select/patch/keybox)
//   context  { id, keyboxFiles, addApp(entry), removeApp(entry), openScope(),
//              labelMap, installedSet, autoInclude, autoTakenBy }
//            - id           stable element id, so a re-render can restore focus
//            - keyboxFiles  choices for the 'keybox' widget
//            - addApp/removeApp  the applist/scope widget's structural callbacks
//            - openScope    the scope widget's "Configure scope" jump (opens the picker)
//            - labelMap     optional Map(package -> human label) so a scope chip can show
//                           the app's real name, not just its package
//            - installedSet optional Set of installed package names, so a scope chip can
//                           flag a package that is not currently installed on the device
//            - autoInclude  whether this profile has auto-include on
//            - autoCount    how many apps the daemon currently auto-includes for it (0 when
//                           /scope is unavailable), so the face can count what apps[] cannot
//            - autoInclude  whether this profile has auto-include on (scope face empty state)
//            - autoTakenBy  for the auto-include toggle: the OTHER profile that already owns
//                           auto-include (or null); when set, the switch renders disabled with
//                           a "(used by <name>)" note, since only one profile may auto-include
//
// A new descriptor of an EXISTING type needs no edit here. A new type is one new
// case below.

import { el } from "./dom.js";
import { UID_RE } from "../domain/schema.js";

export function renderField(descriptor, value, onChange, context = {}) {
  switch (descriptor.type) {
    case "select":
      return labelled(descriptor, selectWidget(descriptor, value, onChange, context));
    case "keybox":
      return labelled(descriptor, keyboxWidget(descriptor, value, onChange, context));
    case "patch":
      return labelled(descriptor, patchWidget(descriptor, value, onChange, context));
    case "applist":
      return labelled(descriptor, applistWidget(descriptor, value, context));
    case "scope":
      return labelled(descriptor, scopeWidget(descriptor, value, context));
    case "toggle":
      return toggleField(descriptor, value, onChange, context);
    case "text":
    default:
      return labelled(descriptor, textWidget(descriptor, value, onChange, context));
  }
}

// Shared wrapper: <div.field> with a label, the control, and optional help text.
// The caller (config-view) appends any inline error after this element.
//
// The <label for> must reference a real focusable control, not a wrapper <div>.
// For the simple widgets the control IS the input/select; for the patch and applist
// widgets it's a wrapper whose focusable input lives inside — so target that input's
// id rather than the id-less wrapper, otherwise those fields have no programmatic
// label.
function labelled(descriptor, control) {
  // Prefer a real form control; but a compound widget (the scope face) has none — its only id-bearing
  // focusable is the "Configure scope" <button id=ctx.id>, so fall back to the first element carrying
  // an id, restoring the label→control association rather than emitting for=null.
  const focusable = control.matches("input, select, textarea")
    ? control
    : control.querySelector("input, select, textarea") || control.querySelector("[id]");
  return el("div", { class: "field" }, [
    el("label", { class: "field-label", for: (focusable && focusable.id) || null, text: descriptor.label }),
    control,
    descriptor.help ? el("div", { class: "field-help", text: descriptor.help }) : null,
  ]);
}

function textWidget(d, value, onChange, ctx) {
  const input = el("input", {
    id: ctx.id, class: "input", type: "text", value: value == null ? "" : value,
    autocapitalize: "off", autocorrect: "off", spellcheck: "false",
    oninput: (e) => {
      const v = e.target.value;
      input.classList.toggle("invalid", !!(d.re && v !== "" && !d.re.test(v)));
      onChange(d.path, v);
    },
  });
  return input;
}

function patchWidget(d, value, onChange, ctx) {
  const input = textWidget(d, value, onChange, ctx);
  // Quick-picks for the patch mini-language, so common values need no typing. The set
  // is per-field (descriptor.picks): vendor/boot offer a YYYY-MM-05 date, a common
  // vendor patch day, that the system (YYYY-MM) field has no use for.
  const pick = (v) => {
    input.value = v;
    input.classList.toggle("invalid", !!(d.re && v !== "" && !d.re.test(v)));
    onChange(d.path, v);
  };
  const picks = (d.picks || ["system_property", "today", "no"]).map(resolvePick);
  const chips = el("div", { class: "quickpicks" },
    picks.map((p) =>
      el("button", { type: "button", class: "chip clickable", text: p.label, onclick: () => pick(p.value) })));
  return el("div", { class: "patch" }, [input, chips]);
}

// A quick-pick token -> { label, value }. "@month05" inserts the template "YYYY-MM-05"
// (a common vendor/boot patch date); the daemon resolves YYYY/MM to today, so it tracks
// the calendar rather than freezing to the month it was picked.
function resolvePick(token) {
  if (token === "@month05") return { label: "YYYY-MM-05", value: "YYYY-MM-05" };
  return { label: token, value: token };
}

function selectWidget(d, value, onChange, ctx) {
  return el("select", {
    id: ctx.id, class: "input",
    onchange: (e) => onChange(d.path, e.target.value),
  }, (d.options || []).map((opt) =>
    el("option", { value: opt, selected: opt === value, text: opt })));
}

function keyboxWidget(d, value, onChange, ctx) {
  // Union of the discovered files and the current value, so a config that names
  // a keybox we can't see right now still shows (flagged) rather than vanishing.
  const files = (ctx.keyboxFiles || []).slice();
  if (value && !files.includes(value)) files.push(value);
  if (files.length === 0) {
    return el("select", { id: ctx.id, class: "input", disabled: true },
      [el("option", { text: "no keybox files found" })]);
  }
  return el("select", {
    id: ctx.id, class: "input",
    onchange: (e) => onChange(d.path, e.target.value),
  }, files.map((f) =>
    el("option", { value: f, selected: f === value, text: f + ((ctx.keyboxFiles || []).includes(f) ? "" : " (missing)") })));
}

function applistWidget(d, value, ctx) {
  const apps = Array.isArray(value) ? value : [];
  const chips = el("div", { class: "applist" }, apps.length
    ? apps.map((pkg) => el("span", { class: "chip removable" }, [
        el("span", { class: "chip-text", text: pkg }),
        el("button", { type: "button", class: "chip-x", "aria-label": "Remove " + pkg, text: "✕",
          onclick: () => ctx.removeApp(pkg) }),
      ]))
    : [el("span", { class: "muted small", text: "No apps yet." })]);

  const input = el("input", {
    id: ctx.id, class: "input", type: "text", placeholder: "com.example.app",
    autocapitalize: "off", autocorrect: "off", spellcheck: "false",
  });
  const submit = () => {
    const v = input.value.trim();
    if (!v) return;
    if (!d.re.test(v)) { input.classList.add("invalid"); return; }
    ctx.addApp(v);
    input.value = "";
  };
  input.addEventListener("input", () => input.classList.toggle("invalid", input.value.trim() !== "" && !d.re.test(input.value.trim())));
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); submit(); } });
  const add = el("button", { type: "button", class: "btn", text: "Add", onclick: submit });

  return el("div", {}, [chips, el("div", { class: "add-row" }, [input, add])]);
}

// A labelled switch: a checkbox styled as an iOS-style toggle. The visible track/thumb is
// a sibling of the (visually hidden but full-size) checkbox, so a tap anywhere on the track
// flips it and CSS drives the thumb off `:checked`. onChange gets the boolean, never a string.
//
// Auto-include is a whole-device catch-all, so at most one profile may own it: when another
// profile already does, ctx.autoTakenBy names it and the switch renders disabled with a short
// "(used by <name>)" note, so the conflict is legible before Save rejects it.
// A compact settings ROW (not the three-line label/control/help stack): the title and its help sit
// stacked on the left as a <label for> that also toggles, and the switch sits inline on the right.
// The help doubles as the "used by <profile>" note when auto-include is locked to another profile.
function toggleField(d, value, onChange, ctx) {
  const checked = value === true;
  const locked = d.key === "autoIncludeNewApps" && !!ctx.autoTakenBy && !checked;
  const input = el("input", {
    id: ctx.id, class: "switch-input", type: "checkbox", checked, disabled: locked,
    role: "switch", "aria-checked": checked ? "true" : "false",
    onchange: locked ? null : (e) => onChange(d.path, e.target.checked),
  });
  const sw = el("span", { class: "switch" + (checked ? " on" : "") + (locked ? " disabled" : "") }, [
    input,
    el("span", { class: "switch-track", "aria-hidden": "true" }, [el("span", { class: "switch-thumb" })]),
  ]);
  const sub = locked ? "Used by profile “" + ctx.autoTakenBy + "”" : d.help;
  return el("div", { class: "field toggle-field" }, [
    el("div", { class: "toggle-row" }, [
      el("label", { class: "toggle-main", for: ctx.id }, [
        el("span", { class: "field-label", text: d.label }),
        sub ? el("span", { class: "field-help", text: sub }) : null,
      ]),
      sw,
    ]),
  ]);
}

// The scope field's compact read-only face inside the editor. Selection happens
// on the Scope page (ctx.openScope); here we only SUMMARISE it in the fewest words: a header row
// with the count and a "Configure scope →" button, then a preview of at most a handful of app
// chips (label only — no package sub-line, no long tally). Extra picks collapse into a "+K more"
// chip. A not-installed / advanced entry gets a small warn dot, never a paragraph. It stays
// resilient before the device app list is fetched: labelMap/installedSet are optional, so a chip
// degrades to its raw package name.
const SCOPE_PREVIEW_MAX = 6;

function scopeWidget(d, value, ctx) {
  const apps = Array.isArray(value) ? value : [];
  const labelMap = ctx.labelMap || null;         // package -> human label
  const installedSet = ctx.installedSet || null; // installed package names

  // apps[] only ever names hand-picked entries, so on its own the count under-reports a profile that
  // auto-includes. Add the daemon's auto count beside it — otherwise this face says "2 apps" for a
  // profile being attested for eleven.
  const autoCount = Number(ctx.autoCount) || 0;
  const countText = (apps.length ? apps.length + (apps.length === 1 ? " app" : " apps") : "No apps") +
    (autoCount ? " · " + autoCount + " auto" : "");
  const header = el("div", { class: "scope-field-head" }, [
    el("span", { class: "scope-field-count", text: countText }),
    el("button", { id: ctx.id, type: "button", class: "btn primary small", text: "Configure scope →", onclick: () => ctx.openScope && ctx.openScope() }),
  ]);

  const kids = [header];

  if (apps.length) {
    const shown = apps.slice(0, SCOPE_PREVIEW_MAX);
    const chips = shown.map((entry) => {
      const isUid = UID_RE.test(entry);
      const missing = !isUid && installedSet && !installedSet.has(entry);
      const label = isUid ? entry : ((labelMap && labelMap.get && labelMap.get(entry)) || entry);
      return el("span", {
        class: "chip scope-chip" + (isUid ? " advanced" : "") + (missing ? " warn" : ""),
        title: isUid ? "Advanced: targets caller uid " + entry.slice(4)
          : missing ? entry + " is not installed (a name-match applies if it installs later)" : entry,
      }, [
        (isUid || missing) ? el("span", { class: "scope-chip-dot", "aria-hidden": "true" }) : null,
        el("span", { class: "chip-text" + (isUid ? " mono" : ""), text: label }),
      ]);
    });
    if (apps.length > SCOPE_PREVIEW_MAX) {
      chips.push(el("span", { class: "chip scope-chip more", text: "+" + (apps.length - SCOPE_PREVIEW_MAX) + " more" }));
    }
    kids.push(el("div", { class: "applist scope-preview" }, chips));
  }

  // Rendered ALONGSIDE the chips, not only instead of them: a profile with picks AND auto-include is
  // the common case, and it is exactly the one where apps[] alone misleads. Worded from the live
  // count so it stops claiming apps are added "automatically" when there are none.
  if (ctx.autoInclude) {
    kids.push(el("span", { class: "muted small", text: autoCount
      ? "Auto-include on — " + autoCount + (autoCount === 1 ? " app" : " apps") + " installed since TEESimulator started " +
        (autoCount === 1 ? "is" : "are") + " also in scope."
      : "Auto-include on — no new apps in scope yet." }));
  }

  return el("div", { class: "scope-field" }, kids);
}
