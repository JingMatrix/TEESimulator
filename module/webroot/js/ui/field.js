// Render exactly one field from a descriptor. A descriptor.type -> widget switch,
// and nothing else. Stateless, no I/O, no imports beyond the DOM helpers.
//
// renderField(descriptor, value, onChange, context) -> HTMLElement
//   value    the current value, already read at descriptor.path by the caller
//   onChange (path, value) => ...  for scalar widgets (text/select/patch/keybox)
//   context  { id, tag, placeholder, keyboxFiles, addApp(entry), removeApp(entry), openScope(),
//              labelMap, installedSet, autoInclude, takenBy }
//            - id           stable element id, so a re-render can restore focus
//            - tag          { text, kind, title } drawn beside the label: where the value comes
//                           from when the field is left empty ("keybox" / "harvested" / "omitted")
//            - placeholder  that default's value, greyed inside the box
//            - defaultValue that default's value for a widget that states it itself (the patch
//                           picker names it on its "default" option and seeds "custom…" with it)
//            - keyboxFiles  choices for the 'keybox' widget
//            - addApp/removeApp  the applist/scope widget's structural callbacks
//            - openScope    the scope widget's "Configure scope" jump (opens the picker)
//            - labelMap     optional Map(package -> human label) so a scope chip can show
//                           the app's real name, not just its package
//            - installedSet optional Set of installed package names, so a scope chip can
//                           flag a package that is not currently installed on the device
//            - autoInclude  whether this profile has auto-include on (scope face empty state)
//            - autoCount    how many apps the daemon currently auto-includes for it (0 when
//                           /scope is unavailable), so the face can count what apps[] cannot
//            - takenBy      for an `exclusive` toggle: the OTHER profile that already owns this
//                           claim (or null); when set, the switch renders disabled with a
//                           "used by <name>" note, since only one profile may hold it
//
// A new descriptor of an EXISTING type needs no edit here. A new type is one new
// case below.

import { el } from "./dom.js";
import { UID_RE, splitEntry } from "../domain/schema.js";

export function renderField(descriptor, value, onChange, context = {}) {
  switch (descriptor.type) {
    case "segment":
      return segmentField(descriptor, value, onChange, context);
    case "select":
      return labelled(descriptor, selectWidget(descriptor, value, onChange, context), context);
    case "keybox":
      return labelled(descriptor, keyboxWidget(descriptor, value, onChange, context), context);
    case "patch":
      return labelled(descriptor, patchWidget(descriptor, value, onChange, context), context);
    case "applist":
      return labelled(descriptor, applistWidget(descriptor, value, context), context);
    case "scope":
      return labelled(descriptor, scopeWidget(descriptor, value, context), context);
    case "toggle":
      return toggleField(descriptor, value, onChange, context);
    case "text":
    default:
      return labelled(descriptor, textWidget(descriptor, value, onChange, context), context);
  }
}

// Shared wrapper: <div.field> with a label row, the control, and optional help text.
// The caller (config-view) appends any inline error after this element.
//
// The label row carries the field's label and, when the caller passes one, a small tag on the
// right naming where the value comes from if the field is left empty ("keybox", "harvested",
// "omitted"). That tag replaces a whole line of prose per field, which is what keeps a screen of
// eleven identity fields readable.
//
// The <label for> must reference a real focusable control, not a wrapper <div>.
// For the simple widgets the control IS the input/select; for the patch and applist
// widgets it's a wrapper whose focusable input lives inside — so target that input's
// id rather than the id-less wrapper, otherwise those fields have no programmatic
// label.
function labelled(descriptor, control, ctx = {}) {
  // Prefer a real form control; but a compound widget (the scope face) has none — its only
  // id-bearing focusable is the "Configure scope" <button id=ctx.id>, so fall back to the first
  // element carrying an id, restoring the label→control association rather than emitting for=null.
  const focusable = control.matches("input, select, textarea")
    ? control
    : control.querySelector("input, select, textarea") || control.querySelector("[id]");
  return el("div", { class: "field" }, [
    fieldHead(descriptor, (focusable && focusable.id) || null, ctx),
    control,
    descriptor.help ? el("div", { class: "field-help", text: descriptor.help }) : null,
  ]);
}

// The label row: the label, plus ctx.tag = { text, kind, title } when the caller has a source to
// name. kind is "" (harvested), "keybox" or "warn", which is the only colour difference.
function fieldHead(descriptor, forId, ctx) {
  const tag = ctx.tag || null;
  if (descriptor.labelHidden && !tag) return null;
  return el("div", { class: "field-head" }, [
    el("label", { class: "field-label", for: forId, text: descriptor.label }),
    tag ? el("span", {
      class: "field-tag" + (tag.kind ? " " + tag.kind : ""),
      text: tag.text, title: tag.title || null,
    }) : null,
  ]);
}

function textWidget(d, value, onChange, ctx) {
  const input = el("input", {
    id: ctx.id, type: "text", value: value == null ? "" : value,
    // A keybox-stated default is tinted in the box exactly as it is in the tag beside the label:
    // the one cue that this field, left empty, attests something other than what this device is.
    class: "input" + (ctx.tag && ctx.tag.kind === "keybox" ? " ph-keybox" : ""),
    // The default this field takes when left empty, greyed inside the box: the value is shown
    // where it will apply, instead of a line of prose under every field. Only a short default
    // comes through here — config-view puts a long one (a 64-char hash) on its own line.
    placeholder: ctx.placeholder || "",
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
  // A patch level is one of a handful of tokens, or a date typed by hand. Six of those laid out
  // as chips crowd the row and wrap; one picker holds them in a single line, names what "default"
  // resolves to inside the option itself, and reads like the keybox picker above it.
  // "custom…" is the escape hatch: picking it seeds the box with the value the field was already
  // taking, so there is something to edit rather than an empty field.
  const v = value == null ? "" : String(value);
  const picks = (d.picks || ["system_property", "today", "no"]).map(resolvePick);
  const onPick = picks.some((p) => p.value === v);
  const custom = v !== "" && !onPick;

  const options = [
    { value: "", label: ctx.defaultValue ? "default — " + ctx.defaultValue : "default" },
    ...picks,
    { value: CUSTOM, label: "custom…" },
  ];
  const select = el("select", {
    // The picker keeps ctx.id in both states. Handing it to the box instead would make the
    // caller's focus restore move focus there the moment "custom…" is chosen, and the keyboard
    // that comes up covers the field it belongs to.
    id: ctx.id, class: "input",
    onchange: (e) => {
      // "custom…" is not a value: it writes the seed, and the box that then appears is left
      // unfocused, since a keyboard here would cover the field it belongs to.
      const next = e.target.value === CUSTOM ? customSeed(d, picks, ctx) : e.target.value;
      if (next === v) return;
      onChange(d.path, next);
    },
  }, options.map((o) => el("option", {
    value: o.value, selected: o.value === CUSTOM ? custom : o.value === v, text: o.label,
  })));

  const box = custom ? textWidget(d, v, onChange, { ...ctx, id: ctx.id + "-v" }) : null;
  return el("div", { class: "patch" }, [picker(select), box]);
}

// The picker entry that stands for "a value no option covers". It is not a config value: choosing
// it writes customSeed()'s date, never this string.
const CUSTOM = "\u0000custom";

// A quick-pick token -> { label, value }. "@month05" inserts the template "YYYY-MM-05"
// (a common vendor/boot patch date); the daemon resolves YYYY/MM to today, so it tracks
// the calendar rather than freezing to the month it was picked. Early in a month, before
// the 5th, it resolves to the previous month instead -- never to a day still ahead.
function resolvePick(token) {
  if (token === "@month05") return { label: "YYYY-MM-05", value: "YYYY-MM-05" };
  return { label: token, value: token };
}

// What "custom…" opens the box on: the default the field was taking (a harvested date or OS
// version — never an option's own token, or the field would still read as resting on that one),
// else the descriptor's template, which the daemon resolves against today's calendar.
function customSeed(d, picks, ctx) {
  const seed = ctx.defaultValue || "";
  const isToken = picks.some((p) => p.value === seed);
  if (seed && !isToken && (!d.re || d.re.test(seed))) return seed;
  return d.seed || "";
}

function selectWidget(d, value, onChange, ctx) {
  return picker(el("select", {
    id: ctx.id, class: "input",
    onchange: (e) => onChange(d.path, e.target.value),
  }, (d.options || []).map((opt) =>
    el("option", { value: opt, selected: opt === value, text: opt }))));
}

// A <select> reads as a text box once appearance:none strips the native arrow back off it.
// Wrap it with one, so a picker looks like a picker.
function picker(select) {
  return el("div", { class: "select-wrap" }, [select, el("span", { class: "select-caret", "aria-hidden": "true" })]);
}

// A radio group drawn as one segmented control: every choice visible, one tap to switch, and
// only the chosen one's meaning spelled out underneath.
function segmentField(d, value, onChange, ctx) {
  const opts = d.options || [];
  const labels = d.optionLabels || {};
  const seg = el("div", { class: "segmented segmented-block", role: "radiogroup", "aria-label": d.label },
    opts.map((opt, i) => el("button", {
      id: i === 0 ? ctx.id : null, type: "button",
      class: "seg" + (opt === value ? " on" : ""),
      role: "radio", "aria-checked": opt === value ? "true" : "false",
      text: labels[opt] || opt,
      onclick: () => { if (opt !== value) onChange(d.path, opt); },
    })));
  const help = (d.optionHelp && d.optionHelp[value]) || d.help || null;
  return el("div", { class: "field" }, [
    fieldHead(d, ctx.id, ctx),
    seg,
    help ? el("div", { class: "field-help", text: help }) : null,
  ]);
}

function keyboxWidget(d, value, onChange, ctx) {
  // Union of the discovered files and the current value, so a config that names
  // a keybox we can't see right now still shows (flagged) rather than vanishing.
  const files = (ctx.keyboxFiles || []).slice();
  if (value && !files.includes(value)) files.push(value);
  if (files.length === 0) {
    return picker(el("select", { id: ctx.id, class: "input", disabled: true },
      [el("option", { text: "no keybox files found" })]));
  }
  return picker(el("select", {
    id: ctx.id, class: "input",
    onchange: (e) => onChange(d.path, e.target.value),
  }, files.map((f) =>
    el("option", { value: f, selected: f === value, text: f + ((ctx.keyboxFiles || []).includes(f) ? "" : " (missing)") }))));
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
// An `exclusive` toggle is a whole-device claim, so at most one profile may own it: when another
// profile already does, ctx.takenBy names it and the switch renders disabled with a short
// "used by <name>" note, so the conflict is legible before Save rejects it.
// A compact settings ROW (not the three-line label/control/help stack): the title and its help sit
// stacked on the left as a <label for> that also toggles, and the switch sits inline on the right.
// The help doubles as the "used by <profile>" note when auto-include is locked to another profile.
function toggleField(d, value, onChange, ctx) {
  const checked = value === true;
  const locked = !!d.exclusive && !!ctx.takenBy && !checked;
  const input = el("input", {
    id: ctx.id, class: "switch-input", type: "checkbox", checked, disabled: locked,
    role: "switch", "aria-checked": checked ? "true" : "false",
    onchange: locked ? null : (e) => onChange(d.path, e.target.checked),
  });
  const sw = el("span", { class: "switch" + (checked ? " on" : "") + (locked ? " disabled" : "") }, [
    input,
    el("span", { class: "switch-track", "aria-hidden": "true" }, [el("span", { class: "switch-thumb" })]),
  ]);
  const sub = locked ? "Used by profile “" + ctx.takenBy + "”" : d.help;
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
      // Two users' copies of one app share a label, so the user rides along on the chip — without
      // it a work-profile pick and the primary user's are the same word twice.
      const userId = isUid ? 0 : splitEntry(entry).userId;
      return el("span", {
        class: "chip scope-chip" + (isUid ? " advanced" : "") + (missing ? " warn" : ""),
        title: isUid ? "Advanced: targets caller uid " + entry.slice(4)
          : missing ? entry + " is not installed (a name-match applies if it installs later)" : entry,
      }, [
        (isUid || missing) ? el("span", { class: "scope-chip-dot", "aria-hidden": "true" }) : null,
        el("span", { class: "chip-text" + (isUid ? " mono" : ""), text: label }),
        userId ? el("span", { class: "chip-sub", text: "user " + userId }) : null,
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
