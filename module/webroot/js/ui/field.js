// Render exactly one field from a descriptor. A descriptor.type -> widget switch,
// and nothing else. Stateless, no I/O, no imports beyond the DOM helpers.
//
// renderField(descriptor, value, onChange, context) -> HTMLElement
//   value    the current value, already read at descriptor.path by the caller
//   onChange (path, value) => ...  for scalar widgets (text/select/patch/keybox)
//   context  { id, keyboxFiles, addApp(pkg), removeApp(pkg) }
//            - id           stable element id, so a re-render can restore focus
//            - keyboxFiles  choices for the 'keybox' widget
//            - addApp/removeApp  the applist widget's structural callbacks
//
// A new descriptor of an EXISTING type needs no edit here. A new type is one new
// case below.

import { el } from "./dom.js";

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
  const focusable = control.matches("input, select, textarea")
    ? control
    : control.querySelector("input, select, textarea");
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
