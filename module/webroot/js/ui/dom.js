// Framework-free DOM helpers — the leaf of the UI layer. No app logic and no I/O.
// Its ONE import is ./nav.js (the Back-gesture guard), so every overlay this file
// opens — dialogs, sheets, drill-in panels — dismisses on Android Back the same
// way it dismisses on a Cancel tap. It still imports nothing from data/ or bridge/.
//
// Everything that builds an element goes through el() so no view ever concatenates
// HTML strings (which also keeps user text out of any innerHTML path).

import { pushOverlay, closeOverlay } from "./nav.js";

// el("div", {class:"card", onclick:fn}, [childNode, "text", ...])
// attrs: className via `class`; DOM event handlers as on<Event> functions;
// dataset via data-*; everything else set as an attribute. Falsy children skip.
export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v; // always textContent — user text never touches innerHTML
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "value") node.value = v;
    else if (k === "checked" || k === "disabled" || k === "selected") node[k] = !!v;
    else node.setAttribute(k, v);
  }
  const kids = Array.isArray(children) ? children : [children];
  for (const c of kids) {
    if (c == null || c === false) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}

// Remove every child of a node.
export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

// An inline SVG icon built the same crisp, theme-adaptive way as the bottom-nav icons: a 24x24
// stroke icon that inherits `currentColor`, so it tints with the surrounding text in either theme.
// `paths` is an array of <path>/<circle>/<line> descriptors { d } or { cx, cy, r } etc.; SVG needs
// the SVG namespace, which document.createElement (used by el()) does not set — hence createElementNS.
const SVG_NS = "http://www.w3.org/2000/svg";
export function svgIcon(shapes, { size = 20, cls = "" } = {}) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  if (cls) svg.setAttribute("class", cls);
  for (const s of shapes) {
    const tag = s.d ? "path" : s.tag || "path";
    const n = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(s)) if (k !== "tag") n.setAttribute(k, v);
    svg.appendChild(n);
  }
  return svg;
}

// The two glyphs the Scope search bar needs, as reusable shape sets: a magnifying glass and a
// descending-bars "sort" mark. Kept here next to svgIcon so any view can reuse them.
export const ICON_SEARCH = [{ tag: "circle", cx: 11, cy: 11, r: 7 }, { d: "M20 20l-3.6-3.6" }];
export const ICON_SORT = [{ d: "M4 6h16" }, { d: "M6 12h12" }, { d: "M9 18h6" }];

// Transient toast. Owns the #toast host declared in index.html.
export function toast(msg) {
  const t = document.getElementById("toast");
  if (!t) return;
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.remove("show"), 1900);
}

// The shared overlay primitive behind every dialog, sheet, and drill-in. It puts
// `content` inside a panel, dims the page, registers with the Back guard, and hands
// back a { close } that a caller can invoke to dismiss it programmatically.
//
//   content   the node to show inside the panel
//   variant   "modal" (centered card) | "sheet" (bottom sheet) | "panel" (full drill-in)
//   onClose   run once, when the overlay actually closes (Back, backdrop, or close())
//   label     accessible name for the dialog
//   dismissBackdrop  whether a backdrop tap closes it (default true; false for panels)
//
// The returned close() routes through the Back guard so the synthetic history entry
// is unwound; the guard's popstate is the single thing that runs `onClose`, so a
// hardware Back and a programmatic close share one path and cannot double-fire.
export function openOverlay(content, opts = {}) {
  const { variant = "modal", onClose, label, dismissBackdrop = variant !== "panel" } = opts;
  let settled = false;
  const close = () => {
    if (settled) return; // popstate is the sole caller, but stay idempotent.
    settled = true;
    overlay.remove();
    if (onClose) onClose();
  };
  const onBackdrop = dismissBackdrop ? (e) => { if (e.target === overlay) closeOverlay(); } : null;
  // The inner chrome differs per variant: a centered card, a bottom sheet, or a
  // full-screen drill-in. Distinct class names so none collide with the outer one.
  const innerClass = { modal: "modal", sheet: "sheet", panel: "drill" }[variant] || "modal";
  const overlay = el("div", {
    class: "overlay overlay-" + variant,
    onclick: onBackdrop,
  }, [
    el("div", {
      class: innerClass, role: "dialog", "aria-modal": "true",
      "aria-label": label || null,
    }, [content]),
  ]);
  document.body.appendChild(overlay);
  pushOverlay(close);
  return { close: () => closeOverlay() };
}

// A bottom sheet: openOverlay with the sheet chrome. Same { close } contract.
export function openSheet(content, opts = {}) {
  return openOverlay(content, { ...opts, variant: "sheet" });
}

// A progressive-disclosure section — a header button that expands/collapses a body.
// The open/closed state lives in the caller (so it survives the caller's stateless
// re-renders): pass the current `open`, and `onToggle` flips it and re-renders.
// `id` gives the header a stable handle so a re-render can restore focus to it.
//   summary  a string, node, or array of nodes for the header
export function disclosure(summary, body, { open = false, onToggle, id } = {}) {
  const head = el("button", {
    id: id || null, type: "button",
    class: "disclosure-head" + (open ? " open" : ""),
    "aria-expanded": open ? "true" : "false",
    onclick: () => onToggle && onToggle(),
  }, [
    el("span", { class: "disclosure-summary" }, summary),
    el("span", { class: "disclosure-chevron", "aria-hidden": "true" }),
  ]);
  return el("div", { class: "disclosure" }, [
    head,
    open ? el("div", { class: "disclosure-body" }, body) : null,
  ]);
}

// In-page confirm modal (no native confirm(), which some webviews suppress). It is
// an overlay, so Back and a backdrop tap both resolve it as Cancel. The chosen
// outcome is stashed, then the overlay is unwound through the Back guard, and the
// guard's close callback resolves the promise with that outcome — one path for
// every way to leave. Resolves true on confirm, false otherwise.
export function confirmDialog(msg, opts = {}) {
  const { confirmLabel = "Confirm", cancelLabel = "Cancel", danger = true } = opts;
  return new Promise((resolve) => {
    let outcome = false;
    const content = el("div", {}, [
      el("p", { class: "modal-msg", text: msg }),
      el("div", { class: "modal-actions" }, [
        el("button", { class: "btn ghost", text: cancelLabel, onclick: () => { outcome = false; handle.close(); } }),
        el("button", { class: "btn " + (danger ? "danger" : "primary"), text: confirmLabel, onclick: () => { outcome = true; handle.close(); } }),
      ]),
    ]);
    const handle = openOverlay(content, { variant: "modal", label: "Confirm", onClose: () => resolve(outcome) });
  });
}

// In-page prompt modal (no native prompt(), which the root-manager webview may not
// implement). Same overlay/Back semantics as confirmDialog. Resolves the entered
// string on OK/Enter, or null on Cancel / backdrop / Back.
export function promptDialog(msg, initialValue = "", opts = {}) {
  const { okLabel = "OK", placeholder = "" } = opts;
  return new Promise((resolve) => {
    let outcome = null;
    const input = el("input", {
      class: "input", type: "text", value: initialValue, placeholder,
      autocapitalize: "off", autocorrect: "off", spellcheck: "false",
    });
    const submit = () => { outcome = input.value; handle.close(); };
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); submit(); } });
    const content = el("div", {}, [
      el("p", { class: "modal-msg", text: msg }),
      input,
      el("div", { class: "modal-actions" }, [
        el("button", { class: "btn ghost", text: "Cancel", onclick: () => { outcome = null; handle.close(); } }),
        el("button", { class: "btn primary", text: okLabel, onclick: submit }),
      ]),
    ]);
    const handle = openOverlay(content, { variant: "modal", label: msg, onClose: () => resolve(outcome) });
    setTimeout(() => input.focus(), 0);
  });
}
