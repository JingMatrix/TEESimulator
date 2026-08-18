// Composition root + in-memory panel router.
//
// It instantiates the five controllers into their mount elements and shows exactly
// one at a time. Switching destinations mutates a single in-memory variable and
// toggles [hidden] on the mounts — it writes NO location.hash and pushes NO history
// entry. That is the whole Back-gesture fix: with no per-panel history to walk,
// Android Back at any resting screen falls through to the OS default and the root
// manager closes the WebUI (a true exit). The only thing that intercepts Back is an
// open overlay, handled entirely in js/ui/nav.js. See that file for the model.
//
// Adding a destination is: a mount <section> + a <button data-nav> in index.html
// and one entry in NAV below. This file never names window.ksu, never builds a
// shell command, and (being the composition root, not a view) is allowed to wire
// controllers; it holds no data logic of its own.

import { create as createConfig } from "./controllers/config-controller.js";
import { create as createKeyboxes } from "./controllers/keybox-controller.js";
import { create as createKeys } from "./controllers/keyadmin-controller.js";
import { create as createSystem } from "./controllers/system-controller.js";
import { create as createLogs } from "./controllers/logs-controller.js";
import { translateDOM, t } from "./i18n.js";

// --- global diagnostics (inspect via Chrome DevTools, chrome://inspect) ---
// Surface every uncaught error and rejected promise, so a failure anywhere in the WebUI
// shows up in the console instead of vanishing silently in the WebView.
console.log("[app] boot ua=%o href=%o", navigator.userAgent, location.href);
window.addEventListener("error", (e) => {
  console.error("[app] uncaught error: %o at %s:%d:%d", e.message, e.filename, e.lineno, e.colno, e.error);
});
window.addEventListener("unhandledrejection", (e) => {
  console.error("[app] unhandled promise rejection:", e.reason);
});

// The top-bar health pill and the System nav badge are chrome this root owns; the
// System controller reports into them through these two setters, so no other module
// reaches across destinations to poke shared chrome.
const healthEl = document.getElementById("health");
const badgeEl = document.getElementById("update-badge");

function setHealth(status) {
  const dot = healthEl.querySelector(".dot");
  const label = healthEl.querySelector(".healthpill-label");
  const ok = !!(status && status.reachable);
  dot.classList.toggle("ok", ok);
  dot.classList.toggle("off", !ok);
  label.removeAttribute("data-i18n");
  label.textContent = ok ? t("sys_running") : t("sys_stopped");
}

function setBadge(on) {
  badgeEl.hidden = !on;
}

const NAV = {
  config: { mount: "tab-config", make: (m) => createConfig(m) },
  keyboxes: { mount: "tab-keyboxes", make: (m) => createKeyboxes(m) },
  keys: { mount: "tab-keys", make: (m) => createKeys(m) },
  system: { mount: "tab-system", make: (m) => createSystem(m, { onHealth: setHealth, onBadge: setBadge }) },
  logs: { mount: "tab-logs", make: (m) => createLogs(m) },
};

// Instantiate each controller once, bound to its mount element.
const controllers = {};
for (const [name, def] of Object.entries(NAV)) {
  controllers[name] = def.make(document.getElementById(def.mount));
}

let current = null;

// The whole router: toggle which mount is visible, mark the nav item, and (re)load
// that controller. No hash, no history — switching is pure in-memory state.
function show(name) {
  if (!NAV[name]) name = "config";
  current = name;
  for (const [tab, def] of Object.entries(NAV)) {
    const active = tab === name;
    document.getElementById(def.mount).hidden = !active;
    const btn = document.querySelector(`.navitem[data-nav="${tab}"]`);
    if (btn) {
      btn.classList.toggle("active", active);
      if (active) btn.setAttribute("aria-current", "page");
      else btn.removeAttribute("aria-current");
    }
  }
  controllers[name].load();
}

for (const btn of document.querySelectorAll(".navitem")) {
  btn.addEventListener("click", () => show(btn.dataset.nav));
}

// A view can request a jump to another destination via a DOM event, so no view reaches
// into this router directly. Used by the profile editor's "empty means harvested — see
// Harvest" link to open the System screen.
document.addEventListener("teesim:navigate", (e) => {
  const panel = e.detail && e.detail.panel;
  if (panel && NAV[panel]) show(panel);
});

// Boot: seed the header pill and the System badge once, without switching to the
// System screen. The probe degrades silently if the daemon is down (no pill error,
// no badge) — same graceful degradation the Keys/System panels already use.
controllers.system.boot();

// Default destination.
translateDOM();
show("config");
