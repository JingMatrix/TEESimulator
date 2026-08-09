// Owns the System screen: the read-only daemon/harvest status poll AND the canary
// updater. Nothing here reaches the shell except through the daemon seam
// (data/status.js and data/keyadmin.js). It degrades gracefully — an unreachable
// daemon yields a well-formed "unreachable" health snapshot and simply no update
// badge, never a thrown error.
//
// create(mount, { onHealth, onBadge })
//   onHealth(status)  report the latest health snapshot up to the top-bar pill
//   onBadge(bool)     report whether a canary update is available, for the nav dot
// Exposes { load, boot }: load() is called when the screen is shown; boot() runs
// the one-shot probes at startup so the pill and badge are seeded before the user
// ever opens this screen.

import { getStatus } from "../data/status.js";
import { keyAdmin } from "../data/keyadmin.js";
import { renderSystem, refreshHealth as patchHealthCards } from "../ui/system-view.js";
import { toast, confirmDialog } from "../ui/dom.js";

const POLL_MS = 5000;

export function create(mount, opts = {}) {
  const onHealth = opts.onHealth || (() => {});
  const onBadge = opts.onBadge || (() => {});

  let status = null;
  let update = null;      // canary probe result, or null when unreachable/unprobed
  let probed = false;     // has the canary probe resolved at least once?
  let canarySig = null;   // serialized `update` at last paint, to skip no-op re-renders
  let variant = "release";
  let installing = false;
  let installError = null;
  let notesOpen = false;

  let timer = null;
  let inFlight = false;

  // What the Update card is a function of: the probe result AND whether it has
  // resolved yet (probed flips its "Checking…" vs "unavailable" copy). The periodic
  // health poll must not rebuild that card, so probeCanary re-renders only when this
  // signature changes.
  const canarySignature = () => JSON.stringify({ probed, update });

  function render() {
    renderSystem(mount, { status, update, probed, variant, installing, installError, notesOpen }, actions);
    canarySig = canarySignature();
  }

  // Health snapshot: never throws (getStatus returns an "unreachable" object), so
  // the pill always gets a truthful state. Patches ONLY the health + harvest cards so
  // the periodic 5 s poll never tears down the interactive Update card; if the screen
  // hasn't been fully painted yet (probed on boot), fall back to a full render.
  async function refreshHealth() {
    if (inFlight) return; // don't stack probes if one is slow
    inFlight = true;
    try {
      status = await getStatus();
      onHealth(status);
    } finally {
      inFlight = false;
    }
    if (!patchHealthCards(mount, status)) render();
  }

  // Canary probe: sets the update state and the nav badge. A daemon that is down or
  // has no canary endpoint yet leaves update=null and clears the badge — silent.
  // Re-renders only when the probe result actually changed, so a repeat probe that
  // returns the same thing doesn't rebuild the Update card.
  async function probeCanary() {
    let next = null;
    try {
      const res = await keyAdmin("canary");
      next = res && res.ok !== false ? res : null;
    } catch {
      next = null;
    }
    update = next;
    probed = true;
    onBadge(!!(update && update.updateAvailable));
    if (canarySignature() !== canarySig) render();
  }

  const actions = {
    onSelectVariant(v) {
      if (v === variant) return;
      variant = v;
      render();
    },

    onToggleNotes() {
      notesOpen = !notesOpen;
      render();
    },

    async onInstall() {
      const latest = update && update.latest;
      if (!latest || !update.updateAvailable || installing) return;
      const label = "canary-" + (latest.code || "?") + " (" + variant + ")";
      if (!(await confirmDialog(`Install ${label}? This downloads and flashes the module over the current install.`, { confirmLabel: "Install", danger: false }))) return;

      installing = true;
      installError = null;
      render();
      try {
        const res = await keyAdmin("canaryInstall", { tag: latest.tag, variant });
        if (res && res.ok === false) {
          installError = res.message || "The daemon rejected the install.";
          toast("Install failed");
        } else {
          toast((res && res.message) || "Update flashed — reboot to apply.");
        }
      } catch (e) {
        installError = e && e.message ? e.message : String(e);
        toast("Install failed: " + installError);
      } finally {
        installing = false;
        render();
      }
    },
  };

  // Poll health only while the screen is on-screen and the app is foreground, so a
  // hidden panel costs nothing. Canary is not polled — it's checked on boot/load.
  function visible() {
    return mount.offsetParent !== null && document.visibilityState === "visible";
  }
  function startPolling() {
    if (timer) return;
    timer = setInterval(() => { if (visible()) refreshHealth(); }, POLL_MS);
  }

  return {
    // One-shot probes at app startup: seed the pill and the badge without showing
    // this screen. Fire-and-forget; both degrade silently.
    boot() {
      refreshHealth();
      probeCanary();
    },

    load() {
      render();            // paint the last snapshot instantly
      startPolling();
      refreshHealth();
      probeCanary();
    },
  };
}
