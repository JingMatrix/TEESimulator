// The System screen: daemon health, harvest summary, and the canary updater — the
// three "is the system healthy and current?" concerns on one read-mostly screen.
// Pure presentation: it renders from the state the controller hands it and emits
// every intent through `actions`. It never imports data/* or bridge/*; the update
// probe/install all happen in the controller through the daemon seam.
//
// renderSystem(mount, state, actions)
//   state = {
//     status,       // { daemonRunning, reachable, hookActive, hook, api, harvest, error? } | null
//     update,       // { installedVersion, currentCode, latest:{code,tag,name,notes,htmlUrl,commit,assets}|null, updateAvailable } | null
//     probed,       // true once the canary probe has resolved (else "checking")
//     variant,      // "release" | "debug" — the selected asset to flash
//     installing,   // true while a flash is in flight (Install disabled + progress)
//     installError, // string | null — surfaced as a .banner.error
//     notesOpen,    // "What's new" disclosure state
//   }
//   actions = { onInstall(), onSelectVariant(v), onToggleNotes() }

import { el, clear, disclosure } from "./dom.js";
import { renderMarkdown } from "./markdown.js";

export function renderSystem(mount, state, actions) {
  clear(mount);
  const { status = null, update = null, probed = false,
          variant = "release", installing = false, installError = null, notesOpen = false } = state;

  mount.appendChild(el("div", { class: "panel-head" }, [el("h1", { class: "panel-title", text: "System" })]));

  mount.appendChild(tag(healthCard(status), "health"));
  mount.appendChild(tag(harvestCard(status), "harvest"));
  mount.appendChild(tag(updateCard({ update, probed, variant, installing, installError, notesOpen }, actions), "update"));
}

// Patch ONLY the health + harvest cards from a fresh status snapshot, leaving the
// interactive Update card (and any open disclosure / variant choice / focus) exactly
// as it is. The 5 s health poll calls this instead of renderSystem so it never tears
// down the updater. Returns false when the screen hasn't been fully rendered yet
// (e.g. probed on boot before it's shown), so the caller can fall back to a full render.
export function refreshHealth(mount, status) {
  const oldHealth = mount.querySelector('[data-card="health"]');
  const oldHarvest = mount.querySelector('[data-card="harvest"]');
  if (!oldHealth || !oldHarvest) return false;
  oldHealth.replaceWith(tag(healthCard(status), "health"));
  oldHarvest.replaceWith(tag(harvestCard(status), "harvest"));
  return true;
}

// Stamp a card's slot marker so the health-only patch path can find and swap it.
function tag(card, name) {
  card.setAttribute("data-card", name);
  return card;
}

// --- daemon health -------------------------------------------------------
function healthCard(status) {
  if (!status) {
    return el("div", { class: "card" }, [el("h2", { text: "Daemon health" }), el("p", { class: "muted", text: "Reading status…" })]);
  }
  const dot = (cls) => el("span", { class: "dot " + cls });
  // Interceptor: attached is ok; the daemon up but nothing attached yet is a
  // degraded (amber) state, not a hard failure.
  const interceptorDot = status.hookActive ? "ok" : (status.daemonRunning ? "warn" : "off");
  const interceptorText = status.hookActive ? "active" : (status.daemonRunning ? "not attached" : "inactive");

  const card = el("div", { class: "card" }, [
    el("h2", { text: "Daemon health" }),
    row("Daemon", el("span", { class: "status" }, [dot(status.daemonRunning ? "ok" : "off"), status.daemonRunning ? "running" : "stopped"])),
    row("Interceptor", el("span", { class: "status" }, [dot(interceptorDot), interceptorText])),
    row("Hook", el("span", { class: "chips" }, [
      el("span", { class: "chip", text: status.hook || "unknown" }),
      status.api ? el("span", { class: "chip", text: "API " + status.api }) : null,
    ])),
  ]);
  if (status.reachable === false) {
    card.appendChild(el("div", { class: "banner" }, [
      el("div", { text: "Daemon status endpoint unreachable." }),
      el("div", { class: "muted small", text: status.error || "The daemon isn't responding on 127.0.0.1:8790 yet." }),
    ]));
  }
  return card;
}

// --- harvest summary -----------------------------------------------------
// A deliberately complete, honest dump of the device state the daemon harvested before
// any simulation, split into two groups. "Captured" is the RAW values read from the real
// TEE key generation (verified-boot key/hash shown even when all-zero, lock/boot state,
// patch and OS levels, security levels, versions). "Fabricated" is the values we override
// or synthesize for attestation — usually deviceLocked and verifiedBootState, since an
// unlocked / unverified device fails attestation. A debugging view: it shows what the real
// TEE reported and exactly what the simulation changes on top of it.
// The harvest level the user last selected, kept across the 5 s status poll's re-render so a click
// on StrongBox doesn't snap back to TrustedEnvironment a few seconds later.
let harvestMode = "tee";

function harvestCard(status) {
  const h = status && status.harvest;
  const card = el("div", { class: "card" }, [el("h2", { text: "Harvest" })]);
  if (!status) { card.appendChild(el("p", { class: "muted", text: "—" })); return card; }
  if (!h) { card.appendChild(el("p", { class: "muted", text: "No harvest record yet." })); return card; }

  const failed = h.failed || h.harvestFailed;
  // fabricated is a map of JSON field name -> the display value we override it to. The
  // record's own fields hold the RAW captured values, so the two groups stay honest.
  const fab = (h.fabricated && typeof h.fabricated === "object" && !Array.isArray(h.fabricated)) ? h.fabricated : {};
  const fabKeys = Object.keys(fab);
  const sbAvailable = !!h.strongBoxAvailable;
  // The two hardware levels a spoofed key can present. We ASK for TrustedEnvironment (the default), and
  // always offer StrongBox too; there is no Software chip because we never present Software — a device
  // with no real TEE has its captured Software level fabricated up to TrustedEnvironment (shown struck
  // in Captured, corrected in Fabricated). Selecting a chip switches the level-specific rows below.
  const modes = [
    { key: "tee", label: "TrustedEnvironment" },
    { key: "strongbox", label: "StrongBox" },
  ];
  if (failed || !modes.some((m) => m.key === harvestMode)) harvestMode = "tee";
  const chipEls = modes.map((m) =>
    el("button", { class: "chip clickable", type: "button", onclick: () => select(m.key) }, [
      el("span", { class: "dot ok" }),
      el("span", { text: m.label }),
    ]),
  );
  if (!failed) card.appendChild(el("div", { class: "harvest-modes" }, chipEls));

  const body = el("div", { class: "harvest-body" });
  card.appendChild(body);

  function select(m) {
    harvestMode = m;
    modes.forEach((mode, i) => chipEls[i].classList.toggle("selected", mode.key === m));
    renderBody();
  }

  function renderBody() {
    body.replaceChildren();
    const sb = harvestMode === "strongbox";
    if (failed) {
      body.appendChild(el("div", { class: "muted small", text: "No key was attestable (common on certain models after unlocking the bootloader), so every value below is synthesized rather than captured from a real TEE." }));
    } else if (sb && !sbAvailable) {
      body.appendChild(el("div", { class: "muted small", text: "StrongBox has no working hardware on this device; keys requested at StrongBox are generated (not patched) at the TEE version." }));
    }

    // Captured: the real values read from the device, shown honestly — only when actually captured (no
    // placeholders), and nothing at all when the harvest failed (everything is then fabricated below).
    // A value we override for attestation (present in `fab`) is shown struck, to signal it is replaced.
    if (!failed) {
      body.appendChild(el("h3", { text: "Captured" }));
      const rows = el("div", { class: "kv-list" });
      const add = (label, val) => {
        if (val != null && val !== "" && val !== "—")
          rows.appendChild(kvRow(label, val, fab[label] !== undefined));
      };

      add("verifiedBootState", h.verifiedBootState == null ? null : named(h.verifiedBootState) + " (" + h.verifiedBootState + ")");
      add("deviceLocked", h.deviceLocked == null ? null : String(h.deviceLocked));
      if (h.verifiedBootKey) hexRow(rows, "verifiedBootKey", h.verifiedBootKey, fab["verifiedBootKey"] !== undefined);
      if (h.verifiedBootHash) hexRow(rows, "verifiedBootHash", h.verifiedBootHash, fab["verifiedBootHash"] !== undefined);
      add("osVersion", show(h.osVersion));
      add("osPatchLevel", show(h.osPatchLevel));
      add("vendorPatchLevel", show(h.vendorPatchLevel));
      add("bootPatchLevel", show(h.bootPatchLevel));
      // The device has one real captured level. StrongBox reads level 2 only when it actually works;
      // otherwise it falls back to the captured level (Software on a device with no secure element), so
      // both chips honestly show that same captured value.
      const sbReal = sb && sbAvailable;
      add("attestationSecurityLevel", secLevel(sbReal ? 2 : h.attestationSecurityLevel));
      add("keymasterSecurityLevel", secLevel(sbReal ? 2 : h.keymasterSecurityLevel));
      add("attestationVersion", show(sbReal ? h.strongBoxAttestationVersion : h.attestationVersion));
      add("keymasterVersion", show(h.keymasterVersion));
      if (h.moduleHash) hexRow(rows, "moduleHash", h.moduleHash, fab["moduleHash"] !== undefined);
      // Device identity captured for ID attestation (only the ids the TEE actually provided).
      for (const key of ["brand", "device", "product", "manufacturer", "model", "serial", "imei", "meid", "imei2"]) {
        if (h[key]) add(key, h[key]);
      }
      if (h.harvestedAt) add("harvestedAt", fmtTime(h.harvestedAt));
      body.appendChild(rows);
    }

    // Fabricated: the values we present to apps in place of the captured ones. The security level is the
    // level of the chip being viewed — we present both TrustedEnvironment and StrongBox; the versions and
    // the device ids are the same for both.
    if (fabKeys.length) {
      body.appendChild(el("h3", { text: "Fabricated" }));
      body.appendChild(el("div", { class: "muted small", text: "Values we present to apps in place of the captured ones." }));
      const fabRows = el("div", { class: "kv-list" });
      const fabLevel = secLevel(sb ? 2 : 1);
      for (const key of fabKeys) {
        const isLevel = key === "attestationSecurityLevel" || key === "keymasterSecurityLevel";
        fabRows.appendChild(kvRow(key, isLevel ? fabLevel : show(fab[key])));
      }
      body.appendChild(fabRows);
    }
  }

  select(harvestMode);
  return card;
}

const show = (v) => (v == null || v === "" ? "—" : String(v));

function secLevel(n) {
  if (n == null) return "—";
  const names = ["Software", "TrustedEnvironment", "StrongBox"];
  return (typeof n === "number" && names[n] ? names[n] : String(n)) + " (" + n + ")";
}

function kvRow(label, val, replaced) {
  return el("div", { class: "kv" + (replaced ? " kv-replaced" : "") }, [
    el("span", { class: "kv-label", text: label }),
    el("span", { class: "kv-val", text: val }),
  ]);
}

// A verified-boot key / hash / module hash: base64 in the record, shown as wrapping hex
// so the raw bytes are visible. An all-zero value is flagged (it is what an unlocked
// device reports, and worth spotting).
function hexRow(rows, label, b64, replaced) {
  const hex = b64 ? b64ToHex(b64) : null;
  const allZero = hex != null && hex.length > 0 && /^0+$/.test(hex);
  const flag = allZero ? el("span", { class: "chip warn small", text: "all zero" }) : null;
  rows.appendChild(el("div", { class: "kv kv-stack" + (replaced ? " kv-replaced" : "") }, [
    el("span", { class: "kv-label" }, [label, flag]),
    el("span", { class: "mono kv-hex", text: hex || "—" }),
  ]));
}

function b64ToHex(b64) {
  try {
    const bin = atob(b64);
    let hex = "";
    for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, "0");
    return hex;
  } catch { return null; }
}

function fmtTime(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return "—";
  try { return new Date(n).toLocaleString(); } catch { return String(ms); }
}

// --- canary updater ------------------------------------------------------
function updateCard(s, actions) {
  const { update, probed, variant, installing, installError, notesOpen } = s;
  const card = el("div", { class: "card" }, [el("h2", { text: "Update" })]);

  // Probe hasn't resolved, or the daemon was unreachable: say so, no controls.
  if (!update) {
    card.appendChild(el("p", { class: "muted", text: probed ? "Update status unavailable — daemon unreachable." : "Checking for updates…" }));
    return card;
  }

  const installed = update.installedVersion || (update.currentCode ? "build " + update.currentCode : "unknown");
  card.appendChild(row("Installed", el("span", { class: "mono small", text: installed })));

  const latest = update.latest;
  if (!latest) {
    card.appendChild(el("p", { class: "muted small", text: "No canary release has been published yet." }));
    return card;
  }

  if (!update.updateAvailable) {
    card.appendChild(el("div", { class: "status" }, [el("span", { class: "dot ok" }), el("span", { text: "On the latest canary." })]));
    return card;
  }

  // An update is available: headline pill, what's-new disclosure, variant + Install.
  card.appendChild(el("div", { class: "update-head" }, [
    el("span", { class: "pill warn", text: "Update available" }),
    el("span", { class: "mono small", text: "canary-" + (latest.code || "?") }),
  ]));
  if (latest.name) card.appendChild(el("div", { class: "small", text: latest.name }));

  card.appendChild(disclosure("What's new", whatsNew(latest), {
    open: notesOpen, onToggle: actions.onToggleNotes, id: "sys-notes",
  }));

  // Variant picker (which asset to flash) + the one primary action on this screen.
  card.appendChild(el("div", { class: "field" }, [
    el("span", { class: "field-label", text: "Build variant" }),
    segmented(variant, ["release", "debug"], actions.onSelectVariant, installing),
  ]));

  card.appendChild(el("div", { class: "update-actions" }, [
    installing
      ? el("span", { class: "status" }, [el("span", { class: "spinner", "aria-hidden": "true" }), el("span", { class: "muted small", text: "Downloading & flashing…" })])
      : el("span", { class: "muted small", text: "Flashes " + variant + " over the current module, then reboot to apply." }),
    el("button", {
      class: "btn primary", text: installing ? "Installing…" : "Install",
      disabled: installing, onclick: () => actions.onInstall(),
    }),
  ]));

  if (installError) {
    card.appendChild(el("div", { class: "banner error" }, [
      el("div", { text: "Install failed" }),
      el("div", { class: "muted small", text: installError }),
    ]));
  }
  return card;
}

const REPO_URL = "https://github.com/JingMatrix/TEESimulator";

function whatsNew(latest) {
  const nodes = [];
  if (latest.tag) nodes.push(el("div", { class: "muted small mono", text: latest.tag }));
  // Links to inspect the build on GitHub: the exact commit and the release page.
  const links = [];
  if (latest.commit) {
    links.push(el("a", { class: "linklike mono small", href: REPO_URL + "/commit/" + latest.commit,
      target: "_blank", rel: "noreferrer", text: "commit " + String(latest.commit).slice(0, 7) }));
  }
  if (latest.htmlUrl) {
    links.push(el("a", { class: "linklike small", href: latest.htmlUrl, target: "_blank", rel: "noreferrer", text: "release page ↗" }));
  }
  if (links.length) nodes.push(el("div", { class: "update-links" }, links));
  if (latest.notes) nodes.push(el("div", { class: "notes small md" }, renderMarkdown(latest.notes)));
  const assets = Array.isArray(latest.assets) ? latest.assets : [];
  if (assets.length) {
    nodes.push(el("div", { class: "muted small", text: "Assets" }));
    nodes.push(el("ul", { class: "asset-list" }, assets.map((a) =>
      el("li", { class: "asset-row" }, [
        el("span", { class: "mono small", text: a.name || "(unnamed)" }),
        el("span", { class: "muted small", text: humanSize(a.size) }),
      ]))));
  }
  if (!nodes.length) nodes.push(el("p", { class: "muted small", text: "No release notes." }));
  return nodes;
}

// --- small shared bits ---------------------------------------------------
function segmented(value, options, onSelect, disabled) {
  return el("div", { class: "segmented", role: "group", "aria-label": "Build variant" },
    options.map((opt) => el("button", {
      type: "button", class: "seg" + (opt === value ? " on" : ""),
      "aria-pressed": opt === value ? "true" : "false", disabled: !!disabled,
      text: opt.charAt(0).toUpperCase() + opt.slice(1),
      onclick: () => onSelect(opt),
    })));
}

function row(label, valueNode) {
  return el("div", { class: "row" }, [el("span", { text: label }), valueNode]);
}

function humanSize(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n <= 0) return "";
  const units = ["B", "KB", "MB", "GB"];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(1)) + " " + units[i];
}

// verifiedBootState is 0 Verified, 1 SelfSigned, 2 Unverified, 3 Failed.
function named(state) {
  const names = ["Verified", "SelfSigned", "Unverified", "Failed"];
  if (state == null) return null;
  return typeof state === "number" && names[state] ? names[state] : String(state);
}
