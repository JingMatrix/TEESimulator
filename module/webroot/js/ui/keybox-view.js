// The Keyboxes panel. The resting screen is the list of *.xml keyboxes on disk, each a
// row whose name is the inspect trigger plus Rename and Delete; Import is the panel-head
// primary and opens a bottom sheet (file picker + name field + Import) built by
// renderKeyboxImport. Inspecting opens a drill-in that pretty-prints the parsed
// certificate chains (renderKeyboxInspect). Pure
// DOM through el(); it renders from controller state and emits intents through `actions`.
// It never imports data/* or bridge/*. All text is textContent via el's `text`, never
// innerHTML.
//
// renderKeyboxes(mount, state, actions)
//   state   = { files }
//   actions = { onImport(), inspect(name), rename(name), delete(name) }
//
// renderKeyboxImport(state, actions) -> HTMLElement   (content for the import sheet)
//   state   = { importName, importContent, error }
//   actions = { pickFile(file), setImportName(str), import(), close() }
//
// renderKeyboxInspect(state, actions) -> HTMLElement  (content for the inspect drill-in)
//   state   = { name, data }   the /keybox/inspect response to pretty-print
//   actions = { close() }

import { el, clear } from "./dom.js";

export function renderKeyboxes(mount, state, actions) {
  clear(mount);
  const { files = [] } = state;

  mount.appendChild(el("div", { class: "panel-head" }, [
    el("h1", { class: "panel-title", text: "Keyboxes" }),
    el("button", { class: "btn primary", text: "Import", onclick: () => actions.onImport() }),
  ]));

  if (!files.length) {
    mount.appendChild(el("div", { class: "card empty" },
      [el("p", { class: "muted", text: "No keyboxes yet. Import an *.xml keybox to sign attestations with." })]));
    return;
  }

  const list = el("ul", { class: "kb-list card" });
  for (const name of files) {
    list.appendChild(el("li", { class: "kb-row" }, [
      // The name is the inspect trigger: a small keybox badge + the filename, keyboard-reachable,
      // that wraps instead of shoving the Rename/Delete buttons off the row.
      el("button", {
        class: "kb-name mono", type: "button",
        title: "Inspect " + name, onclick: () => actions.inspect(name),
      }, [
        el("span", { class: "kb-icon", "aria-hidden": "true" }),
        el("span", { class: "kb-file", text: name }),
      ]),
      el("div", { class: "keybtns" }, [
        el("button", { class: "btn small ghost", text: "Rename", onclick: () => actions.rename(name) }),
        el("button", { class: "btn small danger ghost", text: "Delete", onclick: () => actions.delete(name) }),
      ]),
    ]));
  }
  mount.appendChild(list);
}

export function renderKeyboxImport(state, actions) {
  const { importName = "", importContent = "", error = null } = state;

  // No `accept` filter: Android's document picker greys out any file whose provider
  // MIME isn't an exact match (a keybox reports text/xml or octet-stream, not the
  // application/xml the filter asks for), so it looked like "no file is selectable".
  // We validate the content after reading instead, so any file can be chosen.
  const fileInput = el("input", {
    class: "input", type: "file",
    onchange: (e) => { const f = e.target.files && e.target.files[0]; if (f) actions.pickFile(f); },
  });
  // Bare keystrokes only sync the controller's field; they never re-render, so the
  // caret is never yanked mid-type. A discrete pickFile/import redraws.
  const nameInput = el("input", {
    class: "input", type: "text", value: importName, placeholder: "keybox.xml",
    autocapitalize: "off", autocorrect: "off", spellcheck: "false",
    oninput: (e) => actions.setImportName(e.target.value),
  });

  return el("div", {}, [
    el("div", { class: "sheet-head" }, [
      el("h2", { text: "Import keybox" }),
      el("button", { class: "iconbtn", type: "button", "aria-label": "Close", onclick: () => actions.close() }, [
        el("span", { class: "x-mark", "aria-hidden": "true" }),
      ]),
    ]),
    error ? el("div", { class: "banner error" }, [el("div", { text: error })]) : null,
    el("div", { class: "field" }, [el("span", { class: "field-label", text: "Keybox file" }), fileInput]),
    el("div", { class: "field" }, [el("span", { class: "field-label", text: "Save as" }), nameInput]),
    el("button", { class: "btn primary block sheet-submit", text: "Import", disabled: !importContent, onclick: () => actions.import() }),
    el("p", { class: "field-help", text: "The file is copied into /data/adb/teesim; the name field becomes its filename." }),
  ]);
}

// ---- inspect drill-in ---------------------------------------------------
// The body is filled by fillKeyboxInspect so the controller can refill the SAME .drill-body element
// on pull-to-refresh — keeping the scroll container (and its pull-to-refresh binding) in place.
export function fillKeyboxInspect(body, state) {
  const { name = "", data = null } = state;
  clear(body);
  body.appendChild(el("div", { class: "keyalias" }, [el("span", { class: "mono", text: name })]));

  if (!data || data.ok === false) {
    body.appendChild(el("div", { class: "banner error" }, [
      el("div", { text: (data && data.error) || "Could not inspect this keybox." }),
    ]));
    return;
  }
  if (data.deviceId) body.appendChild(el("div", { class: "muted small", text: "DeviceID: " + data.deviceId }));
  const keys = Array.isArray(data.keys) ? data.keys : [];
  if (!keys.length) body.appendChild(el("p", { class: "muted", text: "No <Key> blocks found in this keybox." }));
  for (const k of keys) body.appendChild(keyBlock(k));
}

export function renderKeyboxInspect(state, actions) {
  const body = el("div", { class: "drill-body" });
  fillKeyboxInspect(body, state);

  return el("div", {}, [
    el("div", { class: "drill-head" }, [
      el("button", { class: "iconbtn", type: "button", "aria-label": "Back to keyboxes", onclick: () => actions.close() }, [
        el("span", { class: "chevron-left", "aria-hidden": "true" }),
      ]),
      el("h1", { class: "drill-title", text: "Keybox", tabindex: "-1" }),
    ]),
    body,
  ]);
}

function keyBlock(k) {
  const linkage = k.linkage || "";
  const linkChip =
    linkage === "ok" ? el("span", { class: "chip good", text: "chain ok" })
    : linkage === "broken" ? el("span", { class: "chip warn", text: "chain broken" })
    : linkage === "single" ? el("span", { class: "chip", text: "single cert" })
    : null;
  const head = el("div", { class: "kbi-head" }, [
    el("span", { class: "chip mono", text: (k.algorithm || "?").toUpperCase() }),
    el("span", { class: "chip", text: (k.chainLength || 0) + (k.chainLength === 1 ? " cert" : " certs") }),
    linkChip,
    k.privateKeyPresent
      ? el("span", { class: "chip good", text: "private key" })
      : el("span", { class: "chip warn", text: "no private key" }),
    // The TA matches this attribute exactly, so a different spelling means the key is invisible
    // to the thing that signs with it — the one defect a chain-level verdict cannot show.
    k.algorithmRecognized === false
      ? el("span", { class: "chip danger", text: "algorithm not 'rsa'/'ecdsa'" })
      : null,
    k.countMismatch
      ? el("span", { class: "chip warn", text: "declares " + k.declaredCerts })
      : null,
  ]);
  const certs = Array.isArray(k.certs) ? k.certs : [];
  return el("div", { class: "card kbi-key" }, [
    verdictBanner(k),
    head,
    privateKeyBlock(k.privateKey),
    ...certs.map(certBlock),
  ]);
}

// What the <PrivateKey> block holds, and the question the file itself cannot answer: does this key
// belong to the leaf certificate? A keybox pairs the two with nothing tying them together, so a
// mismatched pair looks perfect here and fails later, at signing time, with no explanation.
function privateKeyBlock(pk) {
  if (!pk || !pk.present) return null;
  const chips = el("div", { class: "chips" }, [
    el("span", { class: "chip mono", text: (pk.type || "?") + (pk.size ? " " + pk.size : "") }),
    pk.encoding ? el("span", { class: "chip", text: pk.encoding }) : null,
    pk.matchesLeaf === true ? el("span", { class: "chip good", text: "matches the leaf" }) : null,
    pk.matchesLeaf === false ? el("span", { class: "chip danger", text: "does not match the leaf" }) : null,
    pk.algorithmAgrees === false ? el("span", { class: "chip warn", text: "not the declared algorithm" }) : null,
  ]);
  return el("div", { class: "kbi-cert" }, [
    el("div", { class: "kbi-subhead", text: "private key" }),
    chips,
    pk.pemLabel ? kv("pem", pk.pemLabel) : null,
    pk.error ? el("div", { class: "err", text: pk.error }) : null,
    pk.matchesLeaf === false
      ? el("div", { class: "err", text: "Every attestation signed with this key would carry a chain that cannot verify." })
      : null,
  ]);
}

function certBlock(c) {
  if (c.error) {
    return el("div", { class: "kbi-cert" }, [el("div", { class: "err", text: "cert " + c.index + ": " + c.error })]);
  }
  const authTier = c.rootAuthority === "google" || c.rootAuthority === "knox" ? "good" : "warn";
  const badges = el("div", { class: "chips" }, [
    el("span", { class: "chip", text: roleOf(c) }),
    el("span", { class: "chip mono", text: (c.keyAlgorithm || "?") + (c.keySize ? " " + c.keySize : "") }),
    c.rootAuthority ? el("span", { class: "chip " + authTier, text: authorityLabel(c.rootAuthority) }) : null,
    c.revoked ? el("span", { class: "chip danger", text: "revoked" }) : null,
    c.signatureValid === false ? el("span", { class: "chip warn", text: "bad signature" }) : null,
    c.expired ? el("span", { class: "chip warn", text: "expired" }) : null,
    c.notYetValid ? el("span", { class: "chip warn", text: "not yet valid" }) : null,
  ]);
  return el("div", { class: "kbi-cert" }, [
    badges,
    kv("subject", c.subject),
    kv("issuer", c.issuer),
    kv("serial", c.serial),
    c.revoked ? kv("revocation", (c.revocationStatus || "REVOKED") + (c.revocationReason ? " · " + c.revocationReason : "")) : null,
    kv("valid", fmtDate(c.notBefore) + "  →  " + fmtDate(c.notAfter)),
    kv("sigAlg", c.sigAlg),
    // The identifier is recomputable (RFC 5280 method 1: SHA-1 of the subjectPublicKey), so a
    // certificate whose identifier does not match the key it carries has had one of the two swapped.
    c.ski ? kv("subject key id", c.ski.value + (c.ski.isPublicKeySha1 === false ? "  ✕ not the SHA-1 of this key" : "")) : null,
    c.aki ? kv("authority key id", [c.aki.value, c.aki.issuer, c.aki.serial].filter(Boolean).join(" · ")) : null,
    c.keyUsage ? kv("key usage", c.keyUsage.join(", ")) : null,
    c.extendedKeyUsage ? kv("extended key usage", c.extendedKeyUsage.join(", ")) : null,
    c.isCa ? kv("path length", c.pathLen === -1 || c.pathLen == null ? "unlimited" : String(c.pathLen)) : null,
    c.crl ? kv("crl", c.crl.join("\n")) : null,
    c.aia ? kv("authority info", c.aia.join("\n")) : null,
    c.san ? kv("alt names", c.san.join(", ")) : null,
    c.policies ? kv("policies", c.policies.join(", ")) : null,
    // Google's RKP certificates carry this; the build fingerprint inside is the most identifying
    // thing in a keybox, and it is invisible unless something decodes the CBOR.
    c.provisioning ? el("div", { class: "kbi-subhead", text: "provisioning" }) : null,
    ...provisioningRows(c.provisioning),
    c.hasAttestation ? kv("extension", "carries an Android key attestation record") : null,
    c.otherExtensions ? kv("other extensions", c.otherExtensions.join(", ")) : null,
    c.fingerprint ? kv("sha-256", c.fingerprint) : null,
  ]);
}

function provisioningRows(p) {
  if (!p) return [];
  // No summary line: it could only restate the rows below it.
  return (Array.isArray(p.fields) ? p.fields : []).map((f) => kv("  " + f.label, f.value));
}

function authorityLabel(a) {
  switch (a) {
    case "google": return "Google root";
    case "aosp": return "AOSP root";
    case "knox": return "Knox root";
    case "none": return "no root";
    default: return "unknown root";
  }
}

function roleOf(c) {
  if (c.index === 0) return "leaf";
  if (c.selfSigned) return "root";
  return c.isCa ? "intermediate" : "cert " + c.index;
}

function kv(label, value) {
  return el("div", { class: "kv kv-stack" }, [
    el("span", { class: "kv-label", text: label }),
    el("span", { class: "mono kv-hex", text: value == null || value === "" ? "—" : String(value) }),
  ]);
}

function fmtDate(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return "—";
  try { return new Date(n).toISOString().slice(0, 10); } catch { return String(ms); }
}
