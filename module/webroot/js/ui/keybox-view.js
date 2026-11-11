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
//
// The page is built the way a keybox is: a file holding one key per algorithm, each paired with the
// chain that vouches for it. So each key renders as a verdict and then as its CHAIN — one node per
// certificate, leaf first, strung on a rail, with the link between two nodes carrying the one fact
// that joins them (the signature of the lower verified against the key of the upper). A node shows
// what identifies a certificate and whether it is usable right now; everything else it carries sits
// one tap away, so the page can be read at a glance and still holds every field.
export function fillKeyboxInspect(body, state) {
  const { name = "", data = null } = state;
  clear(body);

  if (!data || data.ok === false) {
    body.appendChild(el("div", { class: "keyalias" }, [el("span", { class: "mono", text: name })]));
    body.appendChild(el("div", { class: "banner error" }, [
      el("div", { text: (data && data.error) || "Could not inspect this keybox." }),
    ]));
    return;
  }

  body.appendChild(fileHead(name, data));
  const keys = Array.isArray(data.keys) ? data.keys : [];
  if (!keys.length) {
    body.appendChild(el("div", { class: "card empty" }, [
      el("p", { class: "muted", text: "No <Key> blocks found in this keybox." }),
    ]));
  }
  // A keybox may pair a chain per algorithm. With one there is nothing to tell apart and the
  // algorithm is already a chip on the verdict; with two, each section says which key it is about.
  for (const k of keys) body.appendChild(keySection(k, keys.length > 1));
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

// The file itself: its name, and the DeviceID its <Keybox> element declares. The id is the keybox's
// own label for the device it was cut for -- manufacturer plus random, not a hardware address -- so
// it is reported, not interpreted.
function fileHead(name, data) {
  return el("div", { class: "kbi-file" }, [
    el("div", { class: "kbi-file-name mono", text: name }),
    data.deviceId
      ? el("div", { class: "kbi-file-sub" }, [
          el("span", { class: "kv-label", text: "DeviceID:" }),
          el("span", { class: "mono", text: data.deviceId }),
        ])
      : null,
    data.revocationListAvailable === false
      ? el("div", { class: "kbi-file-sub warn-text", text: "Google's revocation list could not be fetched — revocation below is unchecked." })
      : null,
  ]);
}

// One <Key> element: the verdict its chain earns, what the file pairs with it, and the chain.
function keySection(k, titled) {
  const certs = Array.isArray(k.certs) ? k.certs : [];
  return el("section", { class: "kbi-key" }, [
    titled ? el("div", { class: "kbi-subhead", text: (k.algorithm || "?").toUpperCase() + " key" }) : null,
    verdictCard(k),
    certs.length
      ? el("ol", { class: "kbi-chain" }, certs.map((c, i) => chainNode(c, i, certs.length)))
      : el("p", { class: "muted small", text: "This key carries no certificates." }),
  ]);
}

// The headline: the verdict, then the facts it was drawn from, then what the file pairs with this
// chain. Everything here is a field of the <Key>, not of any one certificate.
function verdictCard(k) {
  const v = verdictOf(k);
  const pk = k.privateKey;
  return el("div", { class: "card kbi-head kbi-head--" + v.tier }, [
    el("div", { class: "kbi-verdict" }, [
      el("span", { class: "kbi-verdict-icon", "aria-hidden": "true", text: v.icon }),
      el("div", { class: "kbi-verdict-text" }, [
        el("div", { class: "kbi-verdict-title", text: v.title }),
        el("div", { class: "kbi-verdict-sub", text: v.sub }),
      ]),
    ]),
    el("div", { class: "chips" }, [
      el("span", { class: "chip mono", text: (k.algorithm || "?").toUpperCase() }),
      el("span", { class: "chip", text: (k.chainLength || 0) + (k.chainLength === 1 ? " certificate" : " certificates") }),
      k.linkage === "ok" ? el("span", { class: "chip good", text: "chain links up" }) : null,
      k.linkage === "broken" ? el("span", { class: "chip danger", text: "chain does not link up" }) : null,
      k.linkage === "single" ? el("span", { class: "chip warn", text: "single certificate" }) : null,
      // The TA matches this attribute exactly, so a different spelling means the key is invisible
      // to the thing that signs with it — the one defect a chain-level verdict cannot show.
      k.algorithmRecognized === false
        ? el("span", { class: "chip danger", text: "algorithm not 'rsa'/'ecdsa'" })
        : null,
      k.countMismatch ? el("span", { class: "chip warn", text: "declares " + k.declaredCerts }) : null,
    ]),
    privateKeyRow(pk, k.privateKeyPresent),
  ]);
}

// What the <PrivateKey> block holds, and the question the file itself cannot answer: does this key
// belong to the leaf certificate? A keybox pairs the two with nothing tying them together, so a
// mismatched pair looks perfect here and fails later, at signing time, with no explanation. The
// daemon settles it by signing with the key and verifying against the leaf.
function privateKeyRow(pk, present) {
  if (!pk || !pk.present) {
    return el("div", { class: "kbi-pk" }, [
      el("span", { class: "kbi-pk-label", text: "private key" }),
      el("span", { class: "chip danger", text: present ? "unreadable" : "absent" }),
    ]);
  }
  return el("div", { class: "kbi-pk" }, [
    el("span", { class: "kbi-pk-label", text: "private key" }),
    el("div", { class: "chips" }, [
      el("span", { class: "chip mono", text: (pk.type || "?") + (pk.size ? " " + pk.size : "") }),
      pk.encoding ? el("span", { class: "chip", text: pk.encoding }) : null,
      pk.matchesLeaf === true ? el("span", { class: "chip good", text: "matches the leaf" }) : null,
      pk.matchesLeaf === false ? el("span", { class: "chip danger", text: "does not match the leaf" }) : null,
      pk.algorithmAgrees === false ? el("span", { class: "chip warn", text: "not the declared algorithm" }) : null,
    ]),
    pk.error ? el("div", { class: "err", text: pk.error }) : null,
    pk.matchesLeaf === false
      ? el("div", { class: "err", text: "Every attestation signed with this key would carry a chain that cannot verify." })
      : null,
  ]);
}

// ---- the chain ----------------------------------------------------------
// One certificate, as a node on the rail: its position and role, the name it goes by, the facts
// that decide whether it is usable now, and -- under it, on the rail itself -- how it attaches to
// the certificate above. Its full contents are one tap away.
function chainNode(c, i, total) {
  if (c.error) {
    return el("li", { class: "kbi-node" }, [
      el("span", { class: "kbi-node-dot kbi-node-dot--bad", text: String(i + 1) }),
      el("div", { class: "card kbi-cert-card" }, [
        el("div", { class: "err", text: "certificate " + i + ": " + c.error }),
      ]),
    ]);
  }
  const bad = c.revoked || c.signatureValid === false;
  const name = c.subjectCn || c.subject || "(unnamed)";
  const issuedBy = c.selfSigned ? "self-issued" : "issued by " + (c.issuerCn || c.issuer || "(unknown)");

  const card = el("div", { class: "card kbi-cert-card" }, [
    el("div", { class: "kbi-cert-top" }, [
      el("span", { class: "kbi-role", text: roleOf(c) }),
      el("div", { class: "chips" }, [
        c.rootAuthority ? el("span", { class: "chip " + authorityTier(c.rootAuthority), text: authorityLabel(c.rootAuthority) }) : null,
        c.revoked ? el("span", { class: "chip danger", text: "revoked" }) : null,
        c.expired ? el("span", { class: "chip warn", text: "expired" }) : null,
        c.notYetValid ? el("span", { class: "chip warn", text: "not yet valid" }) : null,
      ]),
    ]),
    el("div", { class: "kbi-cert-name mono", text: name }),
    // Two lines rather than one run of separated parts: where it comes from and what it holds, then
    // the window it is good for. A single line wraps mid-separator on a phone and leaves a stray
    // dot at the end of it.
    el("div", { class: "kbi-cert-meta" }, [
      el("span", { text: issuedBy }),
      el("span", { class: "kbi-dot-sep", "aria-hidden": "true", text: "·" }),
      el("span", { class: "mono", text: (c.keyAlgorithm || "?") + (c.keySize ? " " + c.keySize : "") }),
    ]),
    el("div", {
      class: "kbi-cert-meta" + (c.expired || c.notYetValid ? " warn-text" : ""),
      text: fmtDate(c.notBefore) + " → " + fmtDate(c.notAfter),
    }),
    foldable("details", () => certDetail(c)),
  ]);

  return el("li", { class: "kbi-node" + (bad ? " kbi-node--bad" : "") }, [
    el("span", { class: "kbi-node-dot" + (bad ? " kbi-node-dot--bad" : ""), text: String(i + 1) }),
    card,
    linkNote(c, i, total),
  ]);
}

// The edge between this certificate and the one above it: whose key its signature was checked
// against, and whether that check passed. The top certificate has no parent in the file — it either
// signs itself, or the chain simply ends below its issuer and there is nothing here to check it
// against.
function linkNote(c, i, total) {
  const top = i === total - 1;
  if (c.signatureValid === true) {
    return el("div", { class: "kbi-link kbi-link--ok" }, [
      el("span", { class: "kbi-link-mark", "aria-hidden": "true", text: "✓" }),
      el("span", { text: top ? "self-signed, signature verifies" : "signature verifies against #" + (i + 2) }),
    ]);
  }
  if (c.signatureValid === false) {
    return el("div", { class: "kbi-link kbi-link--bad" }, [
      el("span", { class: "kbi-link-mark", "aria-hidden": "true", text: "✕" }),
      el("span", { text: top ? "self-signed, signature does not verify" : "signature does not verify against #" + (i + 2) }),
    ]);
  }
  return el("div", { class: "kbi-link" }, [
    el("span", { class: "kbi-link-mark", "aria-hidden": "true", text: "·" }),
    el("span", { text: "the certificate that signed this one is not in this file" }),
  ]);
}

// Everything the certificate carries, in the order a reader asks for it: the full names, then the
// key and what it may be used for, then the identifiers that tie key and certificate together, then
// where the issuer publishes revocation, then what the issuer recorded, then the file's own digest.
function certDetail(c) {
  return el("div", { class: "kbi-detail" }, [
    kv("subject", c.subject),
    kv("issuer", c.issuer),
    kv("serial", c.serial),
    c.revoked ? kv("revocation", (c.revocationStatus || "REVOKED") + (c.revocationReason ? " · " + c.revocationReason : "")) : null,
    c.revocationChecked === false ? kv("revocation", "not checked — the list could not be fetched") : null,
    kv("valid", fmtDate(c.notBefore) + "  →  " + fmtDate(c.notAfter)),
    kv("signature algorithm", c.sigAlg),
    c.curve ? kv("curve", c.curve) : null,
    c.keyUsage ? kv("key usage", c.keyUsage.join(", ")) : null,
    c.extendedKeyUsage ? kv("extended key usage", c.extendedKeyUsage.join(", ")) : null,
    c.isCa ? kv("path length", c.pathLen === -1 || c.pathLen == null ? "unlimited" : String(c.pathLen)) : null,
    // The identifier is recomputable (RFC 5280 method 1: SHA-1 of the subjectPublicKey), so a
    // certificate whose identifier does not match the key it carries has had one of the two swapped.
    c.ski ? kv("subject key id", c.ski.value + (c.ski.isPublicKeySha1 === false ? "  ✕ not the SHA-1 of this key" : "")) : null,
    c.aki ? kv("authority key id", [c.aki.value, c.aki.issuer, c.aki.serial].filter(Boolean).join(" · ")) : null,
    c.crl ? kv("crl", c.crl.join("\n")) : null,
    c.aia ? kv("authority info", c.aia.join("\n")) : null,
    c.san ? kv("alt names", c.san.join(", ")) : null,
    c.policies ? kv("policies", c.policies.join(", ")) : null,
    // Google's RKP certificates carry this; the build fingerprint inside is the most identifying
    // thing in a keybox, and it is invisible unless something decodes the CBOR.
    c.provisioning ? provisioningBlock(c.provisioning) : null,
    c.hasAttestation ? kv("extension", "carries an Android key attestation record") : null,
    c.otherExtensions ? kv("other extensions", c.otherExtensions.join(", ")) : null,
    c.fingerprint ? kv("sha-256 of this certificate", c.fingerprint) : null,
  ]);
}

// ---- pieces -------------------------------------------------------------
// A fold whose body is built on first open and then shown or hidden in place. The open state is
// presentation alone -- no controller knows or needs to know which certificates are unfolded -- so
// it is held in the DOM rather than pushed through a re-render, which would also cost the page its
// scroll position on every tap.
function foldable(label, buildBody) {
  let built = null;
  const wrap = el("div", { class: "kbi-fold" });
  const head = el("button", {
    class: "kbi-fold-head", type: "button", "aria-expanded": "false",
    onclick: () => {
      const open = head.getAttribute("aria-expanded") === "true";
      if (!open && !built) { built = buildBody(); wrap.appendChild(built); }
      head.setAttribute("aria-expanded", open ? "false" : "true");
      head.classList.toggle("open", !open);
      if (built) built.hidden = open;
    },
  }, [
    el("span", { class: "kbi-fold-chevron", "aria-hidden": "true" }),
    el("span", { text: label }),
  ]);
  wrap.appendChild(head);
  return wrap;
}

// The decoded provisioningInfo. The extension is a map whose values may themselves be maps, and
// that shape is what the rows mean: a verdict belongs to the attribute it sits beside, not to the
// certificate. So each map renders as a labelled block holding its own rows, nested as deeply as
// the extension is -- which also shows where a block ENDS, and so which rows below it are the
// certificate's own rather than the issuer's. No summary line: it could only restate the rows.
function provisioningBlock(p) {
  return el("div", { class: "kbi-map" }, [
    el("div", { class: "kbi-map-label", text: "provisioning" }),
    ...provisioningRows(p && p.fields),
  ]);
}

function provisioningRows(fields) {
  if (!Array.isArray(fields)) return [];
  return fields.map((f) =>
    Array.isArray(f.fields)
      ? el("div", { class: "kbi-map" }, [
          el("div", { class: "kbi-map-label", text: f.label }),
          ...provisioningRows(f.fields),
        ])
      : kv(f.label, f.value));
}

// The headline verdict for a chain: is this a genuine, live keybox that would pass hardware
// attestation, or a revoked / software / broken one? Built from the daemon's chain-level fields.
function verdictOf(k) {
  const unchecked = k.revocationChecked === false;
  if (k.revoked) {
    return { tier: "bad", icon: "✕", title: "Revoked by Google",
      sub: "A certificate in this chain is on Google's revocation list — attestations it signs are rejected by Play Integrity." };
  }
  if (k.chainVerified === false) {
    return { tier: "bad", icon: "✕", title: "Chain does not verify",
      sub: "A certificate signature in this chain is invalid, so it is not a usable attestation chain." };
  }
  // The chain can be impeccable and still be paired with the wrong private key, in which case every
  // signature made with it fails to verify against the leaf that accompanies it.
  if (k.privateKey && k.privateKey.matchesLeaf === false) {
    return { tier: "bad", icon: "✕", title: "Private key is not the leaf's",
      sub: "The key in this keybox does not belong to the certificate paired with it, so nothing it signs verifies against this chain." };
  }
  const revNote = unchecked ? " · revocation list unavailable" : " · not revoked";
  switch (k.rootAuthority) {
    case "google":
      return { tier: "good", icon: "✓", title: "Signed by Google",
        sub: "Roots in the Google Hardware Attestation key" + revNote + "." };
    case "knox":
      return { tier: "good", icon: "✓", title: "Samsung Knox root",
        sub: "Roots in a Samsung Knox attestation key" + revNote + "." };
    case "aosp":
      return { tier: "warn", icon: "!", title: "AOSP software root",
        sub: "Rooted in the AOSP software test key — not a hardware-backed keybox; fails hardware attestation." };
    default:
      return { tier: "warn", icon: "?", title: "Unknown root",
        sub: "Chain does not root in a recognized attestation authority" + (unchecked ? " · revocation list unavailable" : "") + "." };
  }
}

function authorityTier(a) {
  return a === "google" || a === "knox" ? "good" : "warn";
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
  return c.isCa ? "intermediate" : "certificate " + c.index;
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
