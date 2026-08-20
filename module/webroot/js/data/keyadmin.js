// The daemon transport seam. This is the SINGLE file that speaks the daemon's
// KeyAdmin wire protocol; the controller, the status probe, and the views know
// only keyAdmin(action, args) and the JSON shapes documented below. Swapping this
// HTTP transport for, say, an exec-based one later is therefore a one-file change
// — nothing above this file ever names a URL, a token, or a header.
//
// Transport: HTTP/1.1 over the daemon's root-only unix socket, driven through the
// root-exec bridge (see below) because a WebView cannot fetch() one. Every request
// carries the admin token in X-Teesim-Token; the daemon rejects anything without it,
// and refuses any peer that is not root.
//
// Public surface (stable):
//   keyAdmin("status")               -> { ok, version, harvest{…}, lib:{ hook, api } }
//   keyAdmin("list")                 -> { ok, keys:[{ alias, securityLevel, ours, cert{…} }] }
//   keyAdmin("keysDb")               -> { ok, available, apiLevel,
//                                          keys:[{ id, alias, uid, package, state, class,
//                                                  created?, keybox?, keyAlgorithm? }] }
//       the keys THIS MODULE minted for target apps, read from keystore2's database on
//       API >= 31; on Android 10/11 there is no such database, so available:false and
//       keys:[] (the UI shows a hint). `id` is keystore2's keyentry id (delete handle),
//       `keybox` the signing keybox filename when the chain could be attributed.
//   keyAdmin("keysDbDelete", { ids }) -> { ok, deleted, requested }
//       remove those keyentry ids from keystore2; the daemon re-verifies each is one of
//       our marked target-app keys before deleting, so a stray id is a no-op.
//   keyAdmin("packages")             -> { ok, firstAppUid, users:[{ id, name, managed }],
//                                          apps:[{ uid, userId, packages:[…], label, system,
//                                                  launchable, enabled, installTime, freq,
//                                                  lastUsed, recent }] }
//       the live device app list, ONE entry per uid (packages sharing a uid are collapsed;
//       `packages` lists them all, sorted). `label` is the best human name, `system` is
//       true for a framework/system-flagged app or any privileged uid (app id below
//       firstAppUid), `launchable` whether it has a launcher activity, `enabled` the
//       representative app's state. firstAppUid is Process.FIRST_APPLICATION_UID (10000).
//       `users` lists every Android user, and `userId` says which one an entry was found in:
//       an app installed in both the primary user and a work profile appears TWICE, under two
//       uids, because it is two callers to keystore and is targeted separately (as `com.foo`
//       and `com.foo@10`). Feeds the Scope picker.
//       The usage columns: `installTime` epoch ms of first install (0 unknown), `freq`
//       the persistent count of key requests this app has made (max over its app tokens,
//       0 if none), `lastUsed` epoch ms of the last request (0 if never), `recent` true when
//       the app has asked for a key since THIS boot. These drive the Scope sort/badges.
//   keyAdmin("usageClear")           -> { ok, cleared }
//       wipes the daemon's persisted frequency memory (usage.json). The Scope page's "Clear
//       usage" button calls this; `cleared` is how many app entries were dropped.
//   keyAdmin("inspect", { alias })   -> { ok, alias, cert{…}, attestation:{…}|null }
//   keyAdmin("delete",  { alias })   -> { ok, deleted }
//   keyAdmin("logs", { after, max }) -> { ok, lines:[{ seq, level, tag, text }], nextAfter }
//   keyAdmin("logsWrite", { dir, name, text }) -> { ok, path } | { ok:false, error }
//       the daemon (root) writes `text` to <dir>/<safe(name)>, creating dir; it names and
//       places the file since the WebView ignores download filenames and Content-Disposition.
//   keyAdmin("keyboxInspect", { name, refresh? }) -> { ok, name, deviceId, revocationListAvailable,
//       refresh:true forces the daemon to re-fetch Google's revocation list (fresh, cache-busted)
//       before re-checking — the inspector's pull-to-refresh sets it.
//                                          keys:[{ algorithm, privateKeyPresent, chainLength, linkage,
//                                                  rootAuthority, googleSigned, chainVerified, revoked,
//                                                  revocationChecked,
//                                                  certs:[{ index, subject, issuer, serial, notBefore,
//                                                  notAfter, expired, sigAlg, keyAlgorithm, keySize, isCa,
//                                                  selfSigned, signatureValid, revoked, revocationChecked,
//                                                  revocationStatus, revocationReason, rootAuthority }] }] }
//       rootAuthority: which trust anchor the chain roots in — "google" (genuine hardware keybox),
//       "aosp" (software root), "knox", "unknown", or "none". googleSigned/chainVerified/revoked are the
//       chain-level verdicts the inspector's status banner is built from; revocationChecked is false when
//       Google's revocation list could not be fetched (so revoked is not authoritative).
//   keyAdmin("canary")               -> { ok, currentCode, latest:{ code, tag, name,
//                                          notes, htmlUrl, assets:[{ name, size }] }|null,
//                                          updateAvailable }
//   keyAdmin("canaryInstall", { tag, variant }) -> { ok, message }
//       variant is "release" | "debug"; the daemon does the GitHub query, download,
//       and flash — the UI only names the tag+variant and reports the result.
// Key operations are keyed by ALIAS only. On a non-200 response or a network error the
// call throws (or the daemon's own { ok:false, error } is surfaced) so the UI can
// show it rather than silently degrade.
//
// data/* may import bridge/shell.js — the one bridge dependency here. This seam uses it to read the
// root-only token, and to run the teesim-uds client (staging a request body through a temp file when
// one is needed) since the daemon is now reached over a unix socket rather than a fetchable URL.
import { readFile, run, writeFileAtomic, deleteFile, DIR } from "../bridge/shell.js";

// The daemon serves its admin endpoint on a root-only FILESYSTEM unix socket (see KeyAdmin.kt), not a
// loopback TCP port — so no other app can reach or even observe it. A WebView cannot fetch() a unix
// socket, so this seam does not fetch at all: it drives the shipped `teesim-uds` client through the
// root-exec bridge, which connects to the socket as root and speaks the same HTTP the daemon parses.
const SOCK = DIR + "/admin.sock";
const HELPER = DIR + "/teesim-uds";
const TOKEN_FILE = DIR + "/admin.token";

// The admin token gates every request. It is a root-only file, so we read it once
// through the bridge (the single path that has root) and memoize it for the life
// of the page. A concurrent second call reuses the same in-flight promise.
let tokenPromise = null;
function getToken() {
  if (!tokenPromise) {
    tokenPromise = readFile(TOKEN_FILE).then((s) => {
      const t = (s || "").trim();
      console.log("[keyAdmin] admin token loaded (%d chars) from %s", t.length, TOKEN_FILE);
      return t;
    });
  }
  return tokenPromise;
}

// GET /icon?pkg=<package>&user=<userId> -> raw PNG (the daemon renders the app icon and caches it).
// There is no fetchable URL for an <img src> any more — the bytes come back over the root bridge — so
// this returns a self-contained data: URL the view can drop straight into an <img>, or null when the
// app has no icon (the helper exits non-zero on a non-2xx response). `userId` picks the Android user:
// an app that exists only in a work profile has no record in user 0 to read an icon from.
export async function iconDataUrl(pkg, userId) {
  if (!pkg) return null;
  const token = await getToken();
  const path = "/icon?pkg=" + encodeURIComponent(pkg) + "&user=" + encodeURIComponent(userId || 0);
  const r = await run([HELPER, SOCK, "GET", path, token, "--b64"]);
  // errno 0 = HTTP 2xx (a PNG); anything else (no icon, transport error) -> fall back to the avatar.
  if (r.errno !== 0 || !r.stdout) return null;
  return "data:image/png;base64," + r.stdout.trim();
}

// One request helper: run the UDS client with the token header, parse the JSON body it prints, and
// convert a transport failure or a daemon { ok:false } into a thrown Error carrying the daemon's
// message when there is one. The helper's exit code encodes the HTTP status class (0 = 2xx, 2 = other
// status with the body still on stdout, 1 = connect/transport failure).
async function request(method, path, body) {
  const token = await getToken();
  const t0 = Date.now();
  console.log("[keyAdmin] → %s %s%s", method, path, token ? "" : " (NO TOKEN)");
  // A request body can be large (e.g. a full log dump for logsWrite), so it is handed to the helper
  // through a root-only temp file rather than the command line. The helper streams it with a
  // Content-Length; we delete it afterwards.
  let bodyFile = null;
  const argv = [HELPER, SOCK, method, path, token];
  if (body != null) {
    bodyFile = DIR + "/req-" + Math.random().toString(36).slice(2) + ".tmp";
    await writeFileAtomic(bodyFile, String(body));
    argv.push("--body-file", bodyFile);
  }
  try {
    const r = await run(argv);
    if (r.errno === 1 || r.errno === -1) {
      console.error("[keyAdmin] ✗ %s %s transport error in %dms: %o", method, path, Date.now() - t0, r.stderr);
      throw new Error("daemon unreachable" + (r.stderr ? ": " + String(r.stderr).trim() : ""));
    }
    // Response body — a distinct name from the `body` REQUEST parameter above (re-declaring a parameter
    // with `let` is a SyntaxError that would break this whole module and, with it, the entire WebUI).
    let data = null;
    try { data = JSON.parse(r.stdout); } catch { /* leave null on empty/invalid JSON */ }
    const ok = data ? data.ok !== false : r.errno === 0;
    console.log("[keyAdmin] ← %s %s errno=%o ok=%o in %dms", method, path, r.errno, ok, Date.now() - t0);
    if (!ok) {
      console.warn("[keyAdmin] ✗ %s %s body:", method, path, data);
      // The daemon reports failures two ways: key ops use { ok:false, error }, while the canary
      // endpoints use { ok:false, message }. Surface either so a failed canaryInstall keeps the
      // daemon's human-readable reason.
      throw new Error((data && (data.error || data.message)) || ("helper errno " + r.errno));
    }
    return data;
  } finally {
    if (bodyFile) { try { await deleteFile(bodyFile); } catch { /* best effort */ } }
  }
}

// The alias travels in the query string; encode it so any character is inert.
const aliasQuery = (args) => "?alias=" + encodeURIComponent((args && args.alias) || "");

// keystore2 key ids to delete, comma-joined (the daemon re-validates each id it receives).
const idsQuery = (args) => "?ids=" + encodeURIComponent(((args && args.ids) || []).join(","));

// The keybox filename, likewise encoded; the daemon re-validates it to a safe basename.
const nameQuery = (args) => "?name=" + encodeURIComponent((args && args.name) || "");

// Logs poll: fetch only lines newer than the cursor, bounded.
const logsQuery = (args) =>
  `?after=${Number((args && args.after) || 0)}&max=${Number((args && args.max) || 500)}`;

// Canary install target: the release tag and which asset variant to flash. Both
// travel in the query string (mirroring aliasQuery/logsQuery — request() takes no
// body), encoded so any character is inert; variant defaults to "release".
const canaryInstallQuery = (args) =>
  "?tag=" + encodeURIComponent((args && args.tag) || "") +
  "&variant=" + encodeURIComponent((args && args.variant) || "release");

// The save target: the chosen folder and filename, both encoded so any character is inert.
// The log text itself rides in the request body (too large for a query), not here.
const logsWriteQuery = (args) =>
  "?dir=" + encodeURIComponent((args && args.dir) || "") +
  "&name=" + encodeURIComponent((args && args.name) || "");

export async function keyAdmin(action, args = {}) {
  switch (action) {
    case "status":
      return request("GET", "/status");
    case "list":
      return request("GET", "/keys");
    case "keysDb":
      // Economical by default: the daemon maps uid -> app from the scope snapshot it published on the
      // last push, which costs nothing. refresh:true forces a live re-resolve (a full installed-app
      // enumeration) and belongs only on a user-driven refresh, never on a load or a poll.
      return request("GET", "/keys/db" + (args && args.refresh ? "?refresh=1" : ""));
    case "scope":
      // The daemon's RESOLVED per-profile truth from the last push:
      //   { ok, epoch, resolvedAtMs, baselineReady,
      //     profiles:[ { id, autoInclude, packages:[…], explicitUids:[…], autoUids:[…] } ] }
      // The only place auto-included uids are visible — the rule needs known_packages.json, which is
      // root-only and unreadable from here, so this cannot be recomputed client-side. It changes only
      // when the daemon re-resolves (start, config.json change, POST /rescan), so it is deliberately
      // NOT part of the Scope page's 9s /packages poll. An older daemon 404s this; treat that as
      // "no auto data" rather than an error.
      return request("GET", "/scope");
    case "packages":
      return request("GET", "/packages");
    case "usageClear":
      return request("POST", "/usage/clear");
    case "rescan":
      // Re-resolve and re-push the config against the live device. This is how a newly installed
      // app is discovered — there is no package observer in the daemon, so the Profiles screen's
      // pull-to-refresh is what goes and looks. Resolves to { ok, uids }.
      return request("POST", "/rescan");
    case "keysDbDelete":
      return request("POST", "/keys/db/delete" + idsQuery(args));
    case "inspect":
      return request("GET", "/keys/inspect" + aliasQuery(args));
    case "delete":
      return request("POST", "/keys/delete" + aliasQuery(args));
    case "logs":
      return request("GET", "/logs" + logsQuery(args));
    case "logsWrite":
      return request("POST", "/logs/write" + logsWriteQuery(args), args.text);
    case "keyboxInspect":
      // refresh:true has the daemon re-fetch Google's revocation list (fresh, cache-busted) before
      // re-checking — the keybox inspector's pull-to-refresh sets it.
      return request("GET", "/keybox/inspect" + nameQuery(args) + (args.refresh ? "&refresh=1" : ""));
    case "canary":
      return request("GET", "/canary");
    case "canaryInstall":
      return request("POST", "/canary/install" + canaryInstallQuery(args));
    default:
      throw new Error("unknown keyAdmin action: " + action);
  }
}
