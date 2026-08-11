// The daemon transport seam. This is the SINGLE file that speaks the daemon's
// KeyAdmin wire protocol; the controller, the status probe, and the views know
// only keyAdmin(action, args) and the JSON shapes documented below. Swapping this
// HTTP transport for, say, an exec-based one later is therefore a one-file change
// — nothing above this file ever names a URL, a token, or a header.
//
// Transport: HTTP/1.1 to the daemon's loopback listener. The daemon serves CORS-
// open on 127.0.0.1 so the WebUI (running in the manager's webview) can fetch it
// directly. Every request carries the admin token in X-Teesim-Token; the daemon
// rejects anything without it, which keeps the endpoint safe even though it is
// bound to loopback.
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
//   keyAdmin("packages")             -> { ok, firstAppUid,
//                                          apps:[{ uid, packages:[…], label, system,
//                                                  launchable, enabled, installTime, freq,
//                                                  lastUsed, recent }] }
//       the live device app list, ONE entry per uid (packages sharing a uid are collapsed;
//       `packages` lists them all, sorted). `label` is the best human name, `system` is
//       true for a framework/system-flagged app or any uid below firstAppUid, `launchable`
//       whether it has a launcher activity, `enabled` the representative app's state.
//       firstAppUid is Process.FIRST_APPLICATION_UID (10000). Feeds the Scope picker.
//       The usage columns: `installTime` epoch ms of first install (0 unknown), `freq`
//       the persistent count of key requests this app has made (max over its package names,
//       0 if none), `lastUsed` epoch ms of the last request (0 if never), `recent` true when
//       the app has asked for a key since THIS boot. These drive the Scope sort/badges.
//   keyAdmin("usageClear")           -> { ok, cleared }
//       wipes the daemon's persisted frequency memory (usage.json). The Scope page's "Clear
//       usage" button calls this; `cleared` is how many package entries were dropped.
//   keyAdmin("inspect", { alias })   -> { ok, alias, cert{…}, attestation:{…}|null }
//   keyAdmin("delete",  { alias })   -> { ok, deleted }
//   keyAdmin("logs", { after, max }) -> { ok, lines:[{ seq, level, tag, text }], nextAfter }
//   keyAdmin("logsWrite", { dir, name, text }) -> { ok, path } | { ok:false, error }
//       the daemon (root) writes `text` to <dir>/<safe(name)>, creating dir; it names and
//       places the file since the WebView ignores download filenames and Content-Disposition.
//   keyAdmin("keyboxInspect", { name }) -> { ok, name, deviceId,
//                                          keys:[{ algorithm, privateKeyPresent, chainLength,
//                                                  linkage, certs:[{ index, subject, issuer,
//                                                  serial, notBefore, notAfter, expired,
//                                                  keyAlgorithm, keySize, isCa, ... }] }] }
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
// data/* may import bridge/shell.js — that is the only bridge dependency here, and
// only to read the root-only token file once.
import { readFile } from "../bridge/shell.js";

const BASE = "http://127.0.0.1:8790";
const TOKEN_FILE = "/data/adb/teesim/admin.token";

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

// A daemon download is reached by a browser navigation, which cannot carry the
// X-Teesim-Token header, so the log-download route authenticates with a ?token= query
// param. These two exports keep the base URL and token owned by this seam; callers build
// only the path+query. Prefetch adminToken() so the token is in hand before the click.
export const API_BASE = BASE;
export function adminToken() {
  return getToken();
}

// GET /icon?pkg=<package>&token=<token> -> raw PNG (the daemon renders the app icon and
// caches it). A browser <img> cannot set the X-Teesim-Token header, so — exactly like the
// log-download route — the token rides in the query string. The URL is what an <img src> or
// CSS background points at; this seam owns the base+token so the view never names either.
// The Scope controller prefetches adminToken() once and then builds row URLs synchronously,
// but this async helper is here for any caller that just wants one URL without that dance.
export async function iconUrlAsync(pkg) {
  const t = await getToken();
  return BASE + "/icon?pkg=" + encodeURIComponent(pkg || "") + "&token=" + encodeURIComponent(t || "");
}

// One request helper: attach the token header, parse JSON, and convert any non-200
// or network/parse failure into a thrown Error carrying the daemon's message when
// there is one.
async function request(method, path, body) {
  const token = await getToken();
  const t0 = Date.now();
  console.log("[keyAdmin] → %s %s%s", method, path, token ? "" : " (NO TOKEN)");
  const init = { method, headers: { "X-Teesim-Token": token } };
  if (body != null) {
    init.body = body;
    init.headers["Content-Type"] = "text/plain; charset=utf-8";
  }
  let res;
  try {
    res = await fetch(BASE + path, init);
  } catch (e) {
    console.error("[keyAdmin] ✗ %s %s network error in %dms:", method, path, Date.now() - t0, e);
    throw new Error("daemon unreachable: " + (e && e.message ? e.message : String(e)));
  }
  // Response body — a distinct name from the `body` REQUEST parameter above (re-declaring a parameter
  // with `let` is a SyntaxError that would break this whole module and, with it, the entire WebUI).
  let data = null;
  try { data = await res.json(); } catch { /* leave null on empty/invalid JSON */ }
  console.log("[keyAdmin] ← %s %s %d ok=%o in %dms", method, path, res.status, res.ok, Date.now() - t0);
  if (!res.ok) {
    console.warn("[keyAdmin] ✗ %s %s body:", method, path, data);
    // The daemon reports failures two ways: key ops use { ok:false, error },
    // while the canary endpoints use { ok:false, message }. Surface either so a
    // failed canaryInstall keeps the daemon's human-readable reason.
    throw new Error((data && (data.error || data.message)) || ("HTTP " + res.status));
  }
  return data;
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
      return request("GET", "/keys/db");
    case "packages":
      return request("GET", "/packages");
    case "usageClear":
      return request("POST", "/usage/clear");
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
      return request("GET", "/keybox/inspect" + nameQuery(args));
    case "canary":
      return request("GET", "/canary");
    case "canaryInstall":
      return request("POST", "/canary/install" + canaryInstallQuery(args));
    default:
      throw new Error("unknown keyAdmin action: " + action);
  }
}
