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
//   keyAdmin("status")               -> { ok, harvest{…}, lib:{ hook, api } }
//   keyAdmin("list")                 -> { ok, keys:[{ alias, securityLevel, ours, cert{…} }] }
//   keyAdmin("keysDb")               -> { ok, available, apiLevel,
//                                          keys:[{ id, alias, uid, package, state,
//                                                  created?, keybox?, keyAlgorithm? }] }
//       the keys THIS MODULE minted for target apps, read from keystore2's database on
//       API >= 31; on Android 10/11 there is no such database, so available:false and
//       keys:[] (the UI shows a hint). `id` is keystore2's keyentry id (delete handle),
//       `keybox` the signing keybox filename when the chain could be attributed.
//   keyAdmin("keysDbDelete", { ids }) -> { ok, deleted, requested }
//       remove those keyentry ids from keystore2; the daemon re-verifies each is one of
//       our marked target-app keys before deleting, so a stray id is a no-op.
//   keyAdmin("inspect", { alias })   -> { ok, alias, cert{…}, attestation:{…}|null }
//   keyAdmin("delete",  { alias })   -> { ok, deleted }
//   keyAdmin("logs", { after, max }) -> { ok, lines:[{ seq, level, tag, text }], nextAfter }
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
    tokenPromise = readFile(TOKEN_FILE).then((s) => (s || "").trim());
  }
  return tokenPromise;
}

// One request helper: attach the token header, parse JSON, and convert any non-200
// or network/parse failure into a thrown Error carrying the daemon's message when
// there is one.
async function request(method, path) {
  const token = await getToken();
  let res;
  try {
    res = await fetch(BASE + path, { method, headers: { "X-Teesim-Token": token } });
  } catch (e) {
    throw new Error("daemon unreachable: " + (e && e.message ? e.message : String(e)));
  }
  let body = null;
  try { body = await res.json(); } catch { /* leave body null on empty/invalid JSON */ }
  if (!res.ok) {
    // The daemon reports failures two ways: key ops use { ok:false, error },
    // while the canary endpoints use { ok:false, message }. Surface either so a
    // failed canaryInstall keeps the daemon's human-readable reason.
    throw new Error((body && (body.error || body.message)) || ("HTTP " + res.status));
  }
  return body;
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

export async function keyAdmin(action, args = {}) {
  switch (action) {
    case "status":
      return request("GET", "/status");
    case "list":
      return request("GET", "/keys");
    case "keysDb":
      return request("GET", "/keys/db");
    case "keysDbDelete":
      return request("POST", "/keys/db/delete" + idsQuery(args));
    case "inspect":
      return request("GET", "/keys/inspect" + aliasQuery(args));
    case "delete":
      return request("POST", "/keys/delete" + aliasQuery(args));
    case "logs":
      return request("GET", "/logs" + logsQuery(args));
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
