// The single command-assembly boundary — the shell-injection choke point.
//
// RULE FOR CONTRIBUTORS: this is the ONLY module in the app permitted to build a
// shell command string. Every privileged operation is expressed either as an
// argv passed to run() (which POSIX-quotes each element) or as a helper built on
// the base64 heredoc pattern in writeFileAtomic(). Never interpolate a value
// into a command anywhere else, and never add a second file that imports
// bridge/ksu.js. If a value can reach a command, it goes through the quoting
// here — so even a string that somehow slipped past a domain whitelist stays
// inert data, not code.

import { exec } from "./ksu.js";

// Module-owned paths. Never assembled from user input.
export const DIR = "/data/adb/teesim";
export const CONFIG = DIR + "/config.json";
export const HARVEST = DIR + "/harvested.json";
export const OVERRIDES = DIR + "/overrides.json";

// POSIX single-quote one token. Everything between single quotes is literal in
// the shell except a single quote itself, which we close-escape-reopen as '\''.
// Newlines and every metacharacter survive as data.
const q = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";

// Run an argv array. Each element is quoted independently, so argv[0] is the
// program and the rest are inert arguments no matter what they contain.
export function run(argv) {
  return exec(argv.map(q).join(" "));
}

// Read a file's bytes as text. Absent file => empty string (cat writes nothing).
export async function readFile(path) {
  return (await run(["cat", path])).stdout;
}

// List the *.xml basenames in a directory (used for the keybox picker). The glob
// has to be expanded by the shell, so dir is quoted and dropped into an sh -c;
// the glob itself is a fixed literal, never user input.
export async function listXml(dir) {
  const r = await run(["sh", "-c", "ls -1 " + q(dir) + "/*.xml 2>/dev/null"]);
  return r.stdout
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((p) => p.split("/").pop());
}

// The mandated injection-safe write.
//
// The content is base64-encoded in JS and delivered through a quoted heredoc
// whose EOF marker contains underscores. base64's alphabet is [A-Za-z0-9+/=]
// plus newlines, so the body can never contain the marker and can never close
// the heredoc early or inject a command — the payload is never itself on the
// command line and is never an argv element. The temp file lives in the same
// directory as the target, so the final mv is a true atomic rename, and the
// existing file is only ever replaced wholesale (never half-written).
export async function writeFileAtomic(path, text) {
  const b64 = btoa(unescape(encodeURIComponent(text))); // UTF-8 safe
  const rand = Math.random().toString(36).slice(2);
  const marker = "TEESIM_EOF_" + rand; // underscores => impossible in base64
  const tmp = DIR + "/.write.tmp." + rand;
  const script =
    "base64 -d > " + q(tmp) + " <<'" + marker + "' && " +
    "mv -f " + q(tmp) + " " + q(path) + " && chmod 0644 " + q(path) + "\n" +
    b64 + "\n" + marker + "\n";
  const r = await exec(script);
  return r.errno === 0 ? { ok: true } : { ok: false, error: r.stderr || "write failed" };
}

// Rename a file. Both paths are argv elements, so run() quotes them and mv only
// ever sees two inert operands — a name can never become a flag or a command.
export async function renameFile(from, to) {
  const r = await run(["mv", from, to]);
  return r.errno === 0 ? { ok: true } : { ok: false, error: r.stderr || "rename failed" };
}

// Remove a file. -f so a missing target is not an error; the path is a quoted
// argv element, never interpolated.
export async function deleteFile(path) {
  const r = await run(["rm", "-f", path]);
  return r.errno === 0 ? { ok: true } : { ok: false, error: r.stderr || "delete failed" };
}
