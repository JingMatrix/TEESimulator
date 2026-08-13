// Device-free tests for the pure domain layer. Run: `node --test` from
// module/webroot (or `node --test tests/domain.test.mjs`). No jsdom, no ksu
// mock — domain/* imports neither the DOM nor the bridge, which is the whole
// point of keeping it pure.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  emptyProfile, emptyConfig,
  PKG_RE, PROFILE_RE, KEYBOX_RE, PATCH_RE, OSVER_RE, MODE_RE, UID_RE, APP_ENTRY_RE,
} from "../js/domain/schema.js";
import { validateConfig, validateProfile } from "../js/domain/validate.js";

// A minimal profile that should pass: defaults from emptyProfile() + one app.
function validProfile(apps = ["com.example.app"]) {
  const p = emptyProfile();
  p.apps = apps.slice();
  return p;
}
function configWith(profiles) {
  return { version: 1, profiles };
}

test("validateConfig accepts a well-formed config", () => {
  const r = validateConfig(configWith({ pixel: validProfile() }));
  assert.equal(r.ok, true, JSON.stringify(r.errors));
  assert.equal(r.errors.length, 0);
});

test("emptyConfig is valid and JSON round-trips", () => {
  const round = JSON.parse(JSON.stringify(emptyConfig()));
  const r = validateConfig(round);
  assert.equal(r.ok, true);
});

test("emptyProfile JSON round-trips to an equal object", () => {
  const a = emptyProfile();
  const b = JSON.parse(JSON.stringify(a));
  assert.deepEqual(b, a);
  // With one app added it validates cleanly.
  b.apps = ["com.x"];
  assert.equal(validateConfig(configWith({ p: b })).ok, true);
});

test("version must be 1", () => {
  const r = validateConfig({ version: 2, profiles: { p: validProfile() } });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => /version/i.test(e.msg)));
});

test("a non-object config is rejected, not thrown", () => {
  assert.equal(validateConfig(null).ok, false);
  assert.equal(validateConfig([]).ok, false);
  assert.equal(validateConfig("x").ok, false);
});

test("a profile with zero apps is rejected", () => {
  const r = validateConfig(configWith({ p: validProfile([]) }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.profile === "p" && e.field === "apps"));
});

test("a profile missing its keybox is rejected", () => {
  const p = validProfile();
  p.keybox = "";
  const r = validateConfig(configWith({ p }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.profile === "p" && e.field === "keybox"));
});

test("a bad package name is rejected", () => {
  const r = validateConfig(configWith({ p: validProfile(["com.ok", "bad name!"]) }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.field === "apps"));
});

test("an out-of-grammar patch level is rejected", () => {
  const p = validProfile();
  p.patchLevel.system = "2024-1"; // one-digit month: not YYYY-MM
  const r = validateConfig(configWith({ p }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.field === "patchSystem"));
});

test("an impossible patch date is rejected", () => {
  for (const bad of ["2024-13", "2024-00", "2024-01-32", "2024-01-00"]) {
    const p = validProfile();
    p.patchLevel.system = bad;
    const r = validateConfig(configWith({ p }));
    assert.equal(r.ok, false, `expected ${bad} to be rejected`);
    assert.ok(r.errors.some((e) => e.field === "patchSystem"), `expected a patchSystem error for ${bad}`);
  }
});

test("optional identity fields may be left blank", () => {
  const p = validProfile();
  p.brand = ""; p.model = ""; p.imei = ""; // identity is optional
  const r = validateConfig(configWith({ p }));
  assert.equal(r.ok, true, JSON.stringify(r.errors));
});

test("an invalid profile name is rejected", () => {
  assert.ok(validateProfile("has space", validProfile()).some((e) => e.field === "__name"));
  assert.ok(validateProfile("x".repeat(33), validProfile()).some((e) => e.field === "__name"));
  assert.equal(validateProfile("ok-name_1", validProfile()).some((e) => e.field === "__name"), false);
});

test("a package in two profiles is a hard error on BOTH", () => {
  const r = validateConfig(configWith({
    a: validProfile(["com.dup", "com.a"]),
    b: validProfile(["com.dup", "com.b"]),
  }));
  assert.equal(r.ok, false);
  const dupErrs = r.errors.filter((e) => e.field === "apps" && /unique/i.test(e.msg));
  assert.ok(dupErrs.some((e) => e.profile === "a"));
  assert.ok(dupErrs.some((e) => e.profile === "b"));
});

test("a package listed twice in ONE profile is not a cross-profile duplicate", () => {
  const r = validateConfig(configWith({ a: validProfile(["com.dup", "com.dup", "com.a"]) }));
  const dupErrs = r.errors.filter((e) => e.field === "apps" && /unique/i.test(e.msg));
  assert.equal(dupErrs.length, 0, JSON.stringify(dupErrs));
  assert.equal(r.ok, true, JSON.stringify(r.errors));
});

// --- scope: raw-uid tokens -----------------------------------------------
test("a uid: token is accepted as an app entry", () => {
  const r = validateConfig(configWith({ p: validProfile(["com.ok", "uid:10123"]) }));
  assert.equal(r.ok, true, JSON.stringify(r.errors));
});

test("a malformed uid token is rejected", () => {
  for (const bad of ["uid:", "uid:x", "uid: 10", "uid:-1", "uid:10.0"]) {
    const r = validateConfig(configWith({ p: validProfile(["com.ok", bad]) }));
    assert.equal(r.ok, false, `expected ${bad} to be rejected`);
    assert.ok(r.errors.some((e) => e.field === "apps"), `expected an apps error for ${bad}`);
  }
});

test("an empty apps list is invalid", () => {
  const r = validateConfig(configWith({ p: validProfile([]) }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.profile === "p" && e.field === "apps"));
});

// autoIncludeNewApps is gone; a config still carrying it is not rejected for that alone — the
// daemon warns and the key is ignored, so the profile stands or falls on its apps[] like any other.
test("a leftover autoIncludeNewApps key does not affect validation", () => {
  const p = validProfile(["com.a"]);
  p.autoIncludeNewApps = true;
  const r = validateConfig(configWith({ p }));
  assert.equal(r.ok, true, JSON.stringify(r.errors));
});

// --- regex whitelists ----------------------------------------------------
const cases = [
  [PKG_RE, ["com.foo", "com.foo.bar", "a_b.c", "A9._"], ["", "com foo", "com;rm -rf", "com/foo", "com-foo"]],
  [UID_RE, ["uid:0", "uid:10123", "uid:2000"], ["", "uid:", "uid:x", "uid: 10", "uid:-1", "uid:10.0", "10123", "com.foo"]],
  [APP_ENTRY_RE, ["com.foo", "com.foo.bar", "uid:0", "uid:10123"], ["", "uid:", "uid:x", "com foo", "com/foo", "uid:1.0"]],
  [PROFILE_RE, ["pixel", "a-b_c", "x".repeat(32)], ["", "x".repeat(33), "has space", "bad!", "dot.name"]],
  [KEYBOX_RE, ["keybox.xml", "a-b_c.1.xml"], ["keybox", "keybox.XML", "../x.xml", "a b.xml", "keybox.xml.bak"]],
  [PATCH_RE, ["today", "no", "harvested", "system_property", "2024-01", "2024-12", "2024-01-15", "2024-12-31", "YYYY-MM", "YYYY-MM-05", "YYYY-MM-DD"], ["2024", "2024-1", "2024-1-1", "yesterday", "", "2024-00", "2024-13", "2024-01-00", "2024-01-32", "2024-13-01", "MM-05", "YYYY-13-01"]],
  [OSVER_RE, ["harvested", "system_property", "16", "16.0", "16.0.0", "160000"], ["16.0.0.0", "v16", "", "16."]],
  [MODE_RE, ["patch", "generation"], ["", "Patch", "GENERATION", "patched", "gen", "auto"]],
];
for (const [re, good, bad] of cases) {
  test(`regex ${re} accepts its allowed set`, () => {
    for (const g of good) assert.ok(re.test(g), `expected ${re} to accept ${JSON.stringify(g)}`);
  });
  test(`regex ${re} rejects its disallowed set`, () => {
    for (const b of bad) assert.equal(re.test(b), false, `expected ${re} to reject ${JSON.stringify(b)}`);
  });
}
