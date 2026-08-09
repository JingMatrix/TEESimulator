// Pure, DOM-free validators driven entirely off the schema. Every error is hard
// (it blocks Save); there is no warnings tier. Exercised directly by
// tests/domain.test.mjs, which is why nothing here touches the DOM or the bridge.

import {
  FIELDS, KEYBOX_RE, PKG_RE, PROFILE_RE, VERSION,
} from "./schema.js";
import { getPath } from "./path.js";

// Validate one profile in isolation (no cross-profile knowledge here).
// Returns an array of { field, msg }; field matches a descriptor.key, or the
// synthetic "__name" for the profile name itself.
export function validateProfile(name, profile) {
  const errors = [];

  if (!PROFILE_RE.test(name)) {
    errors.push({ field: "__name", msg: "Name must be 1-32 chars: letters, digits, - or _." });
  }
  if (!profile || typeof profile !== "object") {
    errors.push({ field: "__name", msg: "Profile is not an object." });
    return errors;
  }

  for (const f of FIELDS) {
    const value = getPath(profile, f.path);

    if (f.type === "applist") {
      const apps = Array.isArray(value) ? value : [];
      if (f.required && apps.length < 1) {
        errors.push({ field: f.key, msg: "At least one app is required." });
      }
      for (const pkg of apps) {
        if (typeof pkg !== "string" || !PKG_RE.test(pkg)) {
          errors.push({ field: f.key, msg: `Invalid package name: ${pkg}` });
        }
      }
      continue;
    }

    if (f.key === "keybox") {
      if (!value || !KEYBOX_RE.test(value)) {
        errors.push({ field: f.key, msg: "A keybox ending in .xml is required." });
      }
      continue;
    }

    // Generic scalar. Format is checked only when a value is present, so an
    // optional field left blank is fine; presence is a separate, explicit flag.
    if (f.re && value !== undefined && value !== "" && !f.re.test(value)) {
      errors.push({ field: f.key, msg: `Invalid ${f.label.toLowerCase()}: ${value}` });
    }
    if (f.required && (value === undefined || value === "")) {
      errors.push({ field: f.key, msg: `${f.label} is required.` });
    }
  }

  return errors;
}

// Validate the whole config, including the one rule no single profile can see:
// a package may appear in at most one profile (routing is package -> one profile).
// Returns { ok, errors: [{ profile, field, msg }] }.
export function validateConfig(config) {
  const errors = [];

  if (!config || typeof config !== "object" || Array.isArray(config)) {
    return { ok: false, errors: [{ profile: null, field: null, msg: "Config must be an object." }] };
  }
  if (config.version !== VERSION) {
    errors.push({ profile: null, field: null, msg: `Unsupported version (expected ${VERSION}).` });
  }
  const profiles = config.profiles;
  if (!profiles || typeof profiles !== "object" || Array.isArray(profiles)) {
    errors.push({ profile: null, field: null, msg: "Config.profiles must be an object." });
    return { ok: errors.length === 0, errors };
  }

  // Per-profile checks.
  for (const name of Object.keys(profiles)) {
    for (const e of validateProfile(name, profiles[name])) {
      errors.push({ profile: name, field: e.field, msg: e.msg });
    }
  }

  // Cross-profile: which profiles claim each package? Dedup within a profile
  // first (new Set) so a package listed twice in ONE profile is a single claim,
  // not a false cross-profile duplicate.
  const owners = new Map(); // pkg -> [profileName, ...] (distinct profiles)
  for (const name of Object.keys(profiles)) {
    const apps = Array.isArray(profiles[name] && profiles[name].apps) ? profiles[name].apps : [];
    for (const pkg of new Set(apps)) {
      if (!owners.has(pkg)) owners.set(pkg, []);
      owners.get(pkg).push(name);
    }
  }
  for (const [pkg, claimants] of owners) {
    if (claimants.length > 1) {
      for (const name of claimants) {
        errors.push({
          profile: name, field: "apps",
          msg: `Package ${pkg} is claimed by ${claimants.length} profiles; it must be unique.`,
        });
      }
    }
  }

  return { ok: errors.length === 0, errors };
}
