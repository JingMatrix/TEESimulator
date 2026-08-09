// Nested get/set on plain objects addressed by a path array (e.g. ["patchLevel",
// "system"]). This is the single implementation of a pattern the schema, the
// validator, the config view, and the config controller all need — previously
// each kept its own copy.
//
// Pure: no DOM, no I/O, no imports. Keeping it here means the domain layer stays
// unit-testable device-free.

// Read the value at a nested path; undefined if any hop along the way is missing
// or not an object.
export function getPath(obj, path) {
  let node = obj;
  for (const k of path) {
    if (node == null || typeof node !== "object") return undefined;
    node = node[k];
  }
  return node;
}

// Write value at a nested path, creating intermediate objects as needed. Returns
// the mutated root for convenience.
export function setPath(obj, path, value) {
  let node = obj;
  for (let i = 0; i < path.length - 1; i++) {
    if (typeof node[path[i]] !== "object" || node[path[i]] === null) node[path[i]] = {};
    node = node[path[i]];
  }
  node[path[path.length - 1]] = value;
  return obj;
}
