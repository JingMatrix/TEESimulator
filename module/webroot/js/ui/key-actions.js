// Presentation metadata for the key panel's action buttons: their labels, where
// each one renders, and destructive styling. This is pure UI data and lives in
// the UI layer on purpose — the data layer (data/keyadmin.js) carries only the
// transport, never button labels or layout.
//
// Add a key action by appending a descriptor here; key-view renders a button per
// entry and routes its `name` through the injected handler. `danger` drives the
// destructive styling.
//   scope: "global" -> in the panel header;  "row" -> on each key row
// Removal is selection-driven (Delete-selected), so its button is rendered inline by
// key-view (its label carries the live count) rather than described here; this table
// holds only the static global actions.
export const KEY_ACTIONS = [
  { name: "refresh", label: "Refresh", scope: "global", danger: false },
];
