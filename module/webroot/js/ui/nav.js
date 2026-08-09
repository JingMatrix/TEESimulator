// The Back-gesture authority — the ONLY module in the app that touches
// window.history. It exists to make Android Back do exactly one of three things,
// never a fourth:
//
//   1. An overlay is open  -> close that one overlay, stay on the current screen.
//   2. Nested overlays     -> close them one level per Back press, innermost first.
//   3. Nothing open        -> the webview exits (the root manager closes the UI).
//
// It can NEVER cycle between the app's five destinations, because destination
// switching (js/app.js) mutates an in-memory variable and mints no history entry.
// With no per-panel history to walk, Back at any resting screen falls through to
// the OS default (pop the single initial entry) = a true exit.
//
// The mechanism: every overlay pushes EXACTLY ONE synthetic history entry when it
// opens and registers a close callback here. The single popstate listener below
// pops the innermost callback and runs it — closing that overlay and nothing else.
// Programmatic dismissal (a Cancel button, a backdrop tap, an X, a finished Save)
// routes through closeOverlay(), which unwinds the same synthetic entry so both a
// hardware Back and an in-UI dismiss travel the ONE code path.
//
// Contract for callers: the `close` you register must remove your DOM and settle
// your promise, and it must NEVER itself call history.back / closeOverlay — that
// would double-pop. popstate is the sole closer; closeOverlay only feeds it.
//
// This module imports nothing (no data/, no bridge/, no DOM builders): it is the
// leaf of the navigation concern.

const stack = []; // { close, closing }, innermost overlay last.

// Open an overlay: record its closer and mint one history entry to consume on Back.
export function pushOverlay(close) {
  stack.push({ close, closing: false });
  history.pushState({ ovl: stack.length }, "");
}

// Dismiss the top overlay programmatically. We do NOT close it here; we unwind our
// synthetic history entry, and the resulting popstate is what actually closes it —
// so a button-press and a hardware-Back are indistinguishable downstream.
//
// Idempotent by design: two dismissals of the same overlay can race before its
// popstate fires (a backdrop tap arriving alongside a Cancel press). We call
// history.back() at most ONCE per overlay by flagging the top entry as `closing`;
// a second call while that entry is still on the stack is a no-op. Without this a
// double history.back() would pop past the overlay's single synthetic entry and
// walk the WebUI away / exit instead of merely closing the overlay.
export function closeOverlay() {
  const top = stack[stack.length - 1];
  if (top && !top.closing) {
    top.closing = true;
    history.back();
  }
}

// Is any overlay currently open? (Used by callers that want to branch on it; the
// Back handling itself never needs to ask.)
export function overlayOpen() {
  return stack.length > 0;
}

// The one and only reaction to Back once an entry has been popped: close the
// innermost overlay. An empty stack means Back already left the base entry and the
// webview is exiting, so there is nothing to do.
window.addEventListener("popstate", () => {
  const top = stack.pop();
  if (top) top.close();
});
