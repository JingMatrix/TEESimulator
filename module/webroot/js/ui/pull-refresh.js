// Pull-to-refresh for a scrolled surface: drag down from the very top past a threshold to run
// onRefresh(). Vanilla touch events, no library. It only claims the gesture while genuinely pulling
// from scrollTop 0, so ordinary scrolling is untouched; the host also sets
// `overscroll-behavior-y: contain` so the browser's own pull-to-refresh never competes.
//
// By default it watches the document scroller (the resting screens are document-scrolled). Pass
// opts.scroller to bind an inner overflow container instead (e.g. the keybox inspector's .drill-body,
// which scrolls inside a fixed overlay). opts.zIndex lifts the spinner above that overlay.
//
// The spinner is a fixed element (added once), so a screen re-render — which replaces the mount's
// children — never removes it. attachPullToRefresh returns a detach() that removes the spinner and
// listeners; call it when the surface goes away (an overlay close) so the fixed dot doesn't leak.

const THRESHOLD = 64; // px of pull (after resistance) that commits a refresh
const MAX = 92; // clamp the pull travel
const RESIST = 0.5; // the drag feels heavier than 1:1

export function attachPullToRefresh(screen, onRefresh, opts = {}) {
  const dot = document.createElement("div");
  dot.className = "ptr";
  dot.appendChild(document.createElement("div")).className = "ptr-spin";
  if (opts.zIndex) dot.style.zIndex = String(opts.zIndex);
  document.body.appendChild(dot);

  const scrollTop = () =>
    opts.scroller ? opts.scroller.scrollTop : (document.scrollingElement || document.documentElement).scrollTop;
  const place = (d, op) => {
    dot.style.transform = `translateX(-50%) translateY(${d}px)`;
    dot.style.opacity = String(op);
  };

  let startY = 0;
  let pulling = false;
  let dist = 0;
  let busy = false;

  const relax = () => {
    pulling = false;
    dist = 0;
    dot.style.transition = "";
    dot.classList.remove("ready");
    place(0, 0);
  };

  const onStart = (e) => {
    pulling = false;
    if (busy || e.touches.length !== 1 || scrollTop() > 0) return;
    startY = e.touches[0].clientY;
    pulling = true;
    dist = 0;
    dot.style.transition = "none"; // follow the finger without lag
  };

  const onMove = (e) => {
    if (!pulling) return;
    const dy = e.touches[0].clientY - startY;
    if (dy <= 0 || scrollTop() > 0) {
      relax();
      return;
    }
    e.preventDefault(); // we own this drag now — suppress native scroll/refresh
    dist = Math.min(dy * RESIST, MAX);
    place(dist, Math.min(dist / THRESHOLD, 1));
    dot.classList.toggle("ready", dist >= THRESHOLD);
  };

  const onEnd = () => {
    if (!pulling) return;
    pulling = false;
    dot.style.transition = "";
    if (dist < THRESHOLD || busy) {
      relax();
      return;
    }
    busy = true;
    dot.classList.remove("ready");
    dot.classList.add("busy");
    place(THRESHOLD * 0.75, 1);
    Promise.resolve()
      .then(onRefresh)
      .finally(() => {
        busy = false;
        dot.classList.remove("busy");
        dot.style.transition = "";
        place(0, 0);
      });
  };

  screen.addEventListener("touchstart", onStart, { passive: true });
  screen.addEventListener("touchmove", onMove, { passive: false });
  screen.addEventListener("touchend", onEnd, { passive: true });
  screen.addEventListener("touchcancel", relax, { passive: true });

  return () => {
    screen.removeEventListener("touchstart", onStart);
    screen.removeEventListener("touchmove", onMove);
    screen.removeEventListener("touchend", onEnd);
    screen.removeEventListener("touchcancel", relax);
    dot.remove();
  };
}
