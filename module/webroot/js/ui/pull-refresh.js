// Pull-to-refresh for a document-scrolled screen: drag down from the very top past a threshold to
// run onRefresh(). Vanilla touch events, no library. It only claims the gesture while genuinely
// pulling from scrollTop 0, so ordinary scrolling is untouched; the host also sets
// `overscroll-behavior-y: contain` so the browser's own pull-to-refresh never competes.
//
// The spinner is a fixed element (added once), so a screen re-render — which replaces the mount's
// children — never removes it. Listeners live on the persistent <section> mount, which stays put.

const THRESHOLD = 64; // px of pull (after resistance) that commits a refresh
const MAX = 92; // clamp the pull travel
const RESIST = 0.5; // the drag feels heavier than 1:1

export function attachPullToRefresh(screen, onRefresh) {
  const dot = document.createElement("div");
  dot.className = "ptr";
  dot.appendChild(document.createElement("div")).className = "ptr-spin";
  document.body.appendChild(dot);

  const scroller = () => document.scrollingElement || document.documentElement;
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

  screen.addEventListener(
    "touchstart",
    (e) => {
      pulling = false;
      if (busy || e.touches.length !== 1 || scroller().scrollTop > 0) return;
      startY = e.touches[0].clientY;
      pulling = true;
      dist = 0;
      dot.style.transition = "none"; // follow the finger without lag
    },
    { passive: true },
  );

  screen.addEventListener(
    "touchmove",
    (e) => {
      if (!pulling) return;
      const dy = e.touches[0].clientY - startY;
      if (dy <= 0 || scroller().scrollTop > 0) {
        relax();
        return;
      }
      e.preventDefault(); // we own this drag now — suppress native scroll/refresh
      dist = Math.min(dy * RESIST, MAX);
      place(dist, Math.min(dist / THRESHOLD, 1));
      dot.classList.toggle("ready", dist >= THRESHOLD);
    },
    { passive: false },
  );

  const end = () => {
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

  screen.addEventListener("touchend", end, { passive: true });
  screen.addEventListener("touchcancel", relax, { passive: true });
}
