// The one and only door to the root manager.
//
// KernelSU, APatch and Magisk-WebUIX all expose the same bridge object on the
// page: window.ksu.exec(cmd, optsJson, callbackName) runs a shell command as
// root and then calls window[callbackName](errno, stdout, stderr). This module
// wraps that callback dance in a Promise and is the *only* file in the app that
// is allowed to name window.ksu. Swap the transport here (a different manager,
// a mock for browser testing) and nothing else has to change.

// Is a root bridge actually present? False in a plain browser tab, where every
// exec below resolves to a harmless failure instead of throwing.
export function hasBridge() {
  return !!(window.ksu && window.ksu.exec);
}

// Run one command string as root. Never rejects: a missing bridge or a shell
// error comes back as { errno, stdout, stderr } so callers branch on errno.
export function exec(cmd) {
  return new Promise((resolve) => {
    if (!hasBridge()) {
      console.warn("[ksu] no bridge (window.ksu.exec absent); cmd skipped:", String(cmd).slice(0, 120));
      resolve({ errno: -1, stdout: "", stderr: "no ksu bridge" });
      return;
    }
    // A fresh random global per call: concurrent execs never clobber each other,
    // and the slot is deleted the moment it fires so nothing leaks on window.
    const cb = "cb_" + Math.random().toString(36).slice(2);
    const short = String(cmd).length > 160 ? String(cmd).slice(0, 160) + "…(" + String(cmd).length + "b)" : cmd;
    const t0 = Date.now();
    console.log("[ksu] exec:", short);
    window[cb] = (errno, stdout, stderr) => {
      delete window[cb];
      console.log(
        "[ksu] done errno=%o in %dms stdout=%db stderr=%o",
        errno, Date.now() - t0, (stdout || "").length, stderr || "",
      );
      resolve({ errno, stdout, stderr });
    };
    window.ksu.exec(cmd, "{}", cb);
  });
}
