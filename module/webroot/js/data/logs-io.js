// Data seam for the Logs panel's Save action: the module version for the default filename, read from
// the daemon's /status (the same transport the rest of the UI uses) rather than a separate root-bridge
// read of module.prop. The file write itself is a browser download (Save works in this WebView).
// Controllers import data/*.

import { keyAdmin } from "./keyadmin.js";

// The installed module's version string, e.g. "v4.0 (17-0375393-debug)", from the daemon /status.
// "" when the daemon is unreachable.
export async function moduleVersion() {
  try {
    const st = await keyAdmin("status");
    const v = (st && st.version) || "";
    console.log("[logs-io] module version from /status: %o", v);
    return v;
  } catch (e) {
    console.error("[logs-io] moduleVersion failed:", e);
    return "";
  }
}
