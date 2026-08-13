package org.matrix.teesim

/**
 * Best-effort setter for read-only (`ro.*`) system properties. Plain `setprop` cannot touch `ro.*`, so
 * this shells out to Magisk's `resetprop -n` (the `-n` skips re-triggering property_service, which is
 * what lets a read-only prop be overwritten). Used when a user overrides the verified-boot key/hash so
 * the matching `ro.boot.vbmeta.*` property reflects the spoofed value for anything that reads it directly.
 *
 * Never throws — a device without resetprop just leaves the property as-is, logged. The daemon's own
 * attestation does not depend on these props (it uses the pushed config); this only keeps the visible
 * system state consistent for other integrity readers.
 */
object SysProp {

    /** Overwrite [name] with [value] via the first resetprop invocation that succeeds. Returns whether
     *  any candidate reported success. Idempotent — safe to call on every push. */
    fun set(name: String, value: String): Boolean {
        val candidates =
            listOf(
                listOf("resetprop", "-n", name, value),
                listOf("magisk", "resetprop", "-n", name, value),
            )
        for (cmd in candidates) {
            try {
                val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
                val out = p.inputStream.bufferedReader().readText().trim()
                val code = p.waitFor()
                if (code == 0) {
                    SystemLogger.info("SysProp: set $name via '${cmd.first()}'")
                    return true
                }
                SystemLogger.info("SysProp: '${cmd.first()}' exited $code for $name${if (out.isEmpty()) "" else " ($out)"}")
            } catch (e: Exception) {
                SystemLogger.info("SysProp: '${cmd.first()}' unavailable: ${e.javaClass.simpleName}: ${e.message}")
            }
        }
        SystemLogger.warning("SysProp: could not set $name (no working resetprop)")
        return false
    }
}
