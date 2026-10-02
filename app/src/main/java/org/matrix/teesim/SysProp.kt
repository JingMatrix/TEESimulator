package org.matrix.teesim

/**
 * Best-effort setter for read-only (`ro.*`) system properties. Plain `setprop` cannot touch `ro.*`,
 * so this shells out to Magisk's `resetprop -n` (the `-n` skips re-triggering property_service,
 * which is what lets a read-only prop be overwritten). Used when a user overrides the verified-boot
 * key/hash so the matching `ro.boot.vbmeta.*` property reflects the spoofed value for anything that
 * reads it directly.
 *
 * Never throws — a device without resetprop just leaves the property as-is, logged. The daemon's
 * own attestation does not depend on these props (it uses the pushed config); this only keeps the
 * visible system state consistent for other integrity readers.
 */
object SysProp {

    /**
     * Overwrite [name] with [value] via the first resetprop invocation that succeeds. Returns
     * whether any candidate reported success. Idempotent — safe to call on every push.
     */
    fun set(name: String, value: String): Boolean =
        run(
            "set",
            name,
            listOf(
                listOf("resetprop", "-n", name, value),
                listOf("magisk", "resetprop", "-n", name, value),
            ),
        )

    /**
     * Remove [name] entirely via `resetprop --delete`, so the property reads back as *unset* rather
     * than as a spoofed value. Used for the `remote_provisioning.*.rkp_only` knobs: an absent prop
     * looks like a device that never declared RKP-only enforcement, whereas a flipped `false` on a
     * device that ships `true` is an anomalous value. keystore2 and our hook both treat unset as
     * false, so deletion yields the same keybox path as a `false` set, with a smaller footprint.
     * Returns whether any candidate reported success. Idempotent — deleting an absent prop
     * succeeds.
     */
    fun delete(name: String): Boolean =
        run(
            "delete",
            name,
            listOf(
                listOf("resetprop", "--delete", name),
                listOf("magisk", "resetprop", "--delete", name),
            ),
        )

    /** Run the first candidate argv that exits 0; [verb] labels the action in the logs. */
    private fun run(verb: String, name: String, candidates: List<List<String>>): Boolean {
        for (cmd in candidates) {
            try {
                val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
                val out = p.inputStream.bufferedReader().readText().trim()
                val code = p.waitFor()
                if (code == 0) {
                    SystemLogger.info("SysProp: $verb $name via '${cmd.first()}'")
                    return true
                }
                SystemLogger.info(
                    "SysProp: '${cmd.first()}' exited $code for $verb $name${if (out.isEmpty()) "" else " ($out)"}"
                )
            } catch (e: Exception) {
                SystemLogger.info(
                    "SysProp: '${cmd.first()}' unavailable: ${e.javaClass.simpleName}: ${e.message}"
                )
            }
        }
        SystemLogger.warning("SysProp: could not $verb $name (no working resetprop)")
        return false
    }
}
