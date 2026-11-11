package org.matrix.teesim

import java.io.File
import org.json.JSONObject

/**
 * What this device's own system properties read before a profile overwrote them, at
 * [Const.propsFile]: `{ "bootId": "<kernel boot id>", "saved": { "<property>": "<its value>" } }`.
 *
 * A profile that applies its properties ([ConfigStore.ProfileConfig.applyProperties]) writes the
 * values it attests over the device's. Two things then need the originals back. The daemon reads
 * several of those same properties when it harvests — a leaf that carries no device ids is
 * supplemented from them — so a daemon restarted inside one boot, which a hot install does, would
 * otherwise capture our own spoof and record it as what this device is. And a profile that stops
 * applying, or stops naming a value, has to leave the property as it found it.
 *
 * The file is scoped to one boot. A `resetprop` lives in memory only, so every property is the
 * device's own again after a reboot and a stored original from a previous boot would be a stale
 * value to write back; a mismatched boot id therefore discards the file unread. The boot id comes
 * from the kernel ([BOOT_ID_FILE]), which is a fresh random value per boot.
 *
 * Not internally locked: every call is on the App monitor (`resolveAndPush` and daemon start), so
 * access is already serialized.
 */
object PropStore {

    private val BOOT_ID_FILE = File("/proc/sys/kernel/random/boot_id")

    /**
     * The kernel's id for this boot, or empty when it cannot be read (the file is then unusable).
     */
    private fun bootId(): String =
        try {
            BOOT_ID_FILE.readText().trim()
        } catch (e: Exception) {
            // Unreadable: the file is then taken at face value rather than discarded. Its entries
            // are this device's own values, so restoring them a boot late is at worst a no-op.
            SystemLogger.warning("PropStore: cannot read the kernel boot id: ${e.message}")
            ""
        }

    /**
     * The saved originals for THIS boot ({ property: value-before-we-wrote-it }), or empty when the
     * file is absent, unreadable, malformed, or written in an earlier boot. An entry's value is the
     * property's exact text at the moment we first overwrote it; an empty string means it was unset
     * and a restore deletes it rather than writing an empty value.
     */
    fun saved(): Map<String, String> {
        val f = Const.propsFile
        if (!f.exists()) return emptyMap()
        return try {
            val root = JSONObject(f.readText())
            val boot = bootId()
            if (boot.isNotEmpty() && root.optString("bootId") != boot) {
                // A previous boot's file: a resetprop did not survive the reboot, so every
                // property is the device's own again and a stored original is at best a repeat of
                // what is already there -- at worst a value an OTA has since moved on from.
                SystemLogger.info("PropStore: props.json is from an earlier boot; discarding it")
                f.delete()
                return emptyMap()
            }
            val saved = root.optJSONObject("saved") ?: JSONObject()
            val m = LinkedHashMap<String, String>()
            for (k in saved.keys()) m[k] = saved.optString(k, "")
            m
        } catch (e: Exception) {
            SystemLogger.warning("PropStore: cannot read props.json; ignoring saved originals", e)
            emptyMap()
        }
    }

    /**
     * Replace the store with exactly [originals] ({ property: value-before-we-wrote-it }) — the set
     * of properties the daemon is now responsible for putting back. One write per push rather than
     * one per property, and no write at all when nothing changed, which is the steady state.
     */
    fun keep(originals: Map<String, String>) {
        val now = saved()
        if (now == originals) return
        writeAll(originals)
        val added = originals.keys - now.keys
        val dropped = now.keys - originals.keys
        if (added.isNotEmpty())
            SystemLogger.info(
                "PropStore: remembering this device's own " +
                    added.joinToString(" ") { "$it='${originals[it]?.ifEmpty { "unset" }}'" }
            )
        if (dropped.isNotEmpty())
            SystemLogger.info("PropStore: no longer holding ${dropped.joinToString(" ")}")
    }

    /**
     * Put every saved property back to the device's own value and empty the store. Returns the
     * names restored, which is empty in the ordinary case of a daemon that never wrote one. Called
     * before the harvest, so the capture reads this device rather than the last run's spoof.
     */
    fun restoreAll(): List<String> {
        val m = saved()
        if (m.isEmpty()) return emptyList()
        val restored = ArrayList<String>()
        for ((name, original) in m) {
            val ok = if (original.isEmpty()) SysProp.delete(name) else SysProp.set(name, original)
            if (ok) restored.add(name)
        }
        // Only what was actually put back is forgotten: a property whose restore failed is still
        // carrying our value, and the store is the only record of what it should read.
        writeAll(m.filterKeys { it !in restored })
        SystemLogger.info(
            "PropStore: restored ${restored.size}/${m.size} spoofed properties to this device's own: " +
                restored.joinToString(" ")
        )
        return restored
    }

    /**
     * Overwrite the whole file atomically (temp + rename) so a crash mid-write can never leave a
     * torn props.json. An empty map removes the file: no saved original is the resting state, and
     * an absent file says so without a boot id to interpret. Never throws — a failed write is
     * logged, and the live properties are already what they should be.
     */
    private fun writeAll(originals: Map<String, String>) {
        val f = Const.propsFile
        try {
            if (originals.isEmpty()) {
                f.delete()
                return
            }
            val saved = JSONObject()
            for ((k, v) in originals) saved.put(k, v)
            val root = JSONObject().put("bootId", bootId()).put("saved", saved)
            val tmp = File(f.parentFile, "${f.name}.tmp")
            tmp.writeText(root.toString(2) + "\n")
            if (!tmp.renameTo(f)) {
                f.writeText(root.toString(2) + "\n")
                tmp.delete()
            }
        } catch (e: Exception) {
            SystemLogger.warning(
                "PropStore: cannot persist props.json; this device's own property values may not " +
                    "be restored before the next harvest",
                e,
            )
        }
    }
}
