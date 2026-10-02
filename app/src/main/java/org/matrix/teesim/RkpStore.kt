package org.matrix.teesim

import java.io.File
import org.json.JSONObject

/**
 * The user's persisted RKP-only *delete intents*, at [Const.rkpFile]. A flat `{ property: "<value
 * it had when deleted>" }` map, keyed by the real system-property name (only the two
 * `remote_provisioning.*.rkp_only` knobs). An entry means "the user deleted this property; keep it
 * gone." The stored value is what the property read just before deletion, so a later restore can
 * put exactly that back.
 *
 * The two `rkp_only` props are plain (not `persist.*`) and a device can ship them `true` in a
 * vendor `.prop` that init re-applies every boot (#236), so a deleted prop reappears on the next
 * boot and the intent is what tells the daemon to delete it again. keystore2 and our hook both read
 * an unset prop as false, so the keybox path holds while it is absent. `enable_rkpd` is **not**
 * managed here — it is `persist.device_config` and survives on its own, so the WebUI keeps it as a
 * plain toggle.
 *
 * The daemon owns the file: [App.deleteRkpProp]/[App.restoreRkpProp] write it (live `resetprop` +
 * this store, atomically) and [App.applyRkpDeletions] re-enforces it at boot. Not internally
 * locked: every read ([load]) and write happens on the App monitor (`resolveAndPush`,
 * `deleteRkpProp` and `restoreRkpProp` are all `@Synchronized`), so access is already serialized —
 * except [load] from [KeyAdmin]'s read-only `GET /rkp`, where a dirty read only feeds a UI repaint.
 */
object RkpStore {

    /**
     * The only property names we will ever delete, persist an intent for, or restore — a
     * hostile/stale key in rkp.json is ignored, so [App.applyRkpDeletions] can never be steered to
     * delete an arbitrary property. Mirrors the WebUI's deletable list.
     */
    val KNOWN =
        setOf(
            "remote_provisioning.tee.rkp_only",
            "remote_provisioning.strongbox.rkp_only",
        )

    /**
     * The persisted delete intents ({ property: value-at-deletion }), or empty when the file is
     * absent/unreadable/malformed. Never throws: a broken rkp.json must not take the daemon's push
     * path down — it just means "no delete intents". Keys outside [KNOWN] are dropped on read, so a
     * stale/hand-edited entry can never reach [App.applyRkpDeletions].
     */
    fun load(): Map<String, String> {
        val f = Const.rkpFile
        if (!f.exists()) return emptyMap()
        return try {
            val o = JSONObject(f.readText())
            val m = LinkedHashMap<String, String>()
            for (k in o.keys()) if (k in KNOWN) m[k] = o.optString(k, "")
            SystemLogger.info(
                "RkpStore: loaded delete intents ${m.keys.joinToString(",").ifEmpty { "(none)" }}"
            )
            m
        } catch (e: Exception) {
            SystemLogger.warning("RkpStore: cannot read rkp.json; ignoring delete intents", e)
            emptyMap()
        }
    }

    /**
     * Record a delete intent for [name], remembering [valueAtDeletion] for a faithful restore, and
     * preserving any other intent. Called only from [App.deleteRkpProp], after the live `resetprop
     * --delete` succeeded. Rejects a name outside [KNOWN] rather than persist something [load]
     * would just drop.
     */
    fun recordDelete(name: String, valueAtDeletion: String) {
        if (name !in KNOWN) {
            SystemLogger.warning(
                "RkpStore: refusing to record delete intent for unknown knob '$name'"
            )
            return
        }
        val m = LinkedHashMap(load())
        m[name] = valueAtDeletion
        writeAll(m)
        SystemLogger.info(
            "RkpStore: delete intent recorded $name (was '${valueAtDeletion.ifEmpty { "unset" }}')"
        )
    }

    /**
     * Drop the delete intent for [name] (the user restored it), preserving the others. Called only
     * from [App.restoreRkpProp], after the live `resetprop` put the value back.
     */
    fun clear(name: String) {
        val m = LinkedHashMap(load())
        if (m.remove(name) == null) return
        writeAll(m)
        SystemLogger.info("RkpStore: delete intent cleared $name")
    }

    /**
     * Overwrite the whole file atomically (temp + rename) so a crash mid-write can never leave a
     * torn rkp.json. Never throws — a failed write is logged; the live state is already correct.
     */
    private fun writeAll(intents: Map<String, String>) {
        try {
            val o = JSONObject()
            for ((k, v) in intents) o.put(k, v)
            val f = Const.rkpFile
            val tmp = File(f.parentFile, "${f.name}.tmp")
            tmp.writeText(o.toString(2) + "\n")
            if (!tmp.renameTo(f)) {
                tmp.copyTo(f, overwrite = true)
                tmp.delete()
            }
        } catch (e: Exception) {
            SystemLogger.warning(
                "RkpStore: cannot persist rkp.json; intent may not survive a reboot",
                e,
            )
        }
    }
}
