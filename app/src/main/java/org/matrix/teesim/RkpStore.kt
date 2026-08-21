package org.matrix.teesim

import java.io.File
import org.json.JSONObject

/**
 * The user's persisted Remote Key Provisioning knobs, at [Const.rkpFile]. A flat `{ property: "true"/"false" }`
 * map keyed by the real system-property name (e.g. `remote_provisioning.tee.rkp_only`). The daemon owns both
 * ends: [App.setRkpKnob] writes it (live `resetprop` + this store, atomically) and [App.applyRkpProps] re-forces
 * it at boot, so the file always mirrors what is actually on the device.
 *
 * The point of persisting is the two `remote_provisioning.*.rkp_only` props: they are plain (not `persist.*`),
 * so a live write reverts to the vendor default on reboot — and a device can ship them `true` in a `.prop`
 * that init re-applies every boot (#236). `…enable_rkpd` is `persist.device_config` and already survives on its
 * own; re-forcing it is a harmless no-op.
 *
 * Not internally locked: every read ([load]) and write ([save]) happens on the App monitor (`resolveAndPush`
 * and `setRkpKnob` are both `@Synchronized`), so access is already serialized and the two can never interleave.
 */
object RkpStore {

    /** The only property names we will ever force or persist — a hostile/stale key in rkp.json is ignored,
     *  so [App.applyRkpProps] can never be steered to set an arbitrary property. Mirrors the WebUI's list. */
    val KNOWN =
        setOf(
            "remote_provisioning.tee.rkp_only",
            "remote_provisioning.strongbox.rkp_only",
            "persist.device_config.remote_key_provisioning_native.enable_rkpd",
        )

    /** The persisted knobs, or empty when the file is absent/unreadable/malformed. Never throws: a broken
     *  rkp.json must not take the daemon's push path down — it just means "no persisted RKP choices". Keys
     *  outside [KNOWN] are dropped on read, so a stale/hand-edited entry can never reach [App.applyRkpProps]. */
    fun load(): Map<String, String> {
        val f = Const.rkpFile
        if (!f.exists()) return emptyMap()
        return try {
            val o = JSONObject(f.readText())
            val m = LinkedHashMap<String, String>()
            for (k in o.keys()) if (k in KNOWN) m[k] = o.optString(k, "")
            SystemLogger.info("RKP knobs loaded: ${m.entries.joinToString(",") { "${it.key}=${it.value}" }.ifEmpty { "(none)" }}")
            m
        } catch (e: Exception) {
            SystemLogger.warning("Could not read rkp.json; ignoring persisted RKP knobs", e)
            emptyMap()
        }
    }

    /**
     * Record one knob's chosen value, preserving the others. Read-modify-write of the whole file, written
     * atomically (temp + rename) so a crash mid-write can never leave a torn rkp.json. Called only from
     * [App.setRkpKnob], after the live `resetprop` succeeded, so the file mirrors the live property. Rejects
     * a name outside [KNOWN] rather than persist something [load] would just drop. Never throws — a failed
     * persist is logged and leaves the live value in place (it simply won't survive the next reboot).
     */
    fun save(name: String, value: String) {
        if (name !in KNOWN) {
            SystemLogger.warning("Refusing to persist unknown RKP knob '$name'")
            return
        }
        try {
            val current = LinkedHashMap(load())
            current[name] = value
            val o = JSONObject()
            for ((k, v) in current) o.put(k, v)
            val f = Const.rkpFile
            val tmp = File(f.parentFile, "${f.name}.tmp")
            tmp.writeText(o.toString(2) + "\n")
            if (!tmp.renameTo(f)) {
                tmp.copyTo(f, overwrite = true)
                tmp.delete()
            }
            SystemLogger.info("RKP knob persisted: $name=$value")
        } catch (e: Exception) {
            SystemLogger.warning("Could not persist RKP knob $name; it will not survive a reboot", e)
        }
    }
}
