package org.matrix.teesim

import org.json.JSONObject

/**
 * The user's edits to the harvest override layer, persisted at [Const.overridesFile]. This is a flat
 * `{ field: value }` map in the machine form the daemon merges — the level integer, "true"/"false", the
 * id string, or 64 hex chars for a boot key/hash. An empty value on a supplemented id declines it.
 *
 * The captured harvest ([Const.harvestedFile]) stays frozen and honest; this is the ONLY place a user's
 * chosen value lives, so an edit survives a re-harvest. The WebUI writes it atomically through the same
 * shell bridge as config.json, so the DATA_DIR FileObserver picks the change up and App.resolveAndPush
 * re-merges + re-pushes. [Harvester.applyUserOverrides] is what actually validates and layers these on.
 */
object OverrideStore {

    /** The persisted user overrides, or empty when the file is absent/unreadable/malformed. Never throws:
     *  a broken overrides.json must not take the daemon's push path down — it just means "no user edits". */
    fun load(): Map<String, String> {
        val f = Const.overridesFile
        if (!f.exists()) return emptyMap()
        return try {
            val o = JSONObject(f.readText())
            val m = LinkedHashMap<String, String>()
            for (k in o.keys()) m[k] = o.optString(k, "")
            SystemLogger.info("Overrides loaded: ${m.keys.joinToString(",").ifEmpty { "(none)" }}")
            m
        } catch (e: Exception) {
            SystemLogger.warning("Could not read overrides.json; ignoring user overrides", e)
            emptyMap()
        }
    }
}
