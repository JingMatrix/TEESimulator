package org.matrix.teesim

import android.os.FileObserver
import java.io.File
import org.json.JSONObject

/**
 * Reads, validates and watches [Const.configFile]. The schema is DESIGN.md "config.json
 * (daemon-owned)". Validation failures throw [ConfigException]; the caller keeps the last-good
 * config on failure.
 */
object ConfigStore {

    class ConfigException(message: String) : Exception(message)

    /** One profile as written by the WebUI, before resolution against the device. */
    data class ProfileConfig(
        val id: String,
        val keybox: String, // relative to Const.DATA_DIR
        val patchSystem: String,
        val patchVendor: String,
        val patchBoot: String,
        val osVersion: String, // system_property | "16" | "16.0.0" | "160000"
        val brand: String,
        val device: String,
        val product: String,
        val manufacturer: String,
        val model: String,
        val serial: String,
        val imei: String,
        val meid: String,
        val imei2: String,
        val apps: List<String>,
    )

    data class Config(val version: Int, val profiles: List<ProfileConfig>)

    /** Parse and validate the on-disk config. Throws [ConfigException] if invalid. */
    fun load(): Config {
        val f = Const.configFile
        if (!f.exists()) throw ConfigException("config.json not found at ${f.absolutePath}")

        val root =
            try {
                JSONObject(f.readText())
            } catch (e: Exception) {
                throw ConfigException("config.json is not valid JSON: ${e.message}")
            }

        val version = root.optInt("version", 0)
        if (version != 1) throw ConfigException("unsupported config version $version (expected 1)")

        val profilesObj =
            root.optJSONObject("profiles")
                ?: throw ConfigException("config.json has no \"profiles\" object")
        if (profilesObj.length() == 0) throw ConfigException("config.json has no profiles")

        val seenApps = HashMap<String, String>() // package -> owning profile id
        val profiles = ArrayList<ProfileConfig>()

        val ids = profilesObj.keys()
        while (ids.hasNext()) {
            val id = ids.next()
            val p = profilesObj.getJSONObject(id)

            val keybox = p.optString("keybox", "").trim()
            if (keybox.isEmpty()) throw ConfigException("profile '$id' has no keybox")
            val keyboxFile = File(Const.DATA_DIR, keybox)
            if (!keyboxFile.isFile)
                throw ConfigException("profile '$id' keybox not found: ${keyboxFile.absolutePath}")

            val patch = p.optJSONObject("patchLevel") ?: JSONObject()
            val apps =
                p.optJSONArray("apps")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it).trim() }
                } ?: emptyList()
            if (apps.isEmpty()) throw ConfigException("profile '$id' has no apps")
            for (pkg in apps) {
                val prev = seenApps.put(pkg, id)
                if (prev != null && prev != id)
                    throw ConfigException(
                        "package '$pkg' appears in both profile '$prev' and '$id' " +
                            "(routing requires one profile per package)"
                    )
            }

            profiles.add(
                ProfileConfig(
                    id = id,
                    keybox = keybox,
                    // Defaults for an omitted field mirror the shipped config: a current-month system
                    // patch and the conventional YYYY-MM-05 vendor/boot patch; an absent osVersion is
                    // left empty (reuse the harvested value).
                    patchSystem = patch.optString("system", "today"),
                    patchVendor = patch.optString("vendor", "YYYY-MM-05"),
                    patchBoot = patch.optString("boot", "YYYY-MM-05"),
                    osVersion =
                        p.opt("osVersion")?.toString()?.trim().takeUnless { it.isNullOrEmpty() }
                            ?: "",
                    brand = p.optString("brand", ""),
                    device = p.optString("device", ""),
                    product = p.optString("product", ""),
                    manufacturer = p.optString("manufacturer", ""),
                    model = p.optString("model", ""),
                    serial = p.optString("serial", ""),
                    imei = p.optString("imei", ""),
                    meid = p.optString("meid", ""),
                    imei2 = p.optString("imei2", ""),
                    apps = apps,
                )
            )
        }
        return Config(version, profiles)
    }

    private var observer: FileObserver? = null

    /**
     * Watch the data dir for config.json / keybox changes and invoke [onChange]. Uses the
     * directory-level FileObserver (editors write via a temp file + rename).
     */
    fun watch(onChange: () -> Unit) {
        File(Const.DATA_DIR).mkdirs()
        val mask = FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO or FileObserver.DELETE
        observer =
            object : FileObserver(File(Const.DATA_DIR), mask) {
                override fun onEvent(event: Int, path: String?) {
                    path ?: return
                    if (path == "config.json" || path.endsWith(".xml")) {
                        SystemLogger.info("Config change detected: $path")
                        onChange()
                    }
                }
            }
        observer?.startWatching()
        SystemLogger.info("Watching ${Const.DATA_DIR} for config/keybox changes")
    }
}
