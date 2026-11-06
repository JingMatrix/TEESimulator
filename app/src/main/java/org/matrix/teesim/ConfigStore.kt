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

    // The accepted apps[] entry shapes: a package name (the app as installed for the primary user),
    // the same name suffixed with @N for Android user N (a work profile or a secondary user), or
    // the advanced raw-uid token uid:N.
    private val PKG_RE = Regex("^[A-Za-z0-9_.]+(@\\d+)?$")
    private val UID_RE = Regex("^uid:\\d+$")

    /** One profile as written by the WebUI, before resolution against the device. */
    data class ProfileConfig(
        val id: String,
        val keybox: String, // relative to Const.DATA_DIR
        // An optional SECOND keybox for this profile, one provisioned for StrongBox, so that level
        // signs with a batch certificate of its own. Empty when the profile has none, and its
        // StrongBox level then shares [keybox] — which a verifier can tell from real hardware.
        val keyboxStrongBox: String,
        val mode: String, // "patch" | "generation"
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
        // When true, the profile ALSO targets every installed user app (uid >= first app uid) that
        // no OTHER profile claims — including apps installed later, since the daemon re-resolves on
        // each package change. At most one profile may set this (checked below); it lets the apps
        // list be empty, the auto set covering it.
        val autoIncludeNewApps: Boolean,
    )

    /**
     * The device-wide StrongBox policy, from config.json's top-level `"strongBox"` object.
     *
     * One decision: whether to present StrongBox as broken. A real device's two security levels are
     * separately provisioned secure elements with their own batch keys, and a batch certificate
     * names the level it belongs to, so serving StrongBox from a keybox provisioned for the TEE
     * leaves a certificate whose issuer names the TEE while the record inside it says StrongBox.
     * A profile with no StrongBox keybox of its own is in exactly that position; forcing the level
     * broken takes it off the table for every app instead.
     *
     * [forceBroken] overrides every profile's StrongBox keybox — the point is that no target app
     * reaches the level at all.
     */
    data class StrongBox(val forceBroken: Boolean)

    data class Config(
        val version: Int,
        val strongBox: StrongBox,
        val profiles: List<ProfileConfig>,
    )

    /** The default when config.json names no `"strongBox"` object: what the module always did. */
    private val STRONGBOX_DEFAULT = StrongBox(forceBroken = false)

    private val KEYBOX_RE = Regex("^[A-Za-z0-9._-]+\\.xml$")

    /**
     * Read the device-wide StrongBox setting without validating the rest of the config. Never
     * throws — a missing or broken config.json just means the default — so the read-only status
     * endpoint can report the setting even while the config as a whole is being rejected.
     */
    fun strongBoxSetting(): StrongBox =
        try {
            parseStrongBox(JSONObject(Const.configFile.readText()))
        } catch (e: Exception) {
            STRONGBOX_DEFAULT
        }

    private fun parseStrongBox(root: JSONObject): StrongBox {
        val o = root.optJSONObject("strongBox") ?: return STRONGBOX_DEFAULT
        return StrongBox(forceBroken = o.optBoolean("forceBroken", false))
    }

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

        val strongBox = parseStrongBox(root)

        val profilesObj =
            root.optJSONObject("profiles")
                ?: throw ConfigException("config.json has no \"profiles\" object")
        if (profilesObj.length() == 0) throw ConfigException("config.json has no profiles")

        val seenApps =
            HashMap<String, String>() // apps[] entry (package or uid:N) -> owning profile id
        val seenUids =
            HashMap<Int, String>() // effective caller uid -> owning profile id (cross-check)
        var autoIncludeProfiles =
            0 // how many profiles set autoIncludeNewApps (at most one allowed)
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

            // The profile's optional StrongBox keybox: a keybox provisioned for StrongBox, so that
            // level signs with its own batch certificate instead of the TEE one above. It must not
            // be the profile's own keybox — one keybox signing both levels is the very thing it
            // exists to replace.
            val keyboxStrongBox = p.optString("keyboxStrongBox", "").trim()
            if (keyboxStrongBox.isNotEmpty()) {
                if (!KEYBOX_RE.matches(keyboxStrongBox))
                    throw ConfigException(
                        "profile '$id' keyboxStrongBox '$keyboxStrongBox' is not a plain *.xml " +
                            "file name"
                    )
                val sbFile = File(Const.DATA_DIR, keyboxStrongBox)
                if (!sbFile.isFile)
                    throw ConfigException(
                        "profile '$id' keyboxStrongBox not found: ${sbFile.absolutePath}"
                    )
                if (keyboxStrongBox == keybox)
                    throw ConfigException(
                        "profile '$id' names the same file as both keybox and keyboxStrongBox; one " +
                            "keybox signing both security levels is what a StrongBox keybox exists " +
                            "to replace"
                    )
            }

            // Operation mode: patch (re-sign the real hardware attestation) or generation (mint the
            // whole key). Defaults to patch; a level whose hardware is unavailable still falls back
            // to generation at resolve time.
            val mode = p.optString("mode", "patch").trim().lowercase()
            if (mode != "patch" && mode != "generation")
                throw ConfigException("profile '$id' has invalid mode '$mode' (patch | generation)")

            val patch = p.optJSONObject("patchLevel") ?: JSONObject()
            val apps =
                p.optJSONArray("apps")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it).trim() }
                } ?: emptyList()

            // A profile that auto-includes every user app may legitimately name no apps of its own;
            // otherwise it must target at least one, or it routes nothing.
            val autoIncludeNewApps = p.optBoolean("autoIncludeNewApps", false)
            if (autoIncludeNewApps) autoIncludeProfiles++
            if (autoIncludeProfiles > 1)
                throw ConfigException(
                    "profile '$id' also sets autoIncludeNewApps, but at most one profile may " +
                        "auto-include new apps (two would both claim every unowned user app)"
                )
            if (apps.isEmpty() && !autoIncludeNewApps)
                throw ConfigException(
                    "profile '$id' has no apps (and does not auto-include new apps)"
                )

            // Each apps[] entry is a package name, a pkg@user name, or the advanced raw-uid token
            // uid:N. Validate the shape here so a typo can't silently slip through to routing, and
            // keep the per-entry uniqueness (a package/user pair OR a uid token may live in only
            // one profile — the router needs exactly one owner per caller).
            for (entry in apps) {
                if (PKG_RE.matches(entry)) {
                    // a package name, optionally naming the user it lives in — nothing further to
                    // validate
                } else if (UID_RE.matches(entry)) {
                    val n = entry.substring(4).toIntOrNull()
                    if (n == null || n < 0)
                        throw ConfigException(
                            "profile '$id' app entry '$entry' is not a valid uid:N token (N must be a non-negative integer)"
                        )
                } else {
                    throw ConfigException(
                        "profile '$id' app entry '$entry' is neither a package name (optionally " +
                            "@<user>) nor a uid:N token"
                    )
                }
                val prev = seenApps.put(entry, id)
                if (prev != null && prev != id)
                    throw ConfigException(
                        "app entry '$entry' appears in both profile '$prev' and '$id' " +
                            "(routing requires one profile per package/uid)"
                    )
                // The literal-string check above misses two entries that DIFFER textually but
                // resolve to the SAME caller uid — a package vs a uid:N token (com.foo vs
                // uid:10123), or two packages that share a uid (a sharedUserId pair). Both would
                // put two profiles' keyboxes on one caller (last-writer-wins in routing). Reject on
                // the effective uid too, when it resolves. Scope.parse is what splits pkg@user, so
                // the uid compared here is the per-user one: the same package in two users is two
                // callers and may legitimately sit in two profiles.
                val uid =
                    when {
                        UID_RE.matches(entry) -> entry.substring(4).toIntOrNull() ?: -1
                        else -> Scope.parse(entry).uid
                    }
                if (uid >= 0) {
                    val prevUid = seenUids.put(uid, id)
                    if (prevUid != null && prevUid != id)
                        throw ConfigException(
                            "app entry '$entry' resolves to uid $uid, already claimed by profile " +
                                "'$prevUid' (one profile per caller uid)"
                        )
                }
            }

            profiles.add(
                ProfileConfig(
                    id = id,
                    keybox = keybox,
                    keyboxStrongBox = keyboxStrongBox,
                    mode = mode,
                    // Defaults for an omitted field mirror the shipped config: a current-month
                    // system patch and the conventional YYYY-MM-05 vendor/boot patch; an absent
                    // osVersion is left empty (reuse the harvested value).
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
                    autoIncludeNewApps = autoIncludeNewApps,
                )
            )
        }
        return Config(version, strongBox, profiles)
    }

    private var observer: FileObserver? = null

    /**
     * Watch the data dir for config.json / keybox / overrides.json changes and invoke [onChange].
     * Uses the directory-level FileObserver (editors write via a temp file + rename).
     */
    fun watch(onChange: () -> Unit) {
        File(Const.DATA_DIR).mkdirs()
        val mask = FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO or FileObserver.DELETE
        observer =
            object : FileObserver(File(Const.DATA_DIR), mask) {
                override fun onEvent(event: Int, path: String?) {
                    path ?: return
                    if (
                        path == "config.json" || path == "overrides.json" || path.endsWith(".xml")
                    ) {
                        SystemLogger.info("ConfigStore: change detected in $path")
                        onChange()
                    }
                }
            }
        observer?.startWatching()
        SystemLogger.info(
            "ConfigStore: watching ${Const.DATA_DIR} for config/keybox/overrides changes"
        )
    }
}
