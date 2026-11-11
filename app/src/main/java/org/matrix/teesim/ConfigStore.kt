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
    /** A verified boot hash as a profile may write it: SHA-256, lowercase hex. */
    private val HEX64_RE = Regex("^[0-9a-f]{64}$")

    /** One profile as written by the WebUI, before resolution against the device. */
    data class ProfileConfig(
        val id: String,
        val keybox: String, // relative to Const.DATA_DIR
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
        // The verified boot hash this profile attests, as 64 hex characters, or empty to take the
        // default ([ProfileDefaults]). It is the root of trust AND an input to the TA's
        // key-encryption key, so a profile that changes it re-keys the generation-mode blobs minted
        // under the previous one — they return when it does, and patch mode never has ours at all.
        val verifiedBootHash: String,
        val apps: List<String>,
        // When true, the profile ALSO targets every installed user app (uid >= first app uid) that
        // no OTHER profile claims — including apps installed later, since the daemon re-resolves on
        // each package change. At most one profile may set this (checked below); it lets the apps
        // list be empty, the auto set covering it.
        val autoIncludeNewApps: Boolean,
        // When true, every value this profile attests that differs from the harvest is written
        // into the system property it is read from, and ro.boot.vbmeta.digest follows this
        // profile's verified boot hash (see App.applySystemProps). There is one set of properties
        // on the device, so at most one profile may ask (checked below). A config that states the
        // key nowhere falls back to the profile named `default`, or the only one there is, which
        // is what the daemon did before the flag existed.
        val applyProperties: Boolean,
    )

    data class Config(
        val version: Int,
        val profiles: List<ProfileConfig>,
    )

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

        val seenApps =
            HashMap<String, String>() // apps[] entry (package or uid:N) -> owning profile id
        val seenUids =
            HashMap<Int, String>() // effective caller uid -> owning profile id (cross-check)
        var autoIncludeProfiles =
            0 // how many profiles set autoIncludeNewApps (at most one allowed)
        var applyPropsProfiles = 0 // how many profiles set applyProperties (at most one allowed)
        // Whether any profile states applyProperties at all, which decides whether the others get
        // the historical fallback or a plain false.
        val statesApplyProperties =
            profilesObj.keys().asSequence().any {
                profilesObj.optJSONObject(it)?.has("applyProperties") == true
            }
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

            // Operation mode: patch (re-sign the real hardware attestation) or generation (mint the
            // whole key). Defaults to patch; a level whose hardware is unavailable still falls back
            // to generation at resolve time.
            val mode = p.optString("mode", "patch").trim().lowercase()
            if (mode != "patch" && mode != "generation")
                throw ConfigException("profile '$id' has invalid mode '$mode' (patch | generation)")

            // A spoofed verified boot hash is 32 bytes of hex, the shape of the real one: a
            // malformed value would otherwise reach the TA's root of trust as a short or empty
            // OCTET STRING and every chain it signs would be refused for a reason nothing names.
            val bootHash = p.optString("verifiedBootHash", "").trim().lowercase()
            if (bootHash.isNotEmpty() && !HEX64_RE.matches(bootHash))
                throw ConfigException(
                    "profile '$id' has an invalid verifiedBootHash '$bootHash' (64 hex characters, " +
                        "or empty to attest what the keybox or this device states)"
                )
            // The all-zero hash is what a device with no verified boot reports, and attestation is
            // refused for it — the one value this field cannot usefully hold. Refusing it here also
            // keeps ro.boot.vbmeta.digest honest: that property is never written all-zero, so a
            // profile attesting zeros would leave it saying something else entirely.
            if (bootHash.isNotEmpty() && bootHash.all { it == '0' })
                throw ConfigException(
                    "profile '$id' sets verifiedBootHash to all zeros, which is what a device with " +
                        "no verified boot reports and what attestation is refused for"
                )

            val patch = p.optJSONObject("patchLevel") ?: JSONObject()
            val apps =
                p.optJSONArray("apps")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it).trim() }
                } ?: emptyList()

            // One device, one set of system properties: two profiles writing them would fight over
            // every value. A config that states the key nowhere gets the choice the daemon made
            // before the flag existed; once any profile states it, the statement is the whole
            // truth and an absent key means no -- otherwise naming a second profile would collide
            // with a `default` that never asked for anything.
            val applyProperties =
                if (p.has("applyProperties")) p.optBoolean("applyProperties", false)
                else !statesApplyProperties && (id == "default" || profilesObj.length() == 1)
            if (applyProperties) applyPropsProfiles++
            if (applyPropsProfiles > 1)
                throw ConfigException(
                    "profile '$id' also sets applyProperties, but at most one profile may write " +
                        "the device's system properties"
                )

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
                    verifiedBootHash = bootHash,
                    apps = apps,
                    autoIncludeNewApps = autoIncludeNewApps,
                    applyProperties = applyProperties,
                )
            )
        }
        return Config(version, profiles)
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
