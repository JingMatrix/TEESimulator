package org.matrix.teesim

import java.io.File
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONArray
import org.json.JSONObject

/**
 * Turns a validated [ConfigStore.Config] plus the frozen [Harvester.Record], system properties and
 * the clock into the full-replace `config` message the interceptor library parses in
 * common/control.cpp ApplyConfig().
 *
 * Field names mirror control.cpp exactly: top level: type, epoch, bootInfo, profiles bootInfo:
 * verifiedBootKey(b64), verifiedBootHash(b64), moduleHash(b64, optional), deviceLocked,
 * verifiedBootState, strongBoxAvailable, attestVersionTee, attestVersionStrongBox profile: id,
 * keyboxB64, mode, securityLevel(int), osVersion, osPatchLevel, vendorPatchLevel, bootPatchLevel,
 * deviceIds{...}, packages[], uids[]. packages[] is every explicit package-name entry verbatim
 * (kept even when not installed, since a name-match still fires on a later install); uids[] is the
 * independent effective caller-uid set (resolved packages + raw uid:N tokens + autoIncludeNewApps
 * expansion, never -1). The router matches package name first, uid second, so the two arrays need
 * not be the same length. See [Scope].
 */
object Resolver {

    private val b64 = Base64.getEncoder()
    private val epochSeq = AtomicLong(System.currentTimeMillis())

    /** Build the next config push, or throw if a keybox can't be read. */
    fun resolve(config: ConfigStore.Config, harvest: Harvester.Record): JSONObject {
        val msg = JSONObject()
        msg.put("type", "config")
        msg.put("epoch", epochSeq.incrementAndGet())

        msg.put(
            "bootInfo",
            JSONObject().apply {
                // Effective boot key/hash: the override when active (an unlocked device's all-zero
                // capture replaced by ro.boot.vbmeta.*, a stable fallback, or the user's edit),
                // else the real capture. Never all-zero, so the attested key still verifies.
                put("verifiedBootKey", b64.encodeToString(harvest.effectiveBootKey()))
                put("verifiedBootHash", b64.encodeToString(harvest.effectiveBootHash()))
                // The MODULE_HASH to attach to generation-mode keys, so they carry the tag
                // keystore2 sends the real HAL only once per boot (and never resends to a TA built
                // afterwards). Re-derived live at each commit from keystore2's own
                // getSupplementaryAttestationInfo blob (SHA-256'd) — the exact digest keystore2
                // pushed to the real HAL — so it stays correct even after an APEX/Play-system
                // update changes the module set; the persisted capture/override is only a fallback
                // when that live source is unavailable. Emitted only for KeyMint v4+ attestations
                // (the TA gates on version), so an older profile never carries it.
                val moduleHash =
                    Harvester.resolveModuleHash().takeIf { hash -> hash.any { it.toInt() != 0 } }
                        ?: harvest.effectiveModuleHash()
                moduleHash?.let { put("moduleHash", b64.encodeToString(it)) }
                // Always present a locked, Verified boot state. Module users run unlocked
                // bootloaders, and reporting the device's real state (unlocked / Unverified) fails
                // attestation by construction. These are the "required" overrides the WebUI shows
                // read-only.
                put("deviceLocked", true)
                put("verifiedBootState", 0)
                // Whether the device's StrongBox can really produce a hardware-backed attested key
                // (probed at harvest). It gates patch mode at the StrongBox level: when false, keys
                // requested at StrongBox fall back to generation even in a patch profile.
                put("strongBoxAvailable", harvest.strongBoxAvailable)
                // The attestationVersion each level reports: the harvested value on a device that
                // attested in hardware, a synthesized OS-appropriate one with no working hardware,
                // or the user's override — all captured by effectiveInt over the synthesized
                // default. StrongBox reuses the TEE value when it has no hardware.
                val effVersion =
                    harvest.effectiveInt(
                        "attestationVersion",
                        Harvester.effectiveAttestation(harvest).second,
                    )
                put("attestVersionTee", effVersion)
                put(
                    "attestVersionStrongBox",
                    if (Harvester.noWorkingHardware(harvest)) effVersion
                    else harvest.strongBoxAttestationVersion,
                )
            },
        )

        // Resolve each profile ONCE, here, and keep the ProfileScope: this is the only place in the
        // daemon that calls Scope.resolve, so it is also the only place that pays for the
        // installed-app enumeration an auto-including profile needs. Everything else (ReAttest,
        // /keys/db, /scope, the WebUI) reads the snapshot published below rather than resolving
        // again.
        val profiles = JSONArray()
        val scopes = ArrayList<Scope.ProfileScope>(config.profiles.size)
        for (p in config.profiles) {
            val scope = Scope.resolve(p, config.profiles.filter { it.id != p.id })
            scopes.add(scope)
            profiles.put(resolveProfile(p, scope, harvest))
        }
        msg.put("profiles", profiles)
        // Published as the last act of building the message, so a resolve that throws part-way
        // publishes nothing. There is no "push succeeded" moment to wait for instead: Control.push
        // only stages the JSON for the connection thread, and actual delivery is confirmed much
        // later by the lib's ack. So the snapshot means "the config the daemon last resolved and
        // staged", which is exactly what the WebUI and ReAttest need to reason about.
        Scope.publishResolved(msg.getLong("epoch"), scopes)
        return msg
    }

    private fun resolveProfile(
        p: ConfigStore.ProfileConfig,
        scope: Scope.ProfileScope,
        harvest: Harvester.Record,
    ): JSONObject {
        val o = JSONObject()
        o.put("id", p.id)

        val keyboxBytes = File(Const.DATA_DIR, p.keybox).readBytes()
        o.put("keyboxB64", b64.encodeToString(keyboxBytes))

        // Operation mode: "patch" re-signs the real hardware attestation, "generation" mints the
        // whole key in our TA. The router still forces generation for a level whose hardware is
        // unavailable.
        o.put("mode", p.mode)

        // Security level is not a profile choice: it is the device's real harvested level, except
        // that a device with no working hardware attestation (software-only / TEE-broken) presents
        // a fabricated TrustedEnvironment so a spoofed key still claims hardware (see
        // effectiveAttestation).
        o.put(
            "securityLevel",
            harvest.effectiveInt(
                "attestationSecurityLevel",
                Harvester.effectiveAttestation(harvest).first,
            ),
        )

        // osVersion: system_property -> the harvested device value, omitted when absent;
        // else the parsed literal, omitted when it can't be parsed. A missing osVersion is reported
        // as "not set" rather than a synthesized default.
        val osVersion =
            when {
                p.osVersion.isBlank() -> harvest.osVersion
                p.osVersion.equals("system_property", true) -> DeviceProps.propOsVersion()
                else -> DeviceProps.parseOsVersion(p.osVersion)
            }
        osVersion?.let { o.put("osVersion", it) }

        // Patch levels via the mini-language; omit (=> not reported) when unresolved.
        DeviceProps.resolvePatch(p.patchSystem, "system", harvest.osPatchLevel)?.let {
            o.put("osPatchLevel", it)
        }
        DeviceProps.resolvePatch(p.patchVendor, "vendor", harvest.vendorPatchLevel)?.let {
            o.put("vendorPatchLevel", it)
        }
        DeviceProps.resolvePatch(p.patchBoot, "boot", harvest.bootPatchLevel)?.let {
            o.put("bootPatchLevel", it)
        }

        // Device IDs: an explicit profile value overrides; otherwise fall back to the harvest
        // baseline — the real captured id, else the value read from the OS at harvest
        // (serial/imei/meid, and brand/device/product/manufacturer/model when the leaf carried
        // none), exposed via effective(). Omitted when neither is set (declines that id).
        val ids = JSONObject()
        putId(ids, "brand", p.brand, harvest.effective("brand"))
        putId(ids, "device", p.device, harvest.effective("device"))
        putId(ids, "product", p.product, harvest.effective("product"))
        putId(ids, "serial", p.serial, harvest.effective("serial"))
        putId(ids, "imei", p.imei, harvest.effective("imei"))
        putId(ids, "imei2", p.imei2, harvest.effective("imei2"))
        putId(ids, "meid", p.meid, harvest.effective("meid"))
        putId(ids, "manufacturer", p.manufacturer, harvest.effective("manufacturer"))
        putId(ids, "model", p.model, harvest.effective("model"))
        if (ids.length() > 0) o.put("deviceIds", ids)

        // packages[] (attestation name-match, verbatim incl. not-yet-installed) and uids[]
        // (caller-uid fallback, effective set with no -1) resolved centrally by Scope, which also
        // folds in raw uid:N tokens and the autoIncludeNewApps expansion and logs the per-entry
        // detail. The two arrays are independent here (uids[] may be longer or shorter than
        // packages[]), so each carries its own companion: packageUsers[] says which Android user a
        // name-match is confined to, and uidPackages[] names the package behind a uid for the
        // legacy keystore1 path, which has to rebuild an attestation application id the caller
        // never got to send.
        o.put("packages", JSONArray(scope.packageNames))
        val packageUsers = JSONArray()
        for (u in scope.packageUsers) packageUsers.put(u)
        o.put("packageUsers", packageUsers)
        val uids = JSONArray()
        val uidPackages = JSONArray()
        for (u in scope.uids) {
            uids.put(u)
            uidPackages.put(scope.uidPackages[u] ?: "")
        }
        o.put("uids", uids)
        o.put("uidPackages", uidPackages)
        return o
    }

    private fun putId(o: JSONObject, key: String, override: String, harvested: String) {
        val v = override.ifBlank { harvested }
        if (v.isNotBlank()) o.put(key, v)
    }
}
