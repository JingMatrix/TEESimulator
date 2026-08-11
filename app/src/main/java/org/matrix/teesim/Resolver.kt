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
 * verifiedBootKey(b64), verifiedBootHash(b64), deviceLocked, verifiedBootState, strongBoxAvailable,
 * attestVersionTee, attestVersionStrongBox profile: id, keyboxB64, mode, securityLevel(int),
 * osVersion, osPatchLevel, vendorPatchLevel,
 * bootPatchLevel, deviceIds{...}, packages[], uids[] uids[] is parallel to packages[] (same length,
 * -1 where not installed).
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
                // Effective boot key/hash: the override when active (an unlocked device's all-zero capture
                // replaced by ro.boot.vbmeta.*, a stable fallback, or the user's edit), else the real
                // capture. Never all-zero, so the attested key still verifies.
                put("verifiedBootKey", b64.encodeToString(harvest.effectiveBootKey()))
                put("verifiedBootHash", b64.encodeToString(harvest.effectiveBootHash()))
                // Always present a locked, Verified boot state. Module users run unlocked bootloaders, and
                // reporting the device's real state (unlocked / Unverified) fails attestation by
                // construction. These are the "required" overrides the WebUI shows read-only.
                put("deviceLocked", true)
                put("verifiedBootState", 0)
                // Whether the device's StrongBox can really produce a hardware-backed attested key
                // (probed at harvest). It gates patch mode at the StrongBox level: when false, keys
                // requested at StrongBox fall back to generation even in a patch profile.
                put("strongBoxAvailable", harvest.strongBoxAvailable)
                // The attestationVersion each level reports: the harvested value on a device that attested
                // in hardware, a synthesized OS-appropriate one with no working hardware, or the user's
                // override — all captured by effectiveInt over the synthesized default. StrongBox reuses
                // the TEE value when it has no hardware.
                val effVersion = harvest.effectiveInt("attestationVersion", Harvester.effectiveAttestation(harvest).second)
                put("attestVersionTee", effVersion)
                put(
                    "attestVersionStrongBox",
                    if (Harvester.noWorkingHardware(harvest)) effVersion
                    else harvest.strongBoxAttestationVersion,
                )
            },
        )

        val profiles = JSONArray()
        for (p in config.profiles) {
            profiles.put(resolveProfile(p, harvest))
        }
        msg.put("profiles", profiles)
        return msg
    }

    private fun resolveProfile(
        p: ConfigStore.ProfileConfig,
        harvest: Harvester.Record,
    ): JSONObject {
        val o = JSONObject()
        o.put("id", p.id)

        val keyboxBytes = File(Const.DATA_DIR, p.keybox).readBytes()
        o.put("keyboxB64", b64.encodeToString(keyboxBytes))

        // Operation mode: "patch" re-signs the real hardware attestation, "generation" mints the whole
        // key in our TA. The router still forces generation for a level whose hardware is unavailable.
        o.put("mode", p.mode)

        // Security level is not a profile choice: it is the device's real harvested level, except that
        // a device with no working hardware attestation (software-only / TEE-broken) presents a
        // fabricated TrustedEnvironment so a spoofed key still claims hardware (see effectiveAttestation).
        o.put(
            "securityLevel",
            harvest.effectiveInt("attestationSecurityLevel", Harvester.effectiveAttestation(harvest).first),
        )

        // osVersion: system_property -> the harvested device value, omitted when absent;
        // else the parsed literal, omitted when it can't be parsed. A missing osVersion is
        // reported as "not set" rather than a synthesized default.
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

        // Device IDs: an explicit profile value overrides; otherwise fall back to the harvest baseline —
        // the real captured id, or (for serial/imei/meid, which the leaf never attests) the value read
        // from the OS at harvest, exposed via effective(). Omitted when neither is set (declines that id).
        val ids = JSONObject()
        putId(ids, "brand", p.brand, harvest.brand)
        putId(ids, "device", p.device, harvest.device)
        putId(ids, "product", p.product, harvest.product)
        putId(ids, "serial", p.serial, harvest.effective("serial"))
        putId(ids, "imei", p.imei, harvest.effective("imei"))
        putId(ids, "imei2", p.imei2, harvest.effective("imei2"))
        putId(ids, "meid", p.meid, harvest.effective("meid"))
        putId(ids, "manufacturer", p.manufacturer, harvest.manufacturer)
        putId(ids, "model", p.model, harvest.model)
        if (ids.length() > 0) o.put("deviceIds", ids)

        // packages[] with a parallel uids[] (-1 where not installed).
        val packages = JSONArray()
        val uids = JSONArray()
        for (pkg in p.apps) {
            packages.put(pkg)
            uids.put(Packages.uidForPackage(pkg))
        }
        o.put("packages", packages)
        o.put("uids", uids)
        return o
    }

    private fun putId(o: JSONObject, key: String, override: String, harvested: String) {
        val v = override.ifBlank { harvested }
        if (v.isNotBlank()) o.put(key, v)
    }
}
