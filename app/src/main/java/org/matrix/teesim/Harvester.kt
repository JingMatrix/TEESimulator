package org.matrix.teesim

import android.content.Context
import android.os.Build
import android.os.IBinder
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.ByteArrayOutputStream
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Null
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.json.JSONObject

/**
 * Harvests real attestation parameters from the device TEE by generating a throwaway attested EC
 * key and parsing the leaf's KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17). Extends the
 * main-branch harvest with deviceLocked, verifiedBootState and the attestation/keymaster security
 * levels.
 *
 * verifiedBootKey/verifiedBootHash feed KeyMint's key-encryption-key derivation, so they are frozen
 * on the first successful harvest and never overwritten with a different value (that would orphan
 * every stored key). The full record is cached to [Const.harvestedFile].
 */
object Harvester {

    private const val OID = "1.3.6.1.4.1.11129.2.1.17"
    private const val CHECK_ALIAS = "TEESimulator_AttestationCheck"

    // KeyDescription SEQUENCE field indices.
    private const val KD_ATTEST_VERSION = 0
    private const val KD_ATTEST_SECLEVEL = 1
    private const val KD_KEYMASTER_VERSION = 2
    private const val KD_KEYMASTER_SECLEVEL = 3
    private const val KD_SOFTWARE_ENFORCED = 6
    private const val KD_TEE_ENFORCED = 7

    // RootOfTrust SEQUENCE field indices.
    private const val ROT_VERIFIED_BOOT_KEY = 0
    private const val ROT_DEVICE_LOCKED = 1
    private const val ROT_VERIFIED_BOOT_STATE = 2
    private const val ROT_VERIFIED_BOOT_HASH = 3

    // AuthorizationList context tags.
    private const val TAG_ROOT_OF_TRUST = 704
    private const val TAG_OS_VERSION = 705
    private const val TAG_OS_PATCHLEVEL = 706
    private const val TAG_VENDOR_PATCHLEVEL = 718
    private const val TAG_BOOT_PATCHLEVEL = 719
    private const val TAG_MODULE_HASH = 724
    // The full KeyMint Tag value for MODULE_HASH (TagType.BYTES | 724 = 0x900002D4) — what
    // IKeystoreService.getSupplementaryAttestationInfo expects, distinct from the cert extension's
    // raw tag number 724 above. Same constant KeyStoreManager.MODULE_HASH resolves to.
    private const val KM_TAG_MODULE_HASH = -1879047468

    // Attestation-ID tags (device properties). Captured so we can provision them back, letting an
    // app's device-ID attestation request succeed against the real values.
    private const val TAG_ATTESTATION_ID_BRAND = 710
    private const val TAG_ATTESTATION_ID_DEVICE = 711
    private const val TAG_ATTESTATION_ID_PRODUCT = 712
    private const val TAG_ATTESTATION_ID_SERIAL = 713
    private const val TAG_ATTESTATION_ID_IMEI = 714
    private const val TAG_ATTESTATION_ID_MEID = 715
    private const val TAG_ATTESTATION_ID_MANUFACTURER = 716
    private const val TAG_ATTESTATION_ID_MODEL = 717
    private const val TAG_ATTESTATION_ID_SECOND_IMEI = 723

    /** Where an override value comes from, which drives its badge and editability in the WebUI. */
    enum class OverrideSource {
        /**
         * Structurally forced for attestation to pass (deviceLocked, verifiedBootState, and the
         * boot key/hash when the device reported an all-zero one). Locked, except the boot
         * key/hash.
         */
        REQUIRED,
        /**
         * A real device value the attested leaf did not carry (imei/meid/serial), read from the OS.
         */
        SUPPLEMENT,
        /**
         * Synthesized because there is no working hardware (level/version on a software-only
         * device).
         */
        SYNTHESIZED,
    }

    /**
     * One field we present to apps in place of the raw captured value. `value` is the display/wire
     * form (hex for the boot key/hash, the plain string otherwise). `editable` is whether the WebUI
     * may change it; `userEdited` is whether the live value came from the user's overrides.json
     * rather than the daemon's computed default.
     */
    data class Override(
        val value: String,
        val source: OverrideSource,
        val editable: Boolean,
        val userEdited: Boolean = false,
    )

    /**
     * Device ids we may read from the OS when the attested leaf did not carry them, presented as
     * SUPPLEMENT overrides. Shown for transparency but NOT editable here — spoofing an id is a
     * per-profile concern (Resolver.resolveProfile lets a profile override each).
     * serial/imei/imei2/meid are read from telephony/props; brand/device/product/manufacturer/model
     * ([DEVICE_PROP_IDS]) are supplemented only when the leaf carried none, via [devicePropId].
     */
    private val DEVICE_PROP_IDS = setOf("brand", "device", "product", "manufacturer", "model")
    private val SUPPLEMENT_IDS = setOf("serial", "imei", "imei2", "meid") + DEVICE_PROP_IDS
    /** Level/version values we synthesize on a device with no working hardware — editable. */
    private val SYNTHESIZED_FIELDS =
        setOf(
            "attestationSecurityLevel",
            "keymasterSecurityLevel",
            "attestationVersion",
            "keymasterVersion",
        )
    /**
     * The two boot fields the user may edit ONLY when the captured value is all-zero (unlocked
     * device); applying an override for either also resetprops the matching ro.boot.vbmeta.* system
     * property.
     */
    val BOOT_PROP =
        mapOf(
            "verifiedBootKey" to "ro.boot.vbmeta.public_key_digest",
            "verifiedBootHash" to "ro.boot.vbmeta.digest",
        )

    /**
     * The ro.boot.vbmeta.* values to reflect for [h]: the PRESENTED boot key and hash — the
     * override when one is active, else the real captured bytes. Unlike a plain read of the
     * override map, this includes a genuinely captured value, so ro.boot.vbmeta.digest tracks the
     * attested verifiedBootHash even on a device whose bootloader never populated the property
     * (#228). A field whose presented value is not a real 32-byte value is skipped — we never write
     * an all-zero prop.
     */
    fun bootPropValues(h: Record): Map<String, String> = buildMap {
        h.effectiveBootKey()
            .takeIf { isUsableBootValue(it) }
            ?.let { put(BOOT_PROP.getValue("verifiedBootKey"), it.toHex()) }
        h.effectiveBootHash()
            .takeIf { isUsableBootValue(it) }
            ?.let { put(BOOT_PROP.getValue("verifiedBootHash"), it.toHex()) }
    }

    private fun sourceFor(field: String): OverrideSource =
        when {
            field in SUPPLEMENT_IDS -> OverrideSource.SUPPLEMENT
            field in SYNTHESIZED_FIELDS -> OverrideSource.SYNTHESIZED
            else -> OverrideSource.REQUIRED
        }

    /**
     * The editability we STAMP on a freshly built override. Synthesized level/version fields are
     * always editable; the boot key/hash carry their own flag (set when built — true only for a
     * fallback value), so they are not decided here; everything else (SUPPLEMENT ids, required
     * captures) stays locked.
     */
    private fun editableFor(field: String): Boolean = field in SYNTHESIZED_FIELDS

    /**
     * Whether the user's overrides.json may change [field] on [base]: synthesized level/version
     * fields always; the boot key/hash only when their current override is a fallback (its editable
     * flag is set) — a real captured, device-property or computed value is locked; everything else
     * is ignored.
     */
    private fun userEditable(field: String, base: Record): Boolean =
        when (field) {
            in SYNTHESIZED_FIELDS -> true
            "verifiedBootKey",
            "verifiedBootHash" -> base.overrides[field]?.editable == true
            else -> false
        }

    /** One harvested (or fallback) device-identity record. */
    data class Record(
        val harvestFailed: Boolean,
        val verifiedBootKey:
            ByteArray, // 32 bytes, RAW as captured (all-zero on an unlocked device)
        val verifiedBootHash: ByteArray, // 32 bytes, RAW as captured
        val deviceLocked: Boolean,
        val verifiedBootState: Int, // 0 Verified,1 SelfSigned,2 Unverified,3 Failed
        val attestationSecurityLevel: Int, // 0 SW,1 TEE,2 SB
        val keymasterSecurityLevel: Int,
        // Whether the device can actually produce a StrongBox-backed attested key (probed at
        // harvest). When a TrustedEnvironment is present StrongBox is always OFFERED regardless;
        // this only decides whether StrongBox keys can be patched (real hardware) or must be
        // generated.
        val strongBoxAvailable: Boolean,
        // KeyMint HAL version (attestationVersion) probed at StrongBox; the TEE value when
        // StrongBox has no real hardware. Keys attested at StrongBox report this instead of the TEE
        // version.
        val strongBoxAttestationVersion: Int,
        val attestationVersion: Int,
        val keymasterVersion: Int,
        val osVersion: Int?, // encoded major*10000+minor*100+sub
        val osPatchLevel: Int?, // YYYYMM
        val vendorPatchLevel: Int?, // YYYYMMDD
        val bootPatchLevel: Int?, // YYYYMMDD
        val moduleHash: ByteArray?,
        // Device-identity values captured from the attested leaf, RAW — blank when the leaf did not
        // carry that id (device-properties attestation omits imei/meid/serial). The value we
        // actually present for a blank one lives in `overrides` (source SUPPLEMENT), never written
        // back here.
        val brand: String,
        val device: String,
        val product: String,
        val manufacturer: String,
        val model: String,
        val serial: String,
        val imei: String,
        val meid: String,
        val imei2: String,
        // The values we present to apps in place of the raw captured ones, keyed by JSON field
        // name. The record keeps the RAW capture in the fields above; this map is the honest
        // override layer the WebUI shows separately (and, for editable fields, lets the user change
        // via overrides.json).
        val overrides: Map<String, Override>,
        val harvestedAt: Long,
    ) {
        /**
         * The string we actually present for a field: the override when one is active, else the raw
         * capture. A blank result (e.g. an unsupplemented, unattested id) means "decline that
         * field".
         */
        fun effective(field: String): String = overrides[field]?.value ?: capturedString(field)

        /**
         * The integer we present for a numeric field, or [fallback] when neither override nor
         * capture yields a parseable value.
         */
        fun effectiveInt(field: String, fallback: Int): Int =
            overrides[field]?.value?.toIntOrNull()
                ?: capturedString(field).toIntOrNull()
                ?: fallback

        /**
         * The 32-byte boot key/hash we actually present: the override (hex) when active —
         * guaranteed non-zero — else the raw capture. Used by the config push and ownership check,
         * which must never see the all-zero value an unlocked device reports.
         */
        fun effectiveBootKey(): ByteArray = effectiveBoot("verifiedBootKey", verifiedBootKey)

        fun effectiveBootHash(): ByteArray = effectiveBoot("verifiedBootHash", verifiedBootHash)

        private fun effectiveBoot(field: String, captured: ByteArray): ByteArray =
            overrides[field]?.value?.let { hexBytes(it) } ?: captured

        /**
         * The MODULE_HASH we present: the override (hex, synthesized when the leaf omitted the tag)
         * when active, else the raw capture. Null only when neither exists — the lib then omits the
         * tag, and its v4-only gate omits it for older profiles regardless.
         */
        fun effectiveModuleHash(): ByteArray? =
            overrides["moduleHash"]?.value?.let { hexBytes(it) } ?: moduleHash

        private fun capturedString(field: String): String =
            when (field) {
                "brand" -> brand
                "device" -> device
                "product" -> product
                "manufacturer" -> manufacturer
                "model" -> model
                "serial" -> serial
                "imei" -> imei
                "imei2" -> imei2
                "meid" -> meid
                "attestationSecurityLevel" -> attestationSecurityLevel.toString()
                "keymasterSecurityLevel" -> keymasterSecurityLevel.toString()
                "attestationVersion" -> attestationVersion.toString()
                "keymasterVersion" -> keymasterVersion.toString()
                else -> ""
            }
    }

    // --- Fabricated attestation identity (software-only / TEE-broken devices) --------------------
    // When the device produces no working HARDWARE attestation — a software-only emulator, or a
    // device whose TEE is broken (attestation falls back to Software, or the harvest failed) — we
    // present a fabricated TrustedEnvironment identity to apps, since spoofing a hardware key is
    // the whole point. On a device that really attested in hardware the captured values pass
    // through unchanged.

    private const val SEC_LEVEL_TEE = 1

    /**
     * True when the harvest captured no working hardware attestation, so the level/version must be
     * fabricated rather than reflected.
     */
    fun noWorkingHardware(r: Record): Boolean =
        r.harvestFailed || r.attestationSecurityLevel < SEC_LEVEL_TEE

    /**
     * The (securityLevel, attestationVersion) to actually present: fabricated TrustedEnvironment +
     * the OS-appropriate version when there is no working hardware, else the captured pair
     * unchanged.
     */
    fun effectiveAttestation(r: Record): Pair<Int, Int> =
        if (noWorkingHardware(r)) SEC_LEVEL_TEE to fabricatedAttestationVersion()
        else r.attestationSecurityLevel to r.attestationVersion

    /**
     * The `attestationVersion` a real hardware device of this OS release reports. Keymaster and
     * KeyMint disagree with `keymasterVersion` only up to Android 11 (mapped in
     * keymasterVersionFor): Keymaster 3.0 (<=8.1) = 2, 4.0 (9/10) = 3, 4.1 (11) = 4; KeyMint N.0
     * (12+) = N*100.
     */
    fun fabricatedAttestationVersion(sdk: Int = Build.VERSION.SDK_INT): Int =
        when {
            sdk <= 27 -> 2 // <= Android 8.1 (Keymaster 3.0); below our floor, best effort
            sdk <= 29 -> 3 // Android 9, 10 (Keymaster 4.0)
            sdk == 30 -> 4 // Android 11 (Keymaster 4.1)
            sdk <= 32 -> 100 // Android 12 / 12L (KeyMint 1.0)
            sdk == 33 -> 200 // Android 13 (KeyMint 2.0)
            sdk <= 35 -> 300 // Android 14, 15 (KeyMint 3.0; Android 15 did not bump KeyMint)
            sdk == 36 -> 400 // Android 16 (KeyMint 4.0; first release to carry MODULE_HASH)
            else -> 500 // Android 17+ (KeyMint 5.0)
        }

    /**
     * The `keymasterVersion` matching an `attestationVersion` (same derivation as the TA's
     * cert.rs): attestation 2 -> keymaster 3, 3 -> 4, 4 -> 41; KeyMint values (>= 100) are equal.
     */
    fun keymasterVersionFor(attestationVersion: Int): Int =
        when (attestationVersion) {
            2 -> 3
            3 -> 4
            4 -> 41
            else -> attestationVersion
        }

    /**
     * Build the typed default overrides from a field->value map (non-boot fields; the boot key/hash
     * are added by [buildOverrides] with their own editability). `userEdited` is false: these are
     * the daemon's computed defaults. Values are the machine form (the level integer, "true", hex)
     * — the WebUI formats them for display.
     */
    private fun typedOverrides(values: Map<String, String>): Map<String, Override> =
        values.mapValues { (field, value) ->
            Override(value, sourceFor(field), editableFor(field), userEdited = false)
        }

    /**
     * A synthesized boot value plus whether it is user-editable — true only for a last-resort
     * fallback, false for a real value (a captured device property, or the digest we computed
     * ourselves).
     */
    private data class BootOverride(val value: String, val editable: Boolean)

    private fun bootOverride(field: String, bo: BootOverride): Override =
        Override(bo.value, sourceFor(field), bo.editable, userEdited = false)

    /**
     * The full override map: the non-boot synthesized/required defaults, plus the boot key/hash
     * overrides (each present only when the raw capture is unusable), each carrying its own
     * editability.
     */
    private fun buildOverrides(
        fab: Map<String, String>,
        rawKey: ByteArray,
        rawHash: ByteArray,
    ): Map<String, Override> {
        val m = typedOverrides(fab).toMutableMap()
        bootKeyOverride(rawKey)?.let { m["verifiedBootKey"] = bootOverride("verifiedBootKey", it) }
        bootHashOverride(rawHash)?.let {
            m["verifiedBootHash"] = bootOverride("verifiedBootHash", it)
        }
        return m
    }

    /** Add or replace one computed-default override, keeping the raw captured fields untouched. */
    private fun Record.withOverride(field: String, value: String): Record =
        copy(
            overrides = overrides + (field to Override(value, sourceFor(field), editableFor(field)))
        )

    /**
     * Layer the user's overrides.json (field -> value) over the daemon's computed defaults,
     * honoring only editable fields (see [userEditable]): the synthesized levels/versions, and the
     * boot key/hash only when their value is a fallback — a hand-edited id, a required capture, or
     * a real/computed boot value is ignored. A blank value resets a field to its computed default;
     * an out-of-range value is dropped with a warning. This is what the daemon pushes.
     */
    fun applyUserOverrides(base: Record, user: Map<String, String>): Record {
        if (user.isEmpty()) return base
        val merged = base.overrides.toMutableMap()
        for ((field, raw) in user) {
            if (!userEditable(field, base)) {
                SystemLogger.info("override: ignoring non-editable field '$field'")
                continue
            }
            val value = raw.trim()
            when {
                value.isEmpty() -> Unit // reset: keep the computed default already in `merged`
                !validOverride(field, value) ->
                    SystemLogger.warning("override: ignoring invalid $field='$value'")
                else -> merged[field] = Override(value, sourceFor(field), true, userEdited = true)
            }
        }
        return base.copy(overrides = merged)
    }

    /**
     * Per-field validation for a user override value (machine form): 64 hex chars for a boot
     * key/hash, an in-range level/version. Keeps a bad hand-edit from ever reaching the config
     * push.
     */
    private fun validOverride(field: String, value: String): Boolean =
        when (field) {
            "verifiedBootKey",
            "verifiedBootHash" -> hexBytes(value) != null
            "attestationSecurityLevel",
            "keymasterSecurityLevel" -> value.toIntOrNull() in 0..2
            "attestationVersion",
            "keymasterVersion" -> (value.toIntOrNull() ?: -1) in 1..100_000
            else -> true
        }

    /**
     * When there is no working hardware, record the synthesized TrustedEnvironment level + versions
     * as overrides so the WebUI presents what we hand apps. Raw captured fields stay untouched.
     */
    private fun markFabricatedAttestation(r: Record): Record {
        if (!noWorkingHardware(r)) return r
        val (level, version) = effectiveAttestation(r)
        return r.withOverride("attestationSecurityLevel", level.toString())
            .withOverride("keymasterSecurityLevel", level.toString())
            .withOverride("attestationVersion", version.toString())
            .withOverride("keymasterVersion", keymasterVersionFor(version).toString())
    }

    /**
     * Reconcile the attestation/keymaster version we present with the keystore HAL the device
     * declares in VINTF ([Vintf.attestationVersionConstraint]). Two constraint kinds, following
     * VtsAidlKeyMintTargetTest::check_attestation_version and ../Duck-Detector-Refactoring
     * VintfKeyMintVersionProbe:
     *
     * - An AIDL KeyMint HAL @N is a CEILING (N*100): `attestationVersion / 100 <= N`, so we clamp
     *   DOWN only when the current value exceeds it (e.g. an image shipping
     *   `IKeyMintDevice/default@3` while the keys or our fabrication claim a newer KeyMint).
     * - A legacy HIDL Keymaster HAL is an EXACT target (@3.0 -> 2, @4.0 -> 3, @4.1 -> 4; AOSP
     *   system/keymaster): we set it in BOTH directions, since the captured or fabricated value may
     *   sit either side of the declared HAL.
     *
     * TEE is recorded as computed overrides so the WebUI, the config push and the TA agree;
     * StrongBox is reconciled in its own field, which Resolver reads directly. keymasterVersionFor
     * derives the matching keymasterVersion, and a resulting version below 400 makes the TA drop
     * MODULE_HASH (a v4-only tag).
     */
    private fun clampAttestationToVintf(r: Record): Record {
        var out = r

        Vintf.attestationVersionConstraint("default")?.let { c ->
            val current = out.effectiveInt("attestationVersion", out.attestationVersion)
            if (if (c.exact) current != c.version else current > c.version) {
                SystemLogger.info(
                    "Harvest: constraining attestationVersion $current -> ${c.version} to the device's " +
                        "VINTF-declared keystore HAL (${if (c.exact) "Keymaster HIDL, exact match" else "KeyMint AIDL, ceiling"})"
                )
                out =
                    out.withOverride("attestationVersion", c.version.toString())
                        .withOverride("keymasterVersion", keymasterVersionFor(c.version).toString())
            }
        }

        // StrongBox declares its own instance constraint; fall back to the default instance's when
        // the manifest lists no separate strongbox HAL (many devices share one HAL version across
        // levels).
        (Vintf.attestationVersionConstraint("strongbox")
                ?: Vintf.attestationVersionConstraint("default"))
            ?.let { c ->
                val current = out.strongBoxAttestationVersion
                if (if (c.exact) current != c.version else current > c.version) {
                    SystemLogger.info(
                        "Harvest: constraining strongBoxAttestationVersion $current -> ${c.version} to the " +
                            "device's VINTF-declared StrongBox keystore HAL"
                    )
                    out = out.copy(strongBoxAttestationVersion = c.version)
                }
            }

        return out
    }

    /**
     * Load the frozen record if present, attempt a fresh harvest, merge (preserving the frozen boot
     * key/hash), persist, and return the effective record.
     */
    fun run(context: Context): Record {
        val existing = loadPersisted()
        val fresh = tryHarvest()

        val effective =
            when {
                // A prior good harvest exists: keep its frozen boot key/hash forever.
                existing != null && !existing.harvestFailed -> {
                    if (fresh != null && !fresh.harvestFailed) {
                        // Refresh volatile fields but freeze verifiedBoot* — unless a stale
                        // all-zero value was frozen before the zero-reject fix, in which case adopt
                        // the fresh (guaranteed non-zero) one.
                        fresh.copy(
                            verifiedBootKey =
                                if (isUsableBootValue(existing.verifiedBootKey))
                                    existing.verifiedBootKey
                                else fresh.verifiedBootKey,
                            verifiedBootHash =
                                if (isUsableBootValue(existing.verifiedBootHash))
                                    existing.verifiedBootHash
                                else fresh.verifiedBootHash,
                            // When we keep existing's real captured boot value, drop fresh's
                            // synthesized override for it — the captured value is now honest and
                            // needs no override.
                            overrides =
                                fresh.overrides.filterKeys { k ->
                                    !(k == "verifiedBootKey" &&
                                        isUsableBootValue(existing.verifiedBootKey)) &&
                                        !(k == "verifiedBootHash" &&
                                            isUsableBootValue(existing.verifiedBootHash))
                                },
                        )
                    } else {
                        existing
                    }
                }
                // No frozen record yet.
                fresh != null && !fresh.harvestFailed -> fresh
                // Harvest failed and nothing frozen: fabricate a stable fallback.
                else -> existing?.takeIf { !it.harvestFailed } ?: fallback()
            }

        val stable = freezeSynthBoot(effective, existing)
        val enriched =
            clampAttestationToVintf(markFabricatedAttestation(supplementDeviceIds(stable)))
        persist(enriched)
        SystemLogger.info(
            "Harvest complete: failed=${enriched.harvestFailed} " +
                "bootKey=${stable.effectiveBootKey().toHex()} bootHash=${stable.effectiveBootHash().toHex()} " +
                "locked=${effective.deviceLocked} vbState=${effective.verifiedBootState} " +
                "attestSecLevel=${effective.attestationSecurityLevel} " +
                "os=${effective.osVersion} osPatch=${effective.osPatchLevel} " +
                "vendorPatch=${enriched.vendorPatchLevel} bootPatch=${enriched.bootPatchLevel}"
        )
        return enriched
    }

    /**
     * Keep the synthesized boot key/hash coherent across reboots, honoring their different needs.
     * The KEY feeds the KEK, so whenever the raw capture is unusable it is pinned to the first
     * persisted value and never allowed to drift — a change would orphan every previously wrapped
     * keystore blob. The HASH is attestation-only, so a real value (the digest we compute from the
     * partitions) is used live and tracks the device across updates; only the last-resort RANDOM
     * fallback is pinned, so ro.boot.vbmeta.digest does not flap each boot, and a persisted value
     * is preferred over a fresh random when this harvest could not compute one. [prior] is the last
     * persisted record, or null on the very first harvest.
     */
    private fun freezeSynthBoot(effective: Record, prior: Record?): Record {
        if (prior == null) return effective
        var overrides = effective.overrides

        if (!isUsableBootValue(effective.verifiedBootKey)) {
            prior.overrides["verifiedBootKey"]?.let { pinned ->
                if (overrides["verifiedBootKey"] != pinned) {
                    overrides = overrides + ("verifiedBootKey" to pinned)
                    SystemLogger.info(
                        "Harvest: pinned verifiedBootKey to the persisted value (KEK stability)"
                    )
                }
            }
        }

        if (!isUsableBootValue(effective.verifiedBootHash)) {
            val fresh = overrides["verifiedBootHash"]
            // fresh.editable is true only for the random fallback; a computed digest
            // (editable=false) is left live so it follows an OTA that changes the real vbmeta.
            if (fresh != null && fresh.editable) {
                prior.overrides["verifiedBootHash"]?.let { persisted ->
                    if (fresh != persisted) {
                        overrides = overrides + ("verifiedBootHash" to persisted)
                        SystemLogger.info(
                            "Harvest: reused the persisted verifiedBootHash (this harvest fell back to a random value)"
                        )
                    }
                }
            }
        }
        return if (overrides === effective.overrides) effective
        else effective.copy(overrides = overrides)
    }

    // A system package name to present as the caller for IPhoneSubInfo. The legacy getDeviceId*
    // path returns the real IMEI for any package (unlike getImei*, which validates it against the
    // caller uid).
    private const val TELEPHONY_CALLER_PKG = "android"

    // How long to wait for telephony (the modem/RIL) to come up before giving up on the device ids.
    private const val TELEPHONY_WAIT_MS = 15_000L

    /**
     * Fill in the device ids a leaf without device-id attestation does not carry — IMEI, MEID,
     * serial.
     *
     * The bare app_process does not initialize the telephony framework (so
     * `TelephonyManager.getImei()` hits a null service registerer), and
     * `getImei()`/`getImeiForSlot()` enforce a "package belongs to caller uid" check the daemon
     * (uid 0) does not pass. So we call the `IPhoneSubInfo` binder's legacy `getDeviceId*` methods,
     * which are not package-scoped. The serial is read from the `ro.serialno` property, since
     * `Build.getSerial()` applies the same package check.
     */
    private fun supplementDeviceIds(r: Record): Record {
        // The harvest runs very early at boot, when telephony (the modem/RIL) usually isn't up yet,
        // so IPhoneSubInfo returns empty even though the device has an IMEI. Defer the reads until
        // it is.
        if (r.imei.isBlank()) awaitTelephony()
        val imei = r.imei.ifBlank { deviceIdForPhone(0) }
        var imei2 = r.imei2.ifBlank { deviceIdForPhone(1) }
        if (imei2.isNotBlank() && imei2 == imei) imei2 = "" // single-SIM: slot 1 mirrors slot 0
        val meid =
            r.meid.ifBlank {
                safeId("getMeidForSubscriber(0)") { phoneSubInfoId("getMeidForSubscriber", 0) }
            }
        val serial = r.serial.ifBlank { DeviceProps.prop("ro.serialno", "") }
        SystemLogger.info(
            "Harvest telephony IDs: imei='$imei' secondImei='$imei2' meid='$meid' serial='$serial'"
        )
        // These ids are not carried by device-properties attestation. When the attested leaf had no
        // value (r.<id> blank) and we read one from the OS, it is a SUPPLEMENT override — the RAW
        // captured field stays blank so "Captured" never claims we attested it. A device that DID
        // attest an id keeps it as a real capture (no override), and the user can still spoof it
        // per-profile.
        var out = r
        if (r.imei.isBlank() && imei.isNotBlank()) out = out.withOverride("imei", imei)
        if (r.imei2.isBlank() && imei2.isNotBlank()) out = out.withOverride("imei2", imei2)
        if (r.meid.isBlank() && meid.isNotBlank()) out = out.withOverride("meid", meid)
        if (r.serial.isBlank() && serial.isNotBlank()) out = out.withOverride("serial", serial)

        // brand/device/product/manufacturer/model are captured from the attested leaf when it
        // carries them; a leaf that carried no device ids leaves them blank, and then the profile
        // presents an empty id. Fill each blank one from the same source the framework fills
        // ATTESTATION_ID_* from (see [devicePropId]), as a SUPPLEMENT override; a real capture is
        // left untouched, and the user can still spoof any of them per-profile.
        val supplemented = ArrayList<String>()
        for (field in DEVICE_PROP_IDS) {
            if (out.effective(field).isNotBlank()) continue // attested, or already supplemented
            val value = devicePropId(field)
            if (value.isNotBlank()) {
                out = out.withOverride(field, value)
                supplemented.add("$field='$value'")
            }
        }
        if (supplemented.isNotEmpty())
            SystemLogger.info(
                "Harvest: device ids not attested; supplemented from system properties: " +
                    supplemented.joinToString(" ")
            )
        return out
    }

    // android.os.Build.UNKNOWN, the sentinel getString returns for an unset property.
    private const val BUILD_UNKNOWN = "unknown"

    /**
     * The property base name AOSP's Build.getVendorDeviceIdProperty uses for each attestation id
     * (PRODUCT is backed by "name"); null for a field with no such mapping.
     */
    private fun attestIdBase(field: String): String? =
        when (field) {
            "brand" -> "brand"
            "device" -> "device"
            "product" -> "name"
            "manufacturer" -> "manufacturer"
            "model" -> "model"
            else -> null
        }

    /**
     * The device-property id [field], resolved the way the framework resolves ATTESTATION_ID_*.
     * Source: AOSP AndroidKeyStoreKeyPairGeneratorSpi reads Build.<X>_FOR_ATTESTATION (falling back
     * to Build.<X>), and android.os.Build.getVendorDeviceIdProperty backs the _FOR_ATTESTATION
     * fields as: ro.product.<base>_for_attestation (unless "unknown") → else
     * ro.product.vendor.<base> (unless empty/"unknown") → else ro.product.<base> (the plain Build
     * value) where <base> is brand/device/name(product)/manufacturer/model. This reads the same
     * properties directly rather than the hidden Build.<X>_FOR_ATTESTATION fields. Blank when the
     * whole chain is unset/unknown.
     */
    private fun devicePropId(field: String): String {
        val base = attestIdBase(field) ?: return ""
        val forAttestation =
            DeviceProps.prop("ro.product.${base}_for_attestation", BUILD_UNKNOWN).let {
                if (it == BUILD_UNKNOWN) DeviceProps.prop("ro.product.vendor.$base", BUILD_UNKNOWN)
                else it
            }
        val resolved =
            if (forAttestation.isBlank() || forAttestation == BUILD_UNKNOWN)
                DeviceProps.prop("ro.product.$base", "")
            else forAttestation
        return resolved.trim().let { if (it == BUILD_UNKNOWN) "" else it }
    }

    /**
     * Wait (bounded) for telephony to return the primary IMEI. IPhoneSubInfo registers early, but
     * the modem takes a few seconds more to load, until which getDeviceIdForPhone returns empty —
     * so poll quietly (no per-attempt "empty" spam) until it appears or [TELEPHONY_WAIT_MS]
     * elapses. A device with no telephony simply waits out the deadline once and proceeds with an
     * empty IMEI.
     */
    private fun awaitTelephony() {
        val deadline = System.currentTimeMillis() + TELEPHONY_WAIT_MS
        var waits = 0
        while (System.currentTimeMillis() < deadline) {
            val imei =
                try {
                    phoneSubInfoId("getDeviceIdForPhone", 0)
                } catch (e: Throwable) {
                    null
                }
            if (!imei.isNullOrBlank()) {
                if (waits > 0) SystemLogger.info("Harvest telephony: ready after ${waits}s")
                return
            }
            waits++
            try {
                Thread.sleep(1000)
            } catch (_: InterruptedException) {
                return
            }
        }
        SystemLogger.warning(
            "Harvest telephony: no IMEI after ${TELEPHONY_WAIT_MS / 1000}s; proceeding (no telephony or modem still down)"
        )
    }

    /**
     * The IMEI for a SIM slot, read via IPhoneSubInfo.getDeviceIdForPhone (works even for uid 0).
     */
    private fun deviceIdForPhone(slot: Int): String =
        safeId("getDeviceIdForPhone($slot)") { phoneSubInfoId("getDeviceIdForPhone", slot) }

    @Volatile private var phoneSubInfo: Any? = null

    /**
     * Invoke a String-returning IPhoneSubInfo method (e.g. getDeviceIdForPhone,
     * getMeidForSubscriber) for a SIM slot. The service is reached straight through ServiceManager
     * — no TelephonyManager, no framework init needed — and any String parameters
     * (callingPackage/featureId) are filled with a system package name. All by reflection, since
     * IPhoneSubInfo is a hidden interface.
     */
    private fun phoneSubInfoId(methodName: String, slot: Int): String? {
        val svc =
            phoneSubInfo
                ?: run {
                    val sm = Class.forName("android.os.ServiceManager")
                    val binder =
                        sm.getMethod("getService", String::class.java).invoke(null, "iphonesubinfo")
                            as? IBinder ?: return null
                    val stub = Class.forName("com.android.internal.telephony.IPhoneSubInfo\$Stub")
                    stub.getMethod("asInterface", IBinder::class.java).invoke(null, binder).also {
                        phoneSubInfo = it
                    }
                }
        val method =
            Class.forName("com.android.internal.telephony.IPhoneSubInfo").methods.firstOrNull {
                it.name == methodName &&
                    it.parameterTypes.firstOrNull() == Int::class.javaPrimitiveType
            } ?: return null
        val args: List<Any?> =
            method.parameterTypes.map { t ->
                when (t) {
                    Int::class.javaPrimitiveType -> slot
                    String::class.java -> TELEPHONY_CALLER_PKG
                    else -> return null
                }
            }
        return method.invoke(svc, *args.toTypedArray()) as? String
    }

    /** A device id read that never throws or returns a placeholder — "" on any failure, logged. */
    private inline fun safeId(what: String, block: () -> String?): String =
        try {
            val v = block()?.takeIf { it.isNotBlank() && !it.equals("null", true) } ?: ""
            if (v.isBlank()) SystemLogger.info("Harvest telephony: $what returned empty")
            v
        } catch (e: Exception) {
            val cause = (e as? InvocationTargetException)?.targetException ?: e
            SystemLogger.warning(
                "Harvest telephony: $what failed: ${cause.javaClass.simpleName}: ${cause.message}"
            )
            ""
        }

    // --- live harvest -----------------------------------------------------------

    private fun tryHarvest(): Record? {
        val leaf = generateAndFetchLeaf() ?: return null
        return try {
            val rec = parse(leaf)
            val sb = probeStrongBox()
            rec.copy(
                strongBoxAvailable = sb.available,
                // Fall back to the TEE version when StrongBox has no real hardware to harvest.
                strongBoxAttestationVersion = sb.attestationVersion ?: rec.attestationVersion,
            )
        } catch (e: Exception) {
            SystemLogger.error("Failed to parse harvested attestation", e)
            null
        }
    }

    /** Outcome of the StrongBox probe: whether it works and, if so, its harvested HAL version. */
    private data class StrongBoxProbe(val available: Boolean, val attestationVersion: Int?)

    /**
     * Probe StrongBox once by generating a throwaway StrongBox-backed attested key, capturing
     * whether it works and the attestationVersion it reports. A device with a TrustedEnvironment
     * but a broken/absent StrongBox (e.g. an unlocked dev unit) reports unavailable — the resolver
     * still offers StrongBox, but routes such keys through generation (at the TEE version) rather
     * than patch.
     */
    private fun probeStrongBox(): StrongBoxProbe {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return StrongBoxProbe(false, null)
        val leaf = tryLeaf(withDeviceIds = false, strongBox = true)
        val version = leaf?.let { runCatching { parse(it).attestationVersion }.getOrNull() }
        val available = leaf != null
        SystemLogger.info(
            "Harvest: StrongBox-backed key generation available = $available (attestationVersion=$version)"
        )
        return StrongBoxProbe(available, version)
    }

    /**
     * One harvested leaf: try a device-properties attestation first (so we capture the real
     * brand/model/… ids), fall back to a plain attestation if the TEE rejects that, and return null
     * only when both fail — which [run] then reports as a broken TEE.
     */
    private fun generateAndFetchLeaf(): X509Certificate? =
        tryLeaf(withDeviceIds = true) ?: tryLeaf(withDeviceIds = false)

    private fun tryLeaf(withDeviceIds: Boolean, strongBox: Boolean = false): X509Certificate? {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val gen =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val challenge = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val builder =
                KeyGenParameterSpec.Builder(CHECK_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            if (withDeviceIds && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                builder.setDevicePropertiesAttestationIncluded(true)
            }
            gen.initialize(builder.build())
            gen.generateKeyPair()

            val chain = ks.getCertificateChain(CHECK_ALIAS)
            ks.deleteEntry(CHECK_ALIAS) // always clean up
            if (chain.isNullOrEmpty()) {
                if (!withDeviceIds)
                    SystemLogger.warning("Harvest: empty certificate chain (no working TEE?)")
                null
            } else {
                chain[0] as X509Certificate
            }
        } catch (e: Exception) {
            if (withDeviceIds) {
                SystemLogger.info(
                    "Harvest: device-properties attestation failed; retrying plain (${e.message})"
                )
            } else {
                SystemLogger.warning("Harvest: attested key generation failed (no working TEE?)", e)
            }
            try {
                KeyStore.getInstance("AndroidKeyStore")
                    .apply { load(null) }
                    .deleteEntry(CHECK_ALIAS)
            } catch (ignored: Exception) {}
            null
        }
    }

    private fun parse(leaf: X509Certificate): Record {
        val holder = X509CertificateHolder(leaf.encoded)
        val ext: Extension =
            holder.getExtension(org.bouncycastle.asn1.ASN1ObjectIdentifier(OID))
                ?: throw IllegalStateException("no attestation extension in leaf")

        val kd = ASN1Sequence.getInstance(ext.extnValue.octets)
        val fields = kd.toArray()

        val attestVersion = ASN1Integer.getInstance(fields[KD_ATTEST_VERSION]).positiveValue.toInt()
        val attestSecLevel = ASN1Enumerated.getInstance(fields[KD_ATTEST_SECLEVEL]).value.toInt()
        val keymasterVersion =
            ASN1Integer.getInstance(fields[KD_KEYMASTER_VERSION]).positiveValue.toInt()
        val keymasterSecLevel =
            ASN1Enumerated.getInstance(fields[KD_KEYMASTER_SECLEVEL]).value.toInt()

        var verifiedBootKey: ByteArray? = null
        var verifiedBootHash: ByteArray? = null
        var deviceLocked = true
        var verifiedBootState = 0
        var osVersion: Int? = null
        var osPatchLevel: Int? = null
        var vendorPatchLevel: Int? = null
        var bootPatchLevel: Int? = null

        // moduleHash may live in softwareEnforced; captured here, resolved (deduced when absent)
        // below.
        val sw = ASN1Sequence.getInstance(fields[KD_SOFTWARE_ENFORCED])
        val capturedModuleHash =
            sw.toArray()
                .firstOrNull { (it as? ASN1TaggedObject)?.tagNo == TAG_MODULE_HASH }
                ?.let { ASN1OctetString.getInstance((it as ASN1TaggedObject).baseObject).octets }

        val tee = ASN1Sequence.getInstance(fields[KD_TEE_ENFORCED])
        tee.forEach { element ->
            val tagged = element as ASN1TaggedObject
            when (tagged.tagNo) {
                TAG_ROOT_OF_TRUST -> {
                    val rot = ASN1Sequence.getInstance(tagged.baseObject.toASN1Primitive())
                    if (rot.size() >= 4) {
                        verifiedBootKey =
                            ASN1OctetString.getInstance(rot.getObjectAt(ROT_VERIFIED_BOOT_KEY))
                                .octets
                        deviceLocked =
                            ASN1Boolean.getInstance(rot.getObjectAt(ROT_DEVICE_LOCKED)).isTrue
                        verifiedBootState =
                            ASN1Enumerated.getInstance(rot.getObjectAt(ROT_VERIFIED_BOOT_STATE))
                                .value
                                .toInt()
                        verifiedBootHash =
                            ASN1OctetString.getInstance(rot.getObjectAt(ROT_VERIFIED_BOOT_HASH))
                                .octets
                    }
                }
                TAG_OS_VERSION -> osVersion = intOf(tagged)
                TAG_OS_PATCHLEVEL -> osPatchLevel = intOf(tagged)
                TAG_VENDOR_PATCHLEVEL -> vendorPatchLevel = intOf(tagged)
                TAG_BOOT_PATCHLEVEL -> bootPatchLevel = intOf(tagged)
            }
        }

        val fab = mutableMapOf<String, String>()
        // Always attest a locked, Verified device (an unlocked / unverified state fails attestation
        // by construction). The record keeps the RAW captured values; these two get an override
        // only when the device's real value differs — a genuinely locked, Verified device needs
        // none. Values are the machine form ("true", "0"); the WebUI formats them for display.
        if (!deviceLocked) fab["deviceLocked"] = "true"
        if (verifiedBootState != 0) fab["verifiedBootState"] = "0"

        // The RAW captured boot key/hash, exactly as the leaf reported them (all-zero on an
        // unlocked device, or absent). We keep the raw bytes in the record; when they are not
        // usable, buildOverrides adds the value we actually present — see bootKeyOverride /
        // bootHashOverride for the precedence.
        val rawBootKey = verifiedBootKey ?: ByteArray(32)
        val rawBootHash = verifiedBootHash ?: ByteArray(32)

        // When the leaf omits MODULE_HASH, present keystore2's own getSupplementaryAttestationInfo
        // blob (SHA-256'd), or the /apex/apex-info-list.xml reconstruction as a fallback (see
        // resolveModuleHash). The RAW capture stays null; this deduced value is a synthesized
        // override. Resolver re-derives it live at each commit, so this persisted snapshot is only
        // a seed.
        if (capturedModuleHash == null) fab["moduleHash"] = resolveModuleHash().toHex()

        // Device-identity ids parsed per tag. An empty value means the tag was ABSENT from the leaf
        // — device-properties attestation omits imei/meid/serial — not a parse failure.
        val brand = idFrom(sw, tee, TAG_ATTESTATION_ID_BRAND)
        val device = idFrom(sw, tee, TAG_ATTESTATION_ID_DEVICE)
        val product = idFrom(sw, tee, TAG_ATTESTATION_ID_PRODUCT)
        val manufacturer = idFrom(sw, tee, TAG_ATTESTATION_ID_MANUFACTURER)
        val model = idFrom(sw, tee, TAG_ATTESTATION_ID_MODEL)
        val serial = idFrom(sw, tee, TAG_ATTESTATION_ID_SERIAL)
        val imei = idFrom(sw, tee, TAG_ATTESTATION_ID_IMEI)
        val meid = idFrom(sw, tee, TAG_ATTESTATION_ID_MEID)
        val imei2 = idFrom(sw, tee, TAG_ATTESTATION_ID_SECOND_IMEI)
        SystemLogger.info(
            "Harvest: device reports locked=$deviceLocked vbState=$verifiedBootState; attesting locked/Verified"
        )
        // The whole KeyDescription decoded onto one line — every field, and every key parameter in
        // the softwareEnforced/teeEnforced authorization lists, as tag-and-value. This is the
        // ground truth to check a captured id (e.g. the IMEI tag) against, independent of the
        // per-field parsing above.
        SystemLogger.info(
            "Harvest leaf KeyDescription: " +
                kd.joinToString(separator = ", ") { formatAsn1Primitive(it) }
        )
        return Record(
            harvestFailed = false,
            verifiedBootKey = rawBootKey,
            verifiedBootHash = rawBootHash,
            deviceLocked = deviceLocked,
            verifiedBootState = verifiedBootState,
            attestationSecurityLevel = attestSecLevel,
            keymasterSecurityLevel = keymasterSecLevel,
            strongBoxAvailable = false, // set by tryHarvest's probe via copy()
            strongBoxAttestationVersion =
                attestVersion, // replaced by the StrongBox probe in tryHarvest
            attestationVersion = attestVersion,
            keymasterVersion = keymasterVersion,
            osVersion = osVersion,
            osPatchLevel = osPatchLevel,
            vendorPatchLevel = vendorPatchLevel,
            bootPatchLevel = bootPatchLevel,
            moduleHash = capturedModuleHash,
            brand = brand,
            device = device,
            product = product,
            manufacturer = manufacturer,
            model = model,
            serial = serial,
            imei = imei,
            meid = meid,
            imei2 = imei2,
            overrides = buildOverrides(fab, rawBootKey, rawBootHash),
            harvestedAt = System.currentTimeMillis(),
        )
    }

    private fun intOf(t: ASN1TaggedObject): Int =
        ASN1Integer.getInstance(t.baseObject.toASN1Primitive()).positiveValue.toInt()

    // --- module hash deduction --------------------------------------------------
    // getSupplementaryAttestationInfo(MODULE_HASH) returns a DER blob whose SHA-256 is the
    // MODULE_HASH tag (724), so that digest is exactly what our attested tag must carry. We take it
    // from keystore2 directly when available; otherwise we reproduce it from apexd's own module
    // list — a DER SET OF SEQUENCE{ OCTET_STRING name, INTEGER version } over every active APEX,
    // members ordered by the DER encoding of the name alone (keystore2's maintenance.rs
    // encode_module_info), SHA-256'd.

    /**
     * The MODULE_HASH to attest. `getSupplementaryAttestationInfo(MODULE_HASH)` returns a DER blob
     * (the stored `ENCODED_MODULE_INFO`, see keystore2's service.rs) whose SHA-256 is the tag-724
     * value, so we must present that exact digest. Precedence:
     * 1. keystore2's own `getSupplementaryAttestationInfo(MODULE_HASH)`, SHA-256'd — the exact blob
     *    keystore2 stores, so the digest matches by construction. Available once keystore2 has
     *    latched the info at boot.
     * 2. a reconstruction from apexd's output file `/apex/apex-info-list.xml`
     *    ([apexInfoListModules]), DER-encoded and hashed exactly as keystore2's maintenance.rs does
     *    (same moduleName + versionCode source apexd feeds getActivePackages) — used when keystore2
     *    has no value yet. apexd writes the file once after activation completes, so it is never
     *    partially populated. Returns 32 zero bytes only if both are unavailable (Resolver then
     *    keeps the persisted value).
     */
    fun resolveModuleHash(): ByteArray {
        Keystore2Service.getSupplementaryAttestationInfo(KM_TAG_MODULE_HASH)?.let { der ->
            SystemLogger.info(
                "moduleHash: via keystore2 getSupplementaryAttestationInfo (${der.size} DER bytes)"
            )
            return sha256(der)
        }
        apexInfoListModules()?.let { modules ->
            SystemLogger.info(
                "moduleHash: keystore2 info unavailable; via /apex/apex-info-list.xml (${modules.size} modules)"
            )
            return sha256(moduleInfoDer(modules))
        }
        SystemLogger.warning(
            "moduleHash: keystore2 and /apex/apex-info-list.xml both unavailable; no module hash"
        )
        return ByteArray(32)
    }

    /**
     * Option 2 for [resolveModuleHash]: the active APEX set read from apexd's canonical output
     * file, `/apex/apex-info-list.xml` — the same (moduleName, versionCode) pairs apexd feeds
     * getActivePackages, but as a plain root-readable file instead of an IApexService binder call.
     * apexd writes it once after every module is activated, so (unlike a live directory scan) it is
     * never partially populated. Attributes are read individually, not by position, since XML
     * attribute order is not guaranteed. Returns null if the file is absent/unreadable/empty.
     */
    private fun apexInfoListModules(): List<Pair<String, Long>>? {
        val file = File("/apex/apex-info-list.xml")
        if (!file.exists()) return null
        return runCatching {
            val xml = file.readText()
            val nameRe = Regex("moduleName=\"([^\"]*)\"")
            val versionRe = Regex("versionCode=\"([^\"]*)\"")
            val activeRe = Regex("isActive=\"([^\"]*)\"")
            Regex("<apex-info\\b[^>]*>")
                .findAll(xml)
                .mapNotNull { match ->
                    val tag = match.value
                    if (activeRe.find(tag)?.groupValues?.get(1) != "true") return@mapNotNull null
                    val name = nameRe.find(tag)?.groupValues?.get(1) ?: return@mapNotNull null
                    val version =
                        versionRe.find(tag)?.groupValues?.get(1)?.toLongOrNull()
                            ?: return@mapNotNull null
                    name to version
                }
                .toList()
                .ifEmpty { null }
        }
            .getOrElse {
                SystemLogger.warning(
                    "apexInfoListModules: failed to parse /apex/apex-info-list.xml",
                    it,
                )
                null
            }
    }

    /**
     * DER-encode a module list the way keystore2 does (maintenance.rs `encode_module_info`): a SET
     * OF SEQUENCE{ OCTET_STRING name, INTEGER version }, the SET ordered by each name's
     * OCTET_STRING encoding only (keystore2's `DerOrd for ModuleInfo` sorts by name, not the whole
     * element as strict X.690 would). BouncyCastle's DERSet would re-sort by the whole encoding, so
     * the SET is assembled and tagged by hand: sort the SEQUENCE encodings by their name's
     * encoding, then wrap in a DER SET (0x31).
     */
    private fun moduleInfoDer(infos: List<Pair<String, Long>>): ByteArray {
        val members = infos.map { (name, version) ->
            val nameOctet = DEROctetString(name.toByteArray(Charsets.UTF_8))
            val seq =
                DERSequence(
                    ASN1EncodableVector().apply {
                        add(nameOctet)
                        add(ASN1Integer(version))
                    }
                )
            nameOctet.encoded to seq.encoded
        }
        val payload = ByteArrayOutputStream()
        members
            .sortedWith { a, b -> compareBytes(a.first, b.first) }
            .forEach { payload.write(it.second) }
        return derSet(payload.toByteArray())
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    /** Unsigned lexicographic byte comparison — the order DER uses for its SET members. */
    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    /**
     * Wrap an already-ordered concatenation of members in a DER SET (tag 0x31) with a DER length.
     */
    private fun derSet(payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x31)
        if (payload.size < 128) {
            out.write(payload.size)
        } else {
            val lenBytes = ArrayList<Int>()
            var n = payload.size
            while (n > 0) {
                lenBytes.add(n and 0xFF)
                n = n ushr 8
            }
            out.write(0x80 or lenBytes.size)
            for (i in lenBytes.indices.reversed()) out.write(lenBytes[i])
        }
        out.write(payload)
        return out.toByteArray()
    }

    /**
     * Recursively formats any ASN.1 value into one concise, readable token: integers/enumerated as
     * their number, an octet string as "text" when printable else #hex, a tagged object as
     * [TAG n]<inner>, a sequence as [ … ], a set as { … }. Applied over a KeyDescription it renders
     * the entire authorization list — every key parameter — on a single log line.
     */
    private fun formatAsn1Primitive(obj: ASN1Encodable?): String {
        return when (val primitive = obj?.toASN1Primitive()) {
            null -> "NULL"
            is ASN1Integer -> primitive.value.toString()
            is ASN1Enumerated -> primitive.value.toString()
            is ASN1Boolean -> primitive.isTrue.toString()
            is ASN1Null -> "NULL"
            is ASN1OctetString -> {
                val bytes = primitive.octets
                when {
                    bytes.isEmpty() -> "\"\""
                    bytes.all { it >= 32 && it < 127 } -> "\"${String(bytes, Charsets.UTF_8)}\""
                    else -> "#" + bytes.toHex()
                }
            }
            is ASN1TaggedObject ->
                "[TAG ${primitive.tagNo}]${formatAsn1Primitive(primitive.baseObject)}"
            is ASN1Sequence ->
                primitive
                    .map { formatAsn1Primitive(it) }
                    .joinToString(prefix = "[", postfix = "]", separator = ", ")
            is ASN1Set ->
                primitive
                    .map { formatAsn1Primitive(it) }
                    .joinToString(prefix = "{", postfix = "}", separator = ", ")
            else -> primitive.toString()
        }
    }

    /** The UTF-8 value of an attestation-ID tag, searching both enforced lists, or "". */
    private fun idFrom(sw: ASN1Sequence, tee: ASN1Sequence, tag: Int): String {
        for (seq in listOf(sw, tee)) {
            val el =
                seq.toArray().firstOrNull { (it as? ASN1TaggedObject)?.tagNo == tag } ?: continue
            return try {
                String(
                    ASN1OctetString.getInstance((el as ASN1TaggedObject).baseObject).octets,
                    Charsets.UTF_8,
                )
            } catch (e: Exception) {
                ""
            }
        }
        return ""
    }

    /** A device-identity value from a system property, falling back to the Build constant. */
    private fun buildId(prop: String, fallback: String?): String =
        DeviceProps.prop(prop, "").ifBlank { fallback ?: "" }

    /**
     * The verified-boot HASH override to present when the TEE reported no usable value, and whether
     * it is user-editable — editable ONLY for the last-resort random. We do NOT read
     * `ro.boot.vbmeta.digest`: it is a system property any module can set and it is exactly the
     * value that is missing/unreliable on the affected devices (#228). Instead we compute the AVB
     * vbmeta digest ourselves from the partitions, and only fall back to a per-install random when
     * that computation fails (logged as a warning). Null when the raw capture is already a usable
     * hash — the honest captured value stands.
     */
    private fun bootHashOverride(raw: ByteArray): BootOverride? {
        if (isUsableBootValue(raw)) return null
        VbMeta.computeDigest()?.let {
            SystemLogger.info(
                "boot hash: TEE reported none; using the vbmeta digest computed from partitions"
            )
            return BootOverride(it.toHex(), editable = false)
        }
        SystemLogger.warning(
            "boot hash: TEE reported none and the vbmeta digest could not be computed; using a random per-install fallback"
        )
        return BootOverride(fallbackBootHash().toHex(), editable = true)
    }

    /**
     * The verified-boot KEY override to present when the TEE reported no usable value, and whether
     * it is user-editable — editable only for the synthesized constant. We have no self-computation
     * for the key, so we take the device's own `ro.boot.vbmeta.public_key_digest` when it holds a
     * real value, else a deterministic constant. Either way it must stay stable — it feeds the KEK
     * — so it is never randomized and, once persisted, is pinned by [freezeSynthBoot]. Null when
     * the raw capture is already usable.
     */
    private fun bootKeyOverride(raw: ByteArray): BootOverride? {
        if (isUsableBootValue(raw)) return null
        hexBytes(DeviceProps.prop("ro.boot.vbmeta.public_key_digest", ""))?.let {
            return BootOverride(it.toHex(), editable = false)
        }
        return BootOverride(fallbackBootKey().toHex(), editable = true)
    }

    /** A usable boot value: exactly 32 bytes and not all zero. */
    private fun isUsableBootValue(v: ByteArray?): Boolean =
        v != null && v.size == 32 && v.any { it.toInt() != 0 }

    /** Parse 64 hex chars into 32 non-zero bytes, or null. */
    private fun hexBytes(s: String): ByteArray? {
        val h = s.trim().removePrefix("0x")
        if (h.length != 64 || h.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' })
            return null
        val out =
            ByteArray(32) {
                ((h[it * 2].digitToInt(16) shl 4) or h[it * 2 + 1].digitToInt(16)).toByte()
            }
        return if (out.any { it.toInt() != 0 }) out else null
    }

    // --- fallback (no working TEE) ---------------------------------------------

    private fun fallback(): Record {
        SystemLogger.warning("Harvest failed; synthesizing boot values + Build.VERSION props")
        val osVersion = DeviceProps.deviceOsVersion()
        val osPatchLevel = DeviceProps.toYyyymm(DeviceProps.systemSecurityPatch())
        val vendorPatchLevel = DeviceProps.toYyyymmdd(DeviceProps.vendorSecurityPatch())
        val bootPatchLevel = DeviceProps.toYyyymmdd(DeviceProps.vendorSecurityPatch())
        // Harvest failed: nothing was captured, so every field is raw-empty (all-zero boot bytes,
        // null moduleHash) and every attestation-critical value we present lives in `overrides`.
        // The WebUI hides the Captured group entirely when harvestFailed, so only these synthesized
        // values show.
        val zero = ByteArray(32)
        return Record(
            harvestFailed = true,
            verifiedBootKey = zero,
            verifiedBootHash = zero,
            deviceLocked = false,
            verifiedBootState = 2, // Unverified — nothing was captured
            attestationSecurityLevel = Const.SECLEVEL_TEE,
            keymasterSecurityLevel = Const.SECLEVEL_TEE,
            strongBoxAvailable = false, // no working TEE ⇒ no StrongBox either
            strongBoxAttestationVersion = 300,
            attestationVersion = 300,
            keymasterVersion = 300,
            osVersion = osVersion,
            osPatchLevel = osPatchLevel,
            vendorPatchLevel = vendorPatchLevel,
            bootPatchLevel = bootPatchLevel,
            moduleHash = null,
            brand = buildId("ro.product.brand", Build.BRAND),
            device = buildId("ro.product.device", Build.DEVICE),
            product = buildId("ro.product.name", Build.PRODUCT),
            manufacturer = buildId("ro.product.manufacturer", Build.MANUFACTURER),
            model = buildId("ro.product.model", Build.MODEL),
            serial = "",
            imei = "",
            meid = "",
            imei2 = "",
            // No working TEE: every attestation-critical value is synthesized. The boot key/hash go
            // through buildOverrides, so the hash is still the digest we compute from the vbmeta
            // partitions when we can read them (random only as a last resort), exactly as on the
            // success path.
            overrides =
                buildOverrides(
                    mapOf(
                        "deviceLocked" to "true",
                        "verifiedBootState" to "0",
                        "osVersion" to osVersion.toString(),
                        "osPatchLevel" to osPatchLevel.toString(),
                        "vendorPatchLevel" to vendorPatchLevel.toString(),
                        "bootPatchLevel" to bootPatchLevel.toString(),
                        "moduleHash" to resolveModuleHash().toHex(),
                    ),
                    zero,
                    zero,
                ),
            harvestedAt = System.currentTimeMillis(),
        )
    }

    // The verified-boot KEY must be deterministic and stable across runs: it feeds the reference
    // TA's key-encryption-key (rot_data → tag::hidden), so a value that changed between reboots
    // would make every previously-wrapped keystore blob undecryptable. A fixed non-zero constant
    // keeps the KEK stable. NEVER randomize this.
    private fun fallbackBootKey(): ByteArray = sha256("TEESimulator/verified_boot_key")

    // The verified-boot HASH is attestation-only — it is NOT part of the KEK (the TA's rot_data
    // carries key + locked + state, never the hash), so it can be anything non-zero without
    // touching stored-key decryptability. Generate a per-install random value instead of a shared
    // constant, so every device does not present the same fingerprintable digest. It is regenerated
    // on each harvest but FROZEN into the persisted record by run()/freezeSynthBoot, so the value
    // stays put across reboots — a ro.boot.vbmeta.digest that flapped each boot would itself be a
    // signal.
    private fun fallbackBootHash(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun sha256(s: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray())

    // --- persistence ------------------------------------------------------------

    private fun loadPersisted(): Record? {
        val f = Const.harvestedFile
        if (!f.exists()) return null
        return try {
            fromJson(JSONObject(f.readText()))
        } catch (e: Exception) {
            SystemLogger.warning("Could not read harvested.json; ignoring", e)
            null
        }
    }

    private fun persist(r: Record) {
        try {
            Const.harvestedFile.parentFile?.mkdirs()
            Const.harvestedFile.writeText(toJson(r).toString(2))
        } catch (e: Exception) {
            SystemLogger.error("Failed to write harvested.json", e)
        }
    }

    private val b64 = Base64.getEncoder()
    private val b64d = Base64.getDecoder()

    fun toJson(r: Record): JSONObject =
        JSONObject().apply {
            put("version", 2)
            put("harvestFailed", r.harvestFailed)
            put("frozen", !r.harvestFailed)
            put("verifiedBootKey", b64.encodeToString(r.verifiedBootKey))
            put("verifiedBootHash", b64.encodeToString(r.verifiedBootHash))
            put("deviceLocked", r.deviceLocked)
            put("verifiedBootState", r.verifiedBootState)
            put("attestationSecurityLevel", r.attestationSecurityLevel)
            put("keymasterSecurityLevel", r.keymasterSecurityLevel)
            put("strongBoxAvailable", r.strongBoxAvailable)
            put("strongBoxAttestationVersion", r.strongBoxAttestationVersion)
            put("attestationVersion", r.attestationVersion)
            put("keymasterVersion", r.keymasterVersion)
            put("osVersion", r.osVersion ?: JSONObject.NULL)
            put("osPatchLevel", r.osPatchLevel ?: JSONObject.NULL)
            put("vendorPatchLevel", r.vendorPatchLevel ?: JSONObject.NULL)
            put("bootPatchLevel", r.bootPatchLevel ?: JSONObject.NULL)
            put("moduleHash", r.moduleHash?.let { b64.encodeToString(it) } ?: JSONObject.NULL)
            put("brand", r.brand)
            put("device", r.device)
            put("product", r.product)
            put("manufacturer", r.manufacturer)
            put("model", r.model)
            put("serial", r.serial)
            put("imei", r.imei)
            put("meid", r.meid)
            put("imei2", r.imei2)
            // The override layer, keyed by field. Each carries the machine value we present plus
            // the metadata the WebUI needs: source (badge), editable (show an input), userEdited
            // (came from overrides.json vs computed default). The captured fields above stay raw
            // and honest.
            put(
                "overrides",
                JSONObject().apply {
                    for ((field, ov) in r.overrides) {
                        put(
                            field,
                            JSONObject()
                                .put("value", ov.value)
                                .put("source", ov.source.name.lowercase())
                                .put("editable", ov.editable)
                                .put("userEdited", ov.userEdited),
                        )
                    }
                },
            )
            put("harvestedAt", r.harvestedAt)
        }

    private fun fromJson(o: JSONObject): Record {
        val bootKey = b64d.decode(o.getString("verifiedBootKey"))
        val bootHash = b64d.decode(o.getString("verifiedBootHash"))
        return Record(
            harvestFailed = o.optBoolean("harvestFailed", false),
            verifiedBootKey = bootKey,
            verifiedBootHash = bootHash,
            deviceLocked = o.optBoolean("deviceLocked", true),
            verifiedBootState = o.optInt("verifiedBootState", 0),
            attestationSecurityLevel = o.optInt("attestationSecurityLevel", Const.SECLEVEL_TEE),
            keymasterSecurityLevel = o.optInt("keymasterSecurityLevel", Const.SECLEVEL_TEE),
            strongBoxAvailable = o.optBoolean("strongBoxAvailable", false),
            strongBoxAttestationVersion =
                o.optInt("strongBoxAttestationVersion", o.optInt("attestationVersion", 300)),
            attestationVersion = o.optInt("attestationVersion", 300),
            keymasterVersion = o.optInt("keymasterVersion", 300),
            osVersion = o.optIntOrNull("osVersion"),
            osPatchLevel = o.optIntOrNull("osPatchLevel"),
            vendorPatchLevel = o.optIntOrNull("vendorPatchLevel"),
            bootPatchLevel = o.optIntOrNull("bootPatchLevel"),
            moduleHash = o.optStringOrNull("moduleHash")?.let { b64d.decode(it) },
            brand = o.optString("brand", ""),
            device = o.optString("device", ""),
            product = o.optString("product", ""),
            manufacturer = o.optString("manufacturer", ""),
            model = o.optString("model", ""),
            serial = o.optString("serial", ""),
            imei = o.optString("imei", ""),
            meid = o.optString("meid", ""),
            imei2 = o.optString("imei2", ""),
            overrides = readOverrides(o),
            harvestedAt = o.optLong("harvestedAt", System.currentTimeMillis()),
        )
    }

    /**
     * Rebuild the typed override map from persisted JSON: the v2 `overrides` object (each entry
     * carries its own editable flag), or a legacy v1 `fabricated` value-map. Absent → empty.
     */
    private fun readOverrides(o: JSONObject): Map<String, Override> {
        o.optJSONObject("overrides")?.let { obj ->
            val m = LinkedHashMap<String, Override>()
            for (field in obj.keys()) {
                val e = obj.optJSONObject(field)
                if (e != null) {
                    val src = runCatching {
                        OverrideSource.valueOf(e.optString("source", "required").uppercase())
                    }
                        .getOrDefault(sourceFor(field))
                    m[field] =
                        Override(
                            e.optString("value", ""),
                            src,
                            e.optBoolean("editable", editableFor(field)),
                            e.optBoolean("userEdited", false),
                        )
                }
            }
            return m
        }
        o.optJSONObject("fabricated")?.let { obj ->
            return typedOverrides(obj.keys().asSequence().associateWith { obj.getString(it) })
        }
        return emptyMap()
    }

    private fun JSONObject.optIntOrNull(k: String): Int? =
        if (isNull(k) || !has(k)) null else optInt(k)

    private fun JSONObject.optStringOrNull(k: String): String? =
        if (isNull(k) || !has(k)) null else optString(k)
}
