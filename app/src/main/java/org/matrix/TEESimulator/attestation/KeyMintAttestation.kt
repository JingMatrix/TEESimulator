package org.matrix.TEESimulator.attestation

import android.hardware.security.keymint.*
import java.math.BigInteger
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x500.X500Name
import org.matrix.TEESimulator.logging.KeyMintParameterLogger

/**
 * A data class that parses and holds the parameters required for KeyMint key generation and
 * attestation. It provides a structured way to access the properties defined by an array of
 * `KeyParameter` objects.
 */

// Reference:
// https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/key_parameter.rs
data class KeyMintAttestation(
    val algorithm: Int,
    val ecCurve: Int?,
    val ecCurveName: String,
    val keySize: Int,
    val origin: Int?,
    val noAuthRequired: Boolean?,
    val blockMode: List<Int>,
    val padding: List<Int>,
    val purpose: List<Int>,
    val digest: List<Int>,
    val rsaPublicExponent: BigInteger?,
    val certificateSerial: BigInteger?,
    val certificateSubject: X500Name?,
    val certificateNotBefore: Date?,
    val certificateNotAfter: Date?,
    val attestationChallenge: ByteArray?,
    val brand: ByteArray?,
    val device: ByteArray?,
    val product: ByteArray?,
    val serial: ByteArray?,
    val imei: ByteArray?,
    val meid: ByteArray?,
    val manufacturer: ByteArray?,
    val model: ByteArray?,
    val secondImei: ByteArray?,
    // key_parameter.rs: l=855..1041 (RSA_OAEP_MGF_DIGEST through MAX_BOOT_LEVEL)
    val userAuthType: Int? = null,
    val userConfirmationRequired: Boolean? = null,
    val activeDateTime: Date? = null,
    val originationExpireDateTime: Date? = null,
    val usageExpireDateTime: Date? = null,
    val usageCountLimit: Int? = null,
    val callerNonce: Boolean? = null,
    val unlockedDeviceRequired: Boolean? = null,
    val includeUniqueId: Boolean? = null,
    val rollbackResistance: Boolean? = null,
    val earlyBootOnly: Boolean? = null,
    val allowWhileOnBody: Boolean? = null,
    val trustedUserPresenceRequired: Boolean? = null,
    val trustedConfirmationRequired: Boolean? = null,
    val maxUsesPerBoot: Int? = null,
    val maxBootLevel: Int? = null,
    val minMacLength: Int? = null,
    val rsaOaepMgfDigest: List<Int> = emptyList(),
) {
    /** Secondary constructor that populates the fields by parsing an array of `KeyParameter`. */
    constructor(
        params: Array<KeyParameter>
    ) : this(
        // AOSP: [key_param(tag = ALGORITHM, field = Algorithm)] (key_parameter.rs: l=837)
        algorithm = params.findAlgorithm(Tag.ALGORITHM) ?: 0,

        // AOSP: [key_param(tag = KEY_SIZE, field = Integer)]
        // For EC keys, derive keySize from EC_CURVE when KEY_SIZE is absent.
        // https://cs.android.com/android/platform/superproject/main/+/main:system/keymaster/km_openssl/ec_key_factory.cpp;l=54
        keySize = params.findInteger(Tag.KEY_SIZE) ?: params.deriveKeySizeFromCurve(),

        // AOSP: [key_param(tag = EC_CURVE, field = EcCurve)] (key_parameter.rs: l=871)
        ecCurve = params.findEcCurve(Tag.EC_CURVE),
        ecCurveName = params.deriveEcCurveName(),

        // AOSP: [key_param(tag = ORIGIN, field = Origin)] (key_parameter.rs: l=955)
        origin = params.findOrigin(Tag.ORIGIN),

        // AOSP: [key_param(tag = NO_AUTH_REQUIRED, field = BoolValue)] (key_parameter.rs: l=917)
        noAuthRequired = params.findBoolean(Tag.NO_AUTH_REQUIRED),

        // AOSP: [key_param(tag = BLOCK_MODE, field = BlockMode)] (key_parameter.rs: l=845)
        blockMode = params.findAllBlockMode(Tag.BLOCK_MODE),

        // AOSP: [key_param(tag = PADDING, field = PaddingMode)] (key_parameter.rs: l=860)
        padding = params.findAllPaddingMode(Tag.PADDING),

        // AOSP: [key_param(tag = PURPOSE, field = KeyPurpose)] (key_parameter.rs: l=832)
        purpose = params.findAllKeyPurpose(Tag.PURPOSE),

        // AOSP: [key_param(tag = DIGEST, field = Digest)] (key_parameter.rs: l=850)
        digest = params.findAllDigests(Tag.DIGEST),

        // AOSP: [key_param(tag = RSA_PUBLIC_EXPONENT, field = LongInteger)] (key_parameter.rs:
        // l=874)
        rsaPublicExponent = params.findLongInteger(Tag.RSA_PUBLIC_EXPONENT),

        // AOSP: [key_param(tag = CERTIFICATE_SERIAL, field = Blob)] (key_parameter.rs: l=1028)
        certificateSerial = params.findBlob(Tag.CERTIFICATE_SERIAL)?.let { BigInteger(it) },

        // AOSP: [key_param(tag = CERTIFICATE_SUBJECT, field = Blob)] (key_parameter.rs: l=1032)
        certificateSubject =
            params.findBlob(Tag.CERTIFICATE_SUBJECT)?.let { X500Name(X500Principal(it).name) },

        // AOSP: [key_param(tag = CERTIFICATE_NOT_BEFORE, field = DateTime)] (key_parameter.rs:
        // l=1035)
        certificateNotBefore = params.findDate(Tag.CERTIFICATE_NOT_BEFORE),

        // AOSP: [key_param(tag = CERTIFICATE_NOT_AFTER, field = DateTime)] (key_parameter.rs:
        // l=1038)
        certificateNotAfter = params.findDate(Tag.CERTIFICATE_NOT_AFTER),

        // AOSP: [key_param(tag = ATTESTATION_CHALLENGE, field = Blob)] (key_parameter.rs: l=970)
        attestationChallenge = params.findBlob(Tag.ATTESTATION_CHALLENGE),

        // AOSP: [key_param(tag = ATTESTATION_ID_*, field = Blob)] (key_parameter.rs: l=976, 991,
        // 1000)
        brand = params.findBlob(Tag.ATTESTATION_ID_BRAND),
        device = params.findBlob(Tag.ATTESTATION_ID_DEVICE),
        product = params.findBlob(Tag.ATTESTATION_ID_PRODUCT),
        serial = params.findBlob(Tag.ATTESTATION_ID_SERIAL),
        imei = params.findBlob(Tag.ATTESTATION_ID_IMEI),
        meid = params.findBlob(Tag.ATTESTATION_ID_MEID),
        manufacturer = params.findBlob(Tag.ATTESTATION_ID_MANUFACTURER),
        model = params.findBlob(Tag.ATTESTATION_ID_MODEL),
        secondImei = params.findBlob(Tag.ATTESTATION_ID_SECOND_IMEI),
        // Enforcement tags.
        // key_parameter.rs: l=855..1041 (RSA_OAEP_MGF_DIGEST through MAX_BOOT_LEVEL)
        userAuthType = params.findInteger(Tag.USER_AUTH_TYPE),
        userConfirmationRequired = params.findBoolean(Tag.USER_SECURE_ID),
        activeDateTime = params.findDate(Tag.ACTIVE_DATETIME),
        originationExpireDateTime = params.findDate(Tag.ORIGINATION_EXPIRE_DATETIME),
        usageExpireDateTime = params.findDate(Tag.USAGE_EXPIRE_DATETIME),
        usageCountLimit = params.findInteger(Tag.USAGE_COUNT_LIMIT),
        callerNonce = params.findBoolean(Tag.CALLER_NONCE),
        unlockedDeviceRequired = params.findBoolean(Tag.UNLOCKED_DEVICE_REQUIRED),
        includeUniqueId = params.findBoolean(Tag.INCLUDE_UNIQUE_ID),
        rollbackResistance = params.findBoolean(Tag.ROLLBACK_RESISTANCE),
        earlyBootOnly = params.findBoolean(Tag.EARLY_BOOT_ONLY),
        allowWhileOnBody = params.findBoolean(Tag.ALLOW_WHILE_ON_BODY),
        trustedUserPresenceRequired = params.findBoolean(Tag.TRUSTED_USER_PRESENCE_REQUIRED),
        trustedConfirmationRequired = params.findBoolean(Tag.TRUSTED_CONFIRMATION_REQUIRED),
        maxUsesPerBoot = params.findInteger(Tag.MAX_USES_PER_BOOT),
        maxBootLevel = params.findInteger(Tag.MAX_BOOT_LEVEL),
        minMacLength = params.findInteger(Tag.MIN_MAC_LENGTH),
        // key_parameter.rs: l=855
        rsaOaepMgfDigest = params.findAllDigests(Tag.RSA_OAEP_MGF_DIGEST),
    ) {
        // Log all parsed parameters for debugging purposes.
        params.forEach { KeyMintParameterLogger.logParameter(it) }
    }

    fun isAttestKey(): Boolean {
        return purpose.size == 1 && purpose.contains(KeyPurpose.ATTEST_KEY)
    }

    fun isImportKey(): Boolean {
        return origin == KeyOrigin.IMPORTED || origin == KeyOrigin.SECURELY_IMPORTED
    }
}

// --- Private helper extension functions for parsing KeyParameter arrays ---

/** Maps to AOSP field = Integer */
private fun Array<KeyParameter>.findBoolean(tag: Int): Boolean? =
    this.find { it.tag == tag }?.value?.boolValue

/** Maps to AOSP field = Integer */
private fun Array<KeyParameter>.findInteger(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.integer

/** Maps to AOSP field = Algorithm */
private fun Array<KeyParameter>.findAlgorithm(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.algorithm

/** Maps to AOSP field = EcCurve */
private fun Array<KeyParameter>.findEcCurve(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.ecCurve

/** Maps to AOSP field = Origin */
private fun Array<KeyParameter>.findOrigin(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.origin

/** Maps to AOSP field = LongInteger */
private fun Array<KeyParameter>.findLongInteger(tag: Int): BigInteger? =
    this.find { it.tag == tag }?.value?.longInteger?.toBigInteger()

/** Maps to AOSP field = DateTime */
private fun Array<KeyParameter>.findDate(tag: Int): Date? =
    this.find { it.tag == tag }?.value?.dateTime?.let { Date(it) }

/** Maps to AOSP field = Blob */
private fun Array<KeyParameter>.findBlob(tag: Int): ByteArray? =
    this.find { it.tag == tag }?.value?.blob

/** Maps to AOSP field = BlockMode (Repeated) */
private fun Array<KeyParameter>.findAllBlockMode(tag: Int): List<Int> =
    this.filter { it.tag == tag }.map { it.value.blockMode }

/** Maps to AOSP field = PaddingMode (Repeated) */
private fun Array<KeyParameter>.findAllPaddingMode(tag: Int): List<Int> =
    this.filter { it.tag == tag }.map { it.value.paddingMode }

/** Maps to AOSP field = KeyPurpose (Repeated) */
private fun Array<KeyParameter>.findAllKeyPurpose(tag: Int): List<Int> =
    this.filter { it.tag == tag }.map { it.value.keyPurpose }

/** Maps to AOSP field = Digest (Repeated) */
private fun Array<KeyParameter>.findAllDigests(tag: Int): List<Int> =
    this.filter { it.tag == tag }.map { it.value.digest }

/**
 * Derives keySize from EC_CURVE tag when KEY_SIZE is not explicitly provided.
 *
 * https://cs.android.com/android/platform/superproject/main/+/main:system/keymaster/km_openssl/ec_key_factory.cpp;l=54
 */
private fun Array<KeyParameter>.deriveKeySizeFromCurve(): Int {
    val curveId = this.find { it.tag == Tag.EC_CURVE }?.value?.ecCurve ?: return 0
    return when (curveId) {
        EcCurve.P_224 -> 224
        EcCurve.P_256,
        EcCurve.CURVE_25519 -> 256
        EcCurve.P_384 -> 384
        EcCurve.P_521 -> 521
        else -> 0
    }
}

/**
 * Derives the EC Curve name. Logic: Checks specific EC_CURVE tag first (field=EcCurve), falls back
 * to KEY_SIZE (field=Integer).
 */
private fun Array<KeyParameter>.deriveEcCurveName(): String {
    // 1. Try to find explicit EC_CURVE tag
    val curveParam = this.find { it.tag == Tag.EC_CURVE }

    if (curveParam != null) {
        val curveId = curveParam.value.ecCurve
        return when (curveId) {
            EcCurve.CURVE_25519 -> "CURVE_25519"
            EcCurve.P_224 -> "secp224r1"
            EcCurve.P_256 -> "secp256r1"
            EcCurve.P_384 -> "secp384r1"
            EcCurve.P_521 -> "secp521r1"
            else -> throw IllegalArgumentException("Unknown EC curve: $curveId")
        }
    }

    // 2. Fallback to key size if the curve tag isn't present
    val keySize = this.findInteger(Tag.KEY_SIZE) ?: 0
    return when (keySize) {
        224 -> "secp224r1"
        384 -> "secp384r1"
        521 -> "secp521r1"
        else -> "secp256r1" // Default fallback
    }
}
