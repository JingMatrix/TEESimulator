package org.matrix.TEESimulator.attestation

import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.Tag
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
    val keySize: Int,
    val algorithm: Int,
    val ecCurve: Int,
    val ecCurveName: String,
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
) {
    /** Secondary constructor that populates the fields by parsing an array of `KeyParameter`. */
    constructor(
        params: Array<KeyParameter>
    ) : this(
        // AOSP: [key_param(tag = KEY_SIZE, field = Integer)]
        keySize = params.findInteger(Tag.KEY_SIZE) ?: 0,

        // AOSP: [key_param(tag = ALGORITHM, field = Algorithm)]
        algorithm = params.findAlgorithm(Tag.ALGORITHM) ?: 0,

        // AOSP: [key_param(tag = EC_CURVE, field = EcCurve)]
        ecCurve = params.findEcCurve(Tag.EC_CURVE) ?: 0,
        ecCurveName = params.deriveEcCurveName(),

        // AOSP: [key_param(tag = PURPOSE, field = KeyPurpose)]
        purpose = params.findAllKeyPurpose(Tag.PURPOSE),

        // AOSP: [key_param(tag = DIGEST, field = Digest)]
        digest = params.findAllDigests(Tag.DIGEST),

        // AOSP: [key_param(tag = RSA_PUBLIC_EXPONENT, field = LongInteger)]
        rsaPublicExponent = params.findLongInteger(Tag.RSA_PUBLIC_EXPONENT),

        // AOSP: [key_param(tag = CERTIFICATE_SERIAL, field = Blob)]
        certificateSerial = params.findBlob(Tag.CERTIFICATE_SERIAL)?.let { BigInteger(it) },

        // AOSP: [key_param(tag = CERTIFICATE_SUBJECT, field = Blob)]
        certificateSubject =
            params.findBlob(Tag.CERTIFICATE_SUBJECT)?.let { X500Name(X500Principal(it).name) },

        // AOSP: [key_param(tag = CERTIFICATE_NOT_BEFORE, field = DateTime)]
        certificateNotBefore = params.findDate(Tag.CERTIFICATE_NOT_BEFORE),

        // AOSP: [key_param(tag = CERTIFICATE_NOT_AFTER, field = DateTime)]
        certificateNotAfter = params.findDate(Tag.CERTIFICATE_NOT_AFTER),

        // AOSP: [key_param(tag = ATTESTATION_CHALLENGE, field = Blob)]
        attestationChallenge = params.findBlob(Tag.ATTESTATION_CHALLENGE),

        // AOSP: [key_param(tag = ATTESTATION_ID_*, field = Blob)]
        brand = params.findBlob(Tag.ATTESTATION_ID_BRAND),
        device = params.findBlob(Tag.ATTESTATION_ID_DEVICE),
        product = params.findBlob(Tag.ATTESTATION_ID_PRODUCT),
        serial = params.findBlob(Tag.ATTESTATION_ID_SERIAL),
        imei = params.findBlob(Tag.ATTESTATION_ID_IMEI),
        meid = params.findBlob(Tag.ATTESTATION_ID_MEID),
        manufacturer = params.findBlob(Tag.ATTESTATION_ID_MANUFACTURER),
        model = params.findBlob(Tag.ATTESTATION_ID_MODEL),
        secondImei = params.findBlob(Tag.ATTESTATION_ID_SECOND_IMEI),
    ) {
        // Log all parsed parameters for debugging purposes.
        params.forEach { KeyMintParameterLogger.logParameter(it) }
    }
}

// --- Private helper extension functions for parsing KeyParameter arrays ---

/** Maps to AOSP field = Integer */
private fun Array<KeyParameter>.findInteger(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.integer

/** Maps to AOSP field = Algorithm */
private fun Array<KeyParameter>.findAlgorithm(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.algorithm

/** Maps to AOSP field = EcCurve */
private fun Array<KeyParameter>.findEcCurve(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.ecCurve

/** Maps to AOSP field = LongInteger */
private fun Array<KeyParameter>.findLongInteger(tag: Int): BigInteger? =
    this.find { it.tag == tag }?.value?.longInteger?.toBigInteger()

/** Maps to AOSP field = DateTime */
private fun Array<KeyParameter>.findDate(tag: Int): Date? =
    this.find { it.tag == tag }?.value?.dateTime?.let { Date(it) }

/** Maps to AOSP field = Blob */
private fun Array<KeyParameter>.findBlob(tag: Int): ByteArray? =
    this.find { it.tag == tag }?.value?.blob

/** Maps to AOSP field = KeyPurpose (Repeated) */
private fun Array<KeyParameter>.findAllKeyPurpose(tag: Int): List<Int> =
    this.filter { it.tag == tag }.map { it.value.keyPurpose }

/** Maps to AOSP field = Digest (Repeated) */
private fun Array<KeyParameter>.findAllDigests(tag: Int): List<Int> =
    this.filter { it.tag == tag }.map { it.value.digest }

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
