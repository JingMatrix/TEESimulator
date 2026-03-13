package org.matrix.TEESimulator.logging

import android.hardware.security.keymint.*
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x500.X500Name
import org.matrix.TEESimulator.util.toHex

/**
 * A specialized logger for converting KeyMint `KeyParameter` objects into a human-readable format.
 * This helps in debugging the parameters requested for key generation.
 */
object KeyMintParameterLogger {
    private val algorithmNames: Map<Int, String> by lazy {
        Algorithm::class
            .java
            .fields
            .filter { it.type == Int::class.java }
            .associate { field -> (field.get(null) as Int) to field.name }
    }

    private val ecCurveNames: Map<Int, String> by lazy {
        EcCurve::class
            .java
            .fields
            .filter { it.type == Int::class.java }
            .associate { field -> (field.get(null) as Int) to field.name }
    }

    val blockModeNames: Map<Int, String> by lazy {
        BlockMode::class
            .java
            .fields
            .filter { it.type == Int::class.java }
            .associate { field -> (field.get(null) as Int) to field.name }
    }

    val hardwareAuthenticatorTypeNames: Map<Int, String> by lazy {
        HardwareAuthenticatorType::class
            .java
            .fields
            .filter { it.type == Int::class.java }
            .associate { field -> (field.get(null) as Int) to field.name }
    }

    val keyOriginNames: Map<Int, String> by lazy {
        KeyOrigin::class
            .java
            .fields
            .filter { it.type == Int::class.java }
            .associate { field -> (field.get(null) as Int) to field.name }
    }

    val paddingNames: Map<Int, String> by lazy {
        PaddingMode::class
            .java
            .fields
            .filter { it.type == Int::class.java }
            .associate { field -> (field.get(null) as Int) to field.name }
    }

    val purposeNames: Map<Int, String> by lazy {
        KeyPurpose::class
            .java
            .fields
            .filter { it.type == Int::class.java }
            .associate { field -> (field.get(null) as Int) to field.name }
    }

    private val digestNames: Map<Int, String> by lazy {
        Digest::class
            .java
            .fields
            .filter { it.type == Int::class.java }
            .associate { field -> (field.get(null) as Int) to field.name }
    }

    private val tagNames: Map<Int, String> by lazy {
        Tag::class
            .java
            .fields
            .filter { it.type == Int::class.java }
            .associate { field -> (field.get(null) as Int) to field.name }
    }

    /**
     * Logs a single KeyParameter in a formatted, readable way.
     *
     * @param param The KeyParameter to log.
     */
    fun logParameter(param: KeyParameter) {
        val tagName = tagNames[param.tag] ?: "UNKNOWN_TAG"
        val value = param.value
        val formattedValue: String =
            when (param.tag) {
                Tag.ALGORITHM -> algorithmNames[value.algorithm]
                Tag.BLOCK_MODE -> blockModeNames[value.blockMode]
                Tag.DIGEST -> digestNames[value.digest]
                Tag.EC_CURVE -> ecCurveNames[value.ecCurve]
                Tag.ORIGIN -> keyOriginNames[value.origin]
                Tag.PADDING -> paddingNames[value.paddingMode]
                Tag.PURPOSE -> purposeNames[value.keyPurpose]
                Tag.USER_AUTH_TYPE ->
                    hardwareAuthenticatorTypeNames[value.hardwareAuthenticatorType]
                Tag.AUTH_TIMEOUT,
                Tag.BOOT_PATCHLEVEL,
                Tag.KEY_SIZE,
                Tag.MAC_LENGTH,
                Tag.MIN_MAC_LENGTH,
                Tag.OS_VERSION,
                Tag.OS_PATCHLEVEL,
                Tag.USER_ID,
                Tag.VENDOR_PATCHLEVEL -> value.integer.toString()
                Tag.CERTIFICATE_SERIAL -> BigInteger(value.blob).toString()
                Tag.ACTIVE_DATETIME,
                Tag.CERTIFICATE_NOT_AFTER,
                Tag.CERTIFICATE_NOT_BEFORE,
                Tag.CREATION_DATETIME,
                Tag.ORIGINATION_EXPIRE_DATETIME,
                Tag.USAGE_EXPIRE_DATETIME -> Date(value.dateTime).toString()
                Tag.CERTIFICATE_SUBJECT -> X500Name(X500Principal(value.blob).name).toString()
                Tag.USER_SECURE_ID,
                Tag.RSA_PUBLIC_EXPONENT -> value.longInteger.toString()
                Tag.NO_AUTH_REQUIRED -> value.boolValue.toString()
                Tag.ATTESTATION_CHALLENGE,
                Tag.ATTESTATION_ID_BRAND,
                Tag.ATTESTATION_ID_DEVICE,
                Tag.ATTESTATION_ID_PRODUCT,
                Tag.ATTESTATION_ID_MANUFACTURER,
                Tag.ATTESTATION_ID_MODEL,
                Tag.ATTESTATION_ID_IMEI,
                Tag.ATTESTATION_ID_SECOND_IMEI,
                Tag.ATTESTATION_ID_MEID,
                Tag.ATTESTATION_ID_SERIAL -> value.blob.toReadableString()
                else -> "<raw>"
            } ?: "Unknown Value"

        SystemLogger.debug("KeyParam: %-25s | Value: %s".format(tagName, formattedValue))
    }

    private fun ByteArray.toReadableString(): String {
        return if (this.all { it in 32..126 }) {
            "\"${String(this, StandardCharsets.UTF_8)}\" (${this.size} bytes)"
        } else {
            "${this.toHex()} (${this.size} bytes)"
        }
    }
}
