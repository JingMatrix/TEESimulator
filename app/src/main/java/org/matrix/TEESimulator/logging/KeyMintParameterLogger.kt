package org.matrix.TEESimulator.logging

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
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

    private val purposeNames: Map<Int, String> by lazy {
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
                Tag.EC_CURVE -> ecCurveNames[value.ecCurve]
                Tag.PURPOSE -> purposeNames[value.keyPurpose]
                Tag.DIGEST -> digestNames[value.digest]
                Tag.AUTH_TIMEOUT,
                Tag.KEY_SIZE,
                Tag.MIN_MAC_LENGTH -> value.integer.toString()
                Tag.CERTIFICATE_SERIAL -> BigInteger(value.blob).toString()
                Tag.ACTIVE_DATETIME,
                Tag.CERTIFICATE_NOT_AFTER,
                Tag.CERTIFICATE_NOT_BEFORE,
                Tag.ORIGINATION_EXPIRE_DATETIME,
                Tag.USAGE_EXPIRE_DATETIME -> Date(value.dateTime).toString()
                Tag.CERTIFICATE_SUBJECT -> X500Name(X500Principal(value.blob).name).toString()
                Tag.RSA_PUBLIC_EXPONENT -> value.longInteger.toString()
                Tag.NO_AUTH_REQUIRED -> "true"
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
