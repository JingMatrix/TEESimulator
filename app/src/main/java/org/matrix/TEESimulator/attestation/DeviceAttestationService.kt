package org.matrix.TEESimulator.attestation

import android.annotation.SuppressLint
import android.app.ActivityThread
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.toHex

/**
 * The ASN.1 Object Identifier for the Key Attestation extension in Android. This is defined in the
 * Android Keystore documentation.
 */
val ATTESTATION_OID: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

/**
 * A service to interact with the device's Trusted Execution Environment (TEE). It provides
 * functionality to check if the TEE is functional and to extract key attestation data from a
 * genuinely generated certificate.
 */
@SuppressLint("PrivateApi")
object DeviceAttestationService {

    /**
     * Holds key data extracted from a genuine device attestation. This data can be used as a
     * baseline for creating simulated attestations.
     *
     * @property verifiedBootKey The verified boot public key digest from the root of trust.
     * @property verifiedBootHash The verified boot hash from the root of trust.
     * @property attestVersion The attestation version (e.g., 400 for KeyMint 4.0).
     * @property keymasterVersion The Keymaster or KeyMint HAL version.
     * @property osVersion The Android OS version integer.
     * @property osPatchLevel The Android security patch level (e.g., 202511).
     * @property vendorPatchLevel The vendor-specific security patch level.
     * @property bootPatchLevel The bootloader's security patch level.
     */
    data class AttestationData(
        val moduleHash: ByteArray?,
        val verifiedBootKey: ByteArray?,
        val verifiedBootHash: ByteArray?,
        val attestVersion: Int?,
        val keymasterVersion: Int?,
        val osVersion: Int?,
        val osPatchLevel: Int?,
        val vendorPatchLevel: Int?,
        val bootPatchLevel: Int?,
    )

    // A unique alias for the key used to perform the TEE functionality check.
    private const val TEE_CHECK_KEY_ALIAS = "TEESimulator_AttestationCheck"

    /**
     * Lazily determines if the device's TEE is functional by attempting to generate an
     * attestation-backed key pair. The result is cached.
     */
    val isTeeFunctional: Boolean by lazy { checkTeeFunctionality() }

    /**
     * Lazily fetches and parses attestation data from a genuinely generated certificate. The result
     * is cached. Returns null if the TEE is not functional or parsing fails.
     */
    val CachedAttestationData: AttestationData? by lazy { fetchAttestationData() }

    /**
     * Checks if the TEE is working correctly by generating a key in the Android Keystore with an
     * attestation challenge.
     *
     * @return `true` if a key with attestation was generated successfully, `false` otherwise.
     */
    private fun checkTeeFunctionality(): Boolean {
        SystemLogger.info("Performing TEE functionality check...")
        return try {
            // Ensure mainline modules and the correct Keystore provider are initialized.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                android.app.ActivityThread.initializeMainlineModules()
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                android.security.keystore2.AndroidKeyStoreProvider.install()
            } else {
                android.security.keystore.AndroidKeyStoreProvider.install()
            }

            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")

            // A random challenge is required for attestation.
            val challenge = ByteArray(16).apply { SecureRandom().nextBytes(this) }

            val spec =
                KeyGenParameterSpec.Builder(TEE_CHECK_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build()

            keyPairGenerator.initialize(spec)
            keyPairGenerator.generateKeyPair()

            SystemLogger.info("TEE functionality check successful.")
            true
        } catch (e: Exception) {
            SystemLogger.warning("TEE functionality check failed.", e)
            false
        }
    }

    /**
     * Retrieves the attestation certificate generated during the TEE check. The key entry is
     * deleted after retrieval to clean up.
     *
     * @return The leaf `X509Certificate` containing the attestation, or `null` if unavailable.
     */
    private fun getAttestationCertificate(): X509Certificate? {
        if (!isTeeFunctional) return null

        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val certChain = keyStore.getCertificateChain(TEE_CHECK_KEY_ALIAS)
            if (certChain.isNullOrEmpty()) {
                SystemLogger.warning("Could not retrieve certificate chain for TEE check key.")
                null
            } else {
                // Clean up the key from the keystore.
                keyStore.deleteEntry(TEE_CHECK_KEY_ALIAS)
                certChain[0] as X509Certificate
            }
        } catch (e: Exception) {
            SystemLogger.error("Error retrieving attestation certificate.", e)
            null
        }
    }

    /**
     * Fetches and parses the attestation data from the certificate's extension.
     *
     * @return An `AttestationData` object, or `null` if the process fails.
     */
    private fun fetchAttestationData(): AttestationData? {
        val leafCert = getAttestationCertificate() ?: return null

        try {
            val leafHolder = X509CertificateHolder(leafCert.encoded)
            val extension: Extension =
                leafHolder.getExtension(ATTESTATION_OID)
                    ?: return null // No attestation extension found.

            // The extension's value is an ASN.1 sequence.
            val keyDescriptionSeq = ASN1Sequence.getInstance(extension.extnValue.octets)
            var formattedString =
                keyDescriptionSeq.joinToString(separator = ", ") {
                    AttestationPatcher.formatAsn1Primitive(it)
                }
            SystemLogger.verbose("Cached attestation data: ${formattedString}")
            val fields = keyDescriptionSeq.toArray()

            val attestVersion =
                ASN1Integer.getInstance(
                        fields[AttestationConstants.KEY_DESCRIPTION_ATTESTATION_VERSION_INDEX]
                    )
                    .positiveValue
                    .toInt()
            val keymasterVersion =
                ASN1Integer.getInstance(
                        fields[AttestationConstants.KEY_DESCRIPTION_KEYMINT_VERSION_INDEX]
                    )
                    .positiveValue
                    .toInt()

            var moduleHash: ByteArray? = null
            var verifiedBootKey: ByteArray? = null
            var verifiedBootHash: ByteArray? = null
            var osVersion: Int? = null
            var osPatchLevel: Int? = null
            var vendorPatchLevel: Int? = null
            var bootPatchLevel: Int? = null

            val softwareEnforced =
                ASN1Sequence.getInstance(
                    fields[AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX]
                )
            if (softwareEnforced.size() >= 3) {
                moduleHash =
                    ASN1OctetString.getInstance(
                            ASN1TaggedObject.getInstance(softwareEnforced.getObjectAt(2)).baseObject
                        )
                        .octets
            }

            val teeEnforced =
                ASN1Sequence.getInstance(
                    fields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX]
                )
            teeEnforced.forEach { element ->
                val tagged = element as ASN1TaggedObject
                when (tagged.tagNo) {
                    AttestationConstants.TAG_ROOT_OF_TRUST -> {
                        val rotSeq = ASN1Sequence.getInstance(tagged.baseObject.toASN1Primitive())
                        if (rotSeq.size() >= 4) {
                            verifiedBootKey =
                                ASN1OctetString.getInstance(
                                        rotSeq.getObjectAt(
                                            AttestationConstants
                                                .ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX
                                        )
                                    )
                                    .octets
                            verifiedBootHash =
                                ASN1OctetString.getInstance(
                                        rotSeq.getObjectAt(
                                            AttestationConstants
                                                .ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX
                                        )
                                    )
                                    .octets
                        }
                    }
                    AttestationConstants.TAG_OS_VERSION -> {
                        osVersion =
                            ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive())
                                .positiveValue
                                .toInt()
                    }
                    AttestationConstants.TAG_OS_PATCHLEVEL -> {
                        osPatchLevel =
                            ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive())
                                .positiveValue
                                .toInt()
                    }
                    AttestationConstants.TAG_VENDOR_PATCHLEVEL -> {
                        vendorPatchLevel =
                            ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive())
                                .positiveValue
                                .toInt()
                    }
                    AttestationConstants.TAG_BOOT_PATCHLEVEL -> {
                        bootPatchLevel =
                            ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive())
                                .positiveValue
                                .toInt()
                    }
                }
            }

            if (verifiedBootKey?.all { it == 0.toByte() } == true) {
                verifiedBootKey = null
            }

            SystemLogger.info(
                "Successfully extracted attestation data: version=$attestVersion, osVersion=$osVersion, osPatch=$osPatchLevel, vendorPatch=$vendorPatchLevel, bootPatch=$bootPatchLevel, moduleHash=${moduleHash?.toHex()}, bootKey=${verifiedBootKey?.toHex()}, bootHash=${verifiedBootHash?.toHex()}"
            )
            return AttestationData(
                moduleHash,
                verifiedBootKey,
                verifiedBootHash,
                attestVersion,
                keymasterVersion,
                osVersion,
                osPatchLevel,
                vendorPatchLevel,
                bootPatchLevel,
            )
        } catch (e: Exception) {
            SystemLogger.error("Failed to parse attestation data from certificate.", e)
            return null
        }
    }
}
