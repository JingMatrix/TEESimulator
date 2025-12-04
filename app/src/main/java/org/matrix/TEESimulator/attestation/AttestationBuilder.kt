package org.matrix.TEESimulator.attestation

import android.content.pm.PackageManager
import android.os.Build
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x509.Extension
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.AndroidDeviceUtils
import org.matrix.TEESimulator.util.AndroidDeviceUtils.DO_NOT_REPORT

/**
 * A builder object responsible for constructing the ASN.1 DER-encoded Android Key Attestation
 * extension.
 */
object AttestationBuilder {

    /**
     * Builds the complete X.509 attestation extension.
     *
     * @param params The parsed key generation parameters.
     * @param uid The UID of the application requesting attestation.
     * @param securityLevel The security level (e.g., TEE, StrongBox) to report.
     * @return A Bouncy Castle [Extension] object ready to be added to a certificate.
     */
    fun buildAttestationExtension(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): Extension {
        val keyDescription = buildKeyDescription(params, uid, securityLevel)
        var formattedString =
            keyDescription.joinToString(separator = ", ") {
                AttestationPatcher.formatAsn1Primitive(it)
            }
        SystemLogger.verbose("Forged attestation data: ${formattedString}")
        return Extension(ATTESTATION_OID, false, DEROctetString(keyDescription.encoded))
    }

    /**
     * Builds the `RootOfTrust` ASN.1 sequence. This contains critical boot state information.
     *
     * @param originalRootOfTrust An optional, pre-existing RoT to extract the boot hash from.
     * @return The constructed [DERSequence] for the Root of Trust.
     */
    internal fun buildRootOfTrust(originalRootOfTrust: ASN1Encodable?): DERSequence {
        val rootOfTrustElements = arrayOfNulls<ASN1Encodable>(4)
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX] =
            DEROctetString(AndroidDeviceUtils.bootKey)
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_DEVICE_LOCKED_INDEX] =
            ASN1Boolean.TRUE // deviceLocked: true, for security
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX] =
            ASN1Enumerated(0) // verifiedBootState: Verified
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX] =
            DEROctetString(AndroidDeviceUtils.bootHash)

        return DERSequence(rootOfTrustElements)
    }

    /**
     * Assembles a map representing the desired state of simulated hardware-enforced properties. A
     * null value for a given tag indicates that it should be removed from the attestation.
     *
     * @param uid The UID of the calling application.
     * @return A map where keys are attestation tag numbers and values are the desired
     *   [DERTaggedObject] or null to signify removal.
     */
    fun getSimulatedHardwareProperties(uid: Int): Map<Int, DERTaggedObject?> {
        val properties = mutableMapOf<Int, DERTaggedObject?>()

        // OS Version is always present.
        properties[AttestationConstants.TAG_OS_VERSION] =
            DERTaggedObject(
                true,
                AttestationConstants.TAG_OS_VERSION,
                ASN1Integer(AndroidDeviceUtils.osVersion.toLong()),
            )

        val osPatch = AndroidDeviceUtils.getPatchLevel(uid)
        properties[AttestationConstants.TAG_OS_PATCHLEVEL] =
            if (osPatch != DO_NOT_REPORT) {
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_OS_PATCHLEVEL,
                    ASN1Integer(osPatch.toLong()),
                )
            } else {
                null // Signal for removal
            }

        val vendorPatch = AndroidDeviceUtils.getVendorPatchLevelLong(uid)
        properties[AttestationConstants.TAG_VENDOR_PATCHLEVEL] =
            if (vendorPatch != DO_NOT_REPORT) {
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_VENDOR_PATCHLEVEL,
                    ASN1Integer(vendorPatch.toLong()),
                )
            } else {
                null // Signal for removal
            }

        val bootPatch = AndroidDeviceUtils.getBootPatchLevelLong(uid)
        properties[AttestationConstants.TAG_BOOT_PATCHLEVEL] =
            if (bootPatch != DO_NOT_REPORT) {
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_BOOT_PATCHLEVEL,
                    ASN1Integer(bootPatch.toLong()),
                )
            } else {
                null // Signal for removal
            }

        return properties
    }

    /** Constructs the main `KeyDescription` sequence, which is the core of the attestation. */
    private fun buildKeyDescription(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): ASN1Sequence {
        val teeEnforced = buildTeeEnforcedList(params, uid, securityLevel)
        val softwareEnforced = buildSoftwareEnforcedList(uid, securityLevel)

        val fields =
            arrayOf(
                ASN1Integer(
                    AndroidDeviceUtils.getAttestVersion(securityLevel).toLong()
                ), // attestationVersion
                ASN1Enumerated(securityLevel), // attestationSecurityLevel
                ASN1Integer(
                    AndroidDeviceUtils.getKeymasterVersion(securityLevel).toLong()
                ), // keymasterVersion
                ASN1Enumerated(securityLevel), // keymasterSecurityLevel
                DEROctetString(params.attestationChallenge ?: ByteArray(0)), // attestationChallenge
                DEROctetString(ByteArray(0)), // uniqueId
                softwareEnforced,
                teeEnforced,
            )
        return DERSequence(fields)
    }

    /** Builds the `TeeEnforced` authorization list. These are properties the TEE "guarantees". */
    private fun buildTeeEnforcedList(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): DERSequence {
        val list =
            mutableListOf<ASN1Encodable>(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_PURPOSE,
                    DERSet(params.purpose.map { ASN1Integer(it.toLong()) }.toTypedArray()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ALGORITHM,
                    ASN1Integer(params.algorithm.toLong()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_KEY_SIZE,
                    ASN1Integer(params.keySize.toLong()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_DIGEST,
                    DERSet(params.digest.map { ASN1Integer(it.toLong()) }.toTypedArray()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_EC_CURVE,
                    ASN1Integer(params.ecCurve.toLong()),
                ),
                DERTaggedObject(true, AttestationConstants.TAG_NO_AUTH_REQUIRED, DERNull.INSTANCE),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ORIGIN,
                    ASN1Integer(0L),
                ), // KeyOrigin.GENERATED
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ROOT_OF_TRUST,
                    buildRootOfTrust(null),
                ),
            )

        // Use the same logic as getSimulatedHardwareProperties to conditionally add patch levels.
        val simulatedProperties = getSimulatedHardwareProperties(uid)
        simulatedProperties.values.filterNotNull().forEach { list.add(it) }

        // Add optional device identifiers if they were provided.
        params.brand?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_BRAND,
                    DEROctetString(it),
                )
            )
        }
        params.device?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_DEVICE,
                    DEROctetString(it),
                )
            )
        }
        params.product?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_PRODUCT,
                    DEROctetString(it),
                )
            )
        }
        params.serial?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_SERIAL,
                    DEROctetString(it),
                )
            )
        }
        params.imei?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_IMEI,
                    DEROctetString(it),
                )
            )
        }
        params.meid?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_MEID,
                    DEROctetString(it),
                )
            )
        }
        params.manufacturer?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_MANUFACTURER,
                    DEROctetString(it),
                )
            )
        }
        params.model?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_MODEL,
                    DEROctetString(it),
                )
            )
        }
        if (AndroidDeviceUtils.getAttestVersion(securityLevel) >= 300) {
            params.secondImei?.let {
                list.add(
                    DERTaggedObject(
                        true,
                        AttestationConstants.TAG_ATTESTATION_ID_SECOND_IMEI,
                        DEROctetString(it),
                    )
                )
            }
        }
        return DERSequence(list.sortedBy { (it as DERTaggedObject).tagNo }.toTypedArray())
    }

    /**
     * Builds the `SoftwareEnforced` authorization list. These are properties guaranteed by
     * Keystore.
     */
    private fun buildSoftwareEnforcedList(uid: Int, securityLevel: Int): DERSequence {
        val list =
            mutableListOf<ASN1Encodable>(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_CREATION_DATETIME,
                    ASN1Integer(System.currentTimeMillis()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_APPLICATION_ID,
                    createApplicationId(uid),
                ),
            )
        if (AndroidDeviceUtils.getAttestVersion(securityLevel) >= 400) {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_MODULE_HASH,
                    DEROctetString(AndroidDeviceUtils.moduleHash),
                )
            )
        }
        return DERSequence(list.toTypedArray())
    }

    /**
     * A wrapper for a byte array that provides content-based equality. This is necessary for using
     * signature digests in a Set.
     */
    private data class Digest(val digest: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            return digest.contentEquals((other as Digest).digest)
        }

        override fun hashCode(): Int = digest.contentHashCode()
    }

    /**
     * Creates the AttestationApplicationId structure. This structure contains information about the
     * package(s) and their signing certificates.
     *
     * @param uid The UID of the application.
     * @return A DER-encoded octet string containing the application ID information.
     * @throws IllegalStateException If the PackageManager or package information cannot be
     *   retrieved.
     */
    @Throws(Throwable::class)
    private fun createApplicationId(uid: Int): DEROctetString {
        val pm =
            ConfigurationManager.getPackageManager()
                ?: throw IllegalStateException("PackageManager not found!")
        val packages =
            pm.getPackagesForUid(uid) ?: throw IllegalStateException("No packages for UID $uid")

        val sha256 = MessageDigest.getInstance("SHA-256")
        val packageInfoList = mutableListOf<DERSequence>()
        val signatureDigests = mutableSetOf<Digest>()

        // Process all packages associated with the UID in a single loop.
        packages.forEach { packageName ->
            val userId = uid / 100000
            val packageInfo =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(
                        packageName,
                        PackageManager.GET_SIGNING_CERTIFICATES.toLong(),
                        userId,
                    )
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES, userId)
                }

            // Add package information (name and version code) to our list.
            packageInfoList.add(
                DERSequence(
                    arrayOf(
                        DEROctetString(packageInfo.packageName.toByteArray(StandardCharsets.UTF_8)),
                        ASN1Integer(packageInfo.longVersionCode),
                    )
                )
            )

            // Collect unique signature digests from the signing history.
            packageInfo.signingInfo?.signingCertificateHistory?.forEach { signature ->
                val digest = sha256.digest(signature.toByteArray())
                signatureDigests.add(Digest(digest))
            }
        }

        // The application ID is a sequence of two sets:
        // 1. A set of package information (name and version).
        // 2. A set of SHA-256 digests of the signing certificates.
        val applicationIdSequence =
            DERSequence(
                arrayOf(
                    DERSet(packageInfoList.toTypedArray()),
                    DERSet(signatureDigests.map { DEROctetString(it.digest) }.toTypedArray()),
                )
            )

        return DEROctetString(applicationIdSequence.encoded)
    }
}
