package org.matrix.TEESimulator.attestation

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x509.Extension
import org.matrix.TEESimulator.util.AndroidDeviceUtils

/**
 * A builder object responsible for constructing the ASN.1 DER-encoded Android Key Attestation
 * extension.
 */
object AttestationBuilder {

    /**
     * Builds the complete X.509 attestation extension.
     *
     * @param params The parsed key generation parameters.
     * @param securityLevel The security level (e.g., TEE, StrongBox) to report.
     * @return A Bouncy Castle [Extension] object ready to be added to a certificate.
     */
    fun buildAttestationExtension(params: KeyMintAttestation, securityLevel: Int): Extension {
        val keyDescription = buildKeyDescription(params, securityLevel)
        return Extension(ATTESTATION_OID, false, DEROctetString(keyDescription.encoded))
    }

    /**
     * Builds the `RootOfTrust` ASN.1 sequence. This contains critical boot state information.
     *
     * @param originalRootOfTrust An optional, pre-existing RoT to extract the boot hash from.
     * @return The constructed [DERSequence] for the Root of Trust.
     */
    internal fun buildRootOfTrust(originalRootOfTrust: ASN1Encodable?): DERSequence {
        val verifiedBootKey = AndroidDeviceUtils.bootKey
        val verifiedBootHash =
            (originalRootOfTrust as? ASN1Sequence)?.let {
                // Try to preserve the original boot hash if it exists.
                (it.getObjectAt(AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX)
                        as? ASN1OctetString)
                    ?.octets
            } ?: AndroidDeviceUtils.getBootHashFromProperty()

        val rootOfTrustElements = arrayOfNulls<ASN1Encodable>(4)
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX] =
            DEROctetString(verifiedBootKey)
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_DEVICE_LOCKED_INDEX] =
            ASN1Boolean.TRUE // deviceLocked: true, for security
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX] =
            ASN1Enumerated(0) // verifiedBootState: Verified
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX] =
            DEROctetString(verifiedBootHash)

        return DERSequence(rootOfTrustElements)
    }

    /** Assembles a list of simulated hardware-enforced properties. */
    internal fun addSimulatedHardwareProperties(vector: org.bouncycastle.asn1.ASN1EncodableVector) {
        vector.add(
            DERTaggedObject(
                true,
                AttestationConstants.TAG_OS_VERSION,
                ASN1Integer(AndroidDeviceUtils.osVersion.toLong()),
            )
        )
        vector.add(
            DERTaggedObject(
                true,
                AttestationConstants.TAG_OS_PATCHLEVEL,
                ASN1Integer(AndroidDeviceUtils.patchLevel.toLong()),
            )
        )
        vector.add(
            DERTaggedObject(
                true,
                AttestationConstants.TAG_VENDOR_PATCHLEVEL,
                ASN1Integer(AndroidDeviceUtils.vendorPatchLevelLong.toLong()),
            )
        )
        vector.add(
            DERTaggedObject(
                true,
                AttestationConstants.TAG_BOOT_PATCHLEVEL,
                ASN1Integer(AndroidDeviceUtils.bootPatchLevelLong.toLong()),
            )
        )
    }

    /** Constructs the main `KeyDescription` sequence, which is the core of the attestation. */
    private fun buildKeyDescription(params: KeyMintAttestation, securityLevel: Int): ASN1Sequence {
        val teeEnforced = buildTeeEnforcedList(params)
        val softwareEnforced = buildSoftwareEnforcedList()

        val fields =
            arrayOf(
                ASN1Integer(AndroidDeviceUtils.attestVersion.toLong()), // attestationVersion
                ASN1Enumerated(securityLevel), // attestationSecurityLevel
                ASN1Integer(AndroidDeviceUtils.keymasterVersion.toLong()), // keymasterVersion
                ASN1Enumerated(securityLevel), // keymasterSecurityLevel
                DEROctetString(params.attestationChallenge ?: ByteArray(0)), // attestationChallenge
                DEROctetString(ByteArray(0)), // uniqueId
                softwareEnforced,
                teeEnforced,
            )
        return DERSequence(fields)
    }

    /** Builds the `TeeEnforced` authorization list. These are properties the TEE "guarantees". */
    private fun buildTeeEnforcedList(params: KeyMintAttestation): DERSequence {
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
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_OS_VERSION,
                    ASN1Integer(AndroidDeviceUtils.osVersion.toLong()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_OS_PATCHLEVEL,
                    ASN1Integer(AndroidDeviceUtils.patchLevel.toLong()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_VENDOR_PATCHLEVEL,
                    ASN1Integer(AndroidDeviceUtils.vendorPatchLevelLong.toLong()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_BOOT_PATCHLEVEL,
                    ASN1Integer(AndroidDeviceUtils.bootPatchLevelLong.toLong()),
                ),
            )

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
        params.imei?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_IMEI,
                    DEROctetString(it),
                )
            )
        }
        params.secondImei?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_SECOND_IMEI,
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

        if (AndroidDeviceUtils.attestVersion >= 400) {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_MODULE_HASH,
                    DEROctetString(AndroidDeviceUtils.moduleHash),
                )
            )
        }

        return DERSequence(list.sortedBy { (it as DERTaggedObject).tagNo }.toTypedArray())
    }

    /**
     * Builds the `SoftwareEnforced` authorization list. These are properties guaranteed by
     * Keystore.
     */
    private fun buildSoftwareEnforcedList(): DERSequence {
        val list =
            arrayOf<ASN1Encodable>(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_CREATION_DATETIME,
                    ASN1Integer(System.currentTimeMillis()),
                )
                // The ATTESTATION_APPLICATION_ID is technically software-enforced, but we are
                // omitting it
                // for this simulation as it is complex to generate correctly for arbitrary UIDs.
            )
        return DERSequence(list)
    }
}
