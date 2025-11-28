package org.matrix.TEESimulator.legacy

import android.content.pm.PackageManager
import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
import android.os.Build
import android.security.keystore.KeyProperties
import android.system.keystore2.KeyDescriptor
import android.util.Pair
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.matrix.TEESimulator.attestation.ATTESTATION_OID
import org.matrix.TEESimulator.config.ConfigurationManager as PkgConfig
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor as SecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger as Logger
import org.matrix.TEESimulator.pki.CertificateHelper
import org.matrix.TEESimulator.pki.KeyBox
import org.matrix.TEESimulator.pki.KeyBoxManager
import org.matrix.TEESimulator.util.AndroidDeviceUtils as AndroidUtils
import org.matrix.TEESimulator.util.toHex

/** Utility for logging KeyMint parameters in a human-readable format. */
object KeyMintTagLogger {
    // Use reflection to build a map from Int -> String for all tags.
    // 'lazy' ensures this heavy work is only done once.
    private val tagNames: Map<Int, String> by lazy {
        Tag::class
            .java
            .fields
            .filter { it.type == Int::class.java }
            .associate { (it.get(null) as Int) to it.name }
    }

    private val algorithmNames =
        mapOf(
            Algorithm.RSA to "RSA",
            Algorithm.EC to "EC",
            Algorithm.AES to "AES",
            Algorithm.TRIPLE_DES to "TRIPLE_DES",
            Algorithm.HMAC to "HMAC",
        )

    private val ecCurveNames =
        mapOf(
            EcCurve.P_224 to "P-224 (secp224r1)",
            EcCurve.P_256 to "P-256 (secp256r1)",
            EcCurve.P_384 to "P-384 (secp384r1)",
            EcCurve.P_521 to "P-521 (secp521r1)",
            EcCurve.CURVE_25519 to "Curve25519",
        )

    private val purposeNames =
        mapOf(
            KeyPurpose.ENCRYPT to "ENCRYPT",
            KeyPurpose.DECRYPT to "DECRYPT",
            KeyPurpose.SIGN to "SIGN",
            KeyPurpose.VERIFY to "VERIFY",
            KeyPurpose.WRAP_KEY to "WRAP_KEY",
            KeyPurpose.ATTEST_KEY to "ATTEST_KEY",
        )

    private val digestNames =
        mapOf(
            Digest.NONE to "NONE",
            Digest.MD5 to "MD5",
            Digest.SHA1 to "SHA1",
            Digest.SHA_2_224 to "SHA-2-224",
            Digest.SHA_2_256 to "SHA-2-256",
            Digest.SHA_2_384 to "SHA-2-384",
            Digest.SHA_2_512 to "SHA-2-512",
        )

    private fun ByteArray.toReadableString(): String {
        if (this.isEmpty()) return "(0 bytes)"
        // Attempt to decode as UTF-8 string if it contains printable ASCII characters
        val printable = this.all { it in 32..126 }
        if (printable) {
            return try {
                "(${this.size} bytes) \"${String(this, StandardCharsets.UTF_8)}\""
            } catch (e: Exception) {
                // Fallback to hex if not a valid string
                "(${this.size} bytes) " + this.joinToString("") { "%02x".format(it) }.take(48)
            }
        }
        return "(${this.size} bytes) " + this.joinToString("") { "%02x".format(it) }.take(48)
    }

    fun logParameter(param: KeyParameter) {
        val tagName = tagNames[param.tag] ?: "UNKNOWN_TAG"
        val value = param.value

        val formattedValue: String =
            when (param.tag) {
                Tag.ALGORITHM ->
                    algorithmNames[value.algorithm] ?: "Unknown Algorithm (${value.algorithm})"
                Tag.EC_CURVE -> ecCurveNames[value.ecCurve] ?: "Unknown Curve (${value.ecCurve})"
                Tag.PURPOSE ->
                    purposeNames[value.keyPurpose] ?: "Unknown Purpose (${value.keyPurpose})"
                Tag.DIGEST -> digestNames[value.digest] ?: "Unknown Digest (${value.digest})"
                Tag.KEY_SIZE,
                Tag.MAC_LENGTH -> value.integer.toString()
                Tag.CERTIFICATE_SERIAL -> BigInteger(value.blob).toString()
                Tag.CERTIFICATE_NOT_BEFORE,
                Tag.CERTIFICATE_NOT_AFTER,
                Tag.CREATION_DATETIME,
                Tag.USAGE_EXPIRE_DATETIME -> Date(value.dateTime).toString()
                Tag.CERTIFICATE_SUBJECT -> X500Name(X500Principal(value.blob).name).toString()
                Tag.RSA_PUBLIC_EXPONENT -> value.longInteger.toString()
                Tag.NO_AUTH_REQUIRED -> "true" // This is a void tag, its presence means true
                Tag.ATTESTATION_CHALLENGE,
                Tag.ATTESTATION_ID_BRAND,
                Tag.ATTESTATION_ID_DEVICE,
                Tag.ATTESTATION_ID_PRODUCT,
                Tag.ATTESTATION_ID_MANUFACTURER,
                Tag.ATTESTATION_ID_MODEL,
                Tag.ATTESTATION_ID_IMEI,
                Tag.ATTESTATION_ID_SECOND_IMEI,
                Tag.ATTESTATION_ID_MEID -> value.blob.toReadableString()
                else -> "<raw value>"
            }

        Logger.debug("Param: %-25s | Value: %s".format(tagName, formattedValue))
    }
}

object CertificateGen {
    private data class Digest(val digest: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Digest
            return digest.contentEquals(other.digest)
        }

        override fun hashCode(): Int = digest.contentHashCode()
    }

    data class KeyGenParameters(
        var keySize: Int = 0,
        var algorithm: Int = 0,
        var certificateSerial: BigInteger? = null,
        var certificateNotBefore: Date? = null,
        var certificateNotAfter: Date? = null,
        var certificateSubject: X500Name? = null,
        var rsaPublicExponent: BigInteger? = null,
        var ecCurve: Int = 0,
        var ecCurveName: String? = null,
        var purpose: MutableList<Int> = mutableListOf(),
        var digest: MutableList<Int> = mutableListOf(),
        var attestationChallenge: ByteArray? = null,
        var brand: ByteArray? = null,
        var device: ByteArray? = null,
        var product: ByteArray? = null,
        var manufacturer: ByteArray? = null,
        var model: ByteArray? = null,
        var imei1: ByteArray? = null,
        var imei2: ByteArray? = null,
        var meid: ByteArray? = null,
        var serialno: ByteArray? = null,
    ) {

        constructor(params: Array<KeyParameter>) : this() {
            params.forEach { param ->
                // Use the new, clean logger. This one line provides detailed, readable logs.
                KeyMintTagLogger.logParameter(param)

                val value = param.value
                when (param.tag) {
                    Tag.KEY_SIZE -> keySize = value.integer
                    Tag.ALGORITHM -> algorithm = value.algorithm
                    Tag.CERTIFICATE_SERIAL -> certificateSerial = BigInteger(value.blob)
                    Tag.CERTIFICATE_NOT_BEFORE -> certificateNotBefore = Date(value.dateTime)
                    Tag.CERTIFICATE_NOT_AFTER -> certificateNotAfter = Date(value.dateTime)
                    Tag.CERTIFICATE_SUBJECT ->
                        certificateSubject = X500Name(X500Principal(value.blob).name)
                    Tag.RSA_PUBLIC_EXPONENT -> rsaPublicExponent = value.longInteger.toBigInteger()
                    Tag.EC_CURVE -> {
                        ecCurve = value.ecCurve
                        ecCurveName = getEcCurveName(ecCurve)
                    }
                    Tag.PURPOSE -> purpose.add(value.keyPurpose)
                    Tag.DIGEST -> digest.add(value.digest)
                    Tag.ATTESTATION_CHALLENGE -> attestationChallenge = value.blob
                    Tag.ATTESTATION_ID_BRAND -> brand = value.blob
                    Tag.ATTESTATION_ID_DEVICE -> device = value.blob
                    Tag.ATTESTATION_ID_PRODUCT -> product = value.blob
                    Tag.ATTESTATION_ID_MANUFACTURER -> manufacturer = value.blob
                    Tag.ATTESTATION_ID_MODEL -> model = value.blob
                    Tag.ATTESTATION_ID_IMEI -> imei1 = value.blob
                    Tag.ATTESTATION_ID_SECOND_IMEI -> imei2 = value.blob
                    Tag.ATTESTATION_ID_MEID -> meid = value.blob
                }
            }
            // Fallback: if no EC curve tag but we know key size
            if (ecCurveName == null && keySize != 0) {
                ecCurveName = ecCurveMapKeySize(keySize)
            }
        }

        private fun ecCurveMapKeySize(curveSize: Int): String =
            when (curveSize) {
                224 -> "secp224r1"
                256 -> "secp256r1"
                384 -> "secp384r1"
                521 -> "secp521r1"
                else -> "secp256r1" // default fallback
            }

        private fun getEcCurveName(curve: Int): String =
            when (curve) {
                EcCurve.CURVE_25519 -> "CURVE_25519"
                EcCurve.P_224 -> "secp224r1"
                EcCurve.P_256 -> "secp256r1"
                EcCurve.P_384 -> "secp384r1"
                EcCurve.P_521 -> "secp521r1"
                else -> throw IllegalArgumentException("Unknown EC curve: $curve")
            }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as KeyGenParameters

            return keySize == other.keySize &&
                algorithm == other.algorithm &&
                certificateSerial == other.certificateSerial &&
                certificateNotBefore == other.certificateNotBefore &&
                certificateNotAfter == other.certificateNotAfter &&
                certificateSubject == other.certificateSubject &&
                rsaPublicExponent == other.rsaPublicExponent &&
                ecCurve == other.ecCurve &&
                ecCurveName == other.ecCurveName &&
                purpose == other.purpose &&
                digest == other.digest &&
                attestationChallenge.contentEquals(other.attestationChallenge) &&
                brand.contentEquals(other.brand) &&
                device.contentEquals(other.device) &&
                product.contentEquals(other.product) &&
                manufacturer.contentEquals(other.manufacturer) &&
                model.contentEquals(other.model) &&
                imei1.contentEquals(other.imei1) &&
                imei2.contentEquals(other.imei2) &&
                meid.contentEquals(other.meid) &&
                serialno.contentEquals(other.serialno)
        }
    }

    fun generateChain(
        uid: Int,
        params: KeyGenParameters,
        keyPair: KeyPair,
        securityLevel: Int = 1,
    ): List<ByteArray>? =
        runCatching {
                val keybox = getKeyboxForAlgorithm(uid, params.algorithm) ?: return null

                val issuer = X509CertificateHolder(keybox.certificates[0].encoded).subject
                val leaf = buildCertificate(keyPair, keybox, params, issuer, uid, securityLevel)

                val chain = buildList {
                    add(leaf)
                    addAll(keybox.certificates)
                }

                CertificateUtils.run { chain.toByteArrayList() }
            }
            .onFailure { Logger.error("Failed to generate certificate chain", it) }
            .getOrNull()

    fun generateKeyPair(params: KeyGenParameters): KeyPair? =
        runCatching {
                Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
                Security.addProvider(BouncyCastleProvider())

                val (keyPairGenerator, spec) =
                    when (params.algorithm) {
                        Algorithm.EC -> {
                            Logger.debug("Generating EC keypair of size ${params.keySize}")
                            val spec = ECGenParameterSpec(params.ecCurveName)
                            val kpg =
                                KeyPairGenerator.getInstance(
                                    "EC",
                                    BouncyCastleProvider.PROVIDER_NAME,
                                )
                            kpg to spec
                        }
                        Algorithm.RSA -> {
                            Logger.debug("Generating RSA keypair of size ${params.keySize}")
                            val spec =
                                RSAKeyGenParameterSpec(params.keySize, params.rsaPublicExponent)
                            val kpg =
                                KeyPairGenerator.getInstance(
                                    "RSA",
                                    BouncyCastleProvider.PROVIDER_NAME,
                                )
                            kpg to spec
                        }
                        else -> {
                            throw IllegalArgumentException(
                                "Unsupported algorithm: ${params.algorithm}"
                            )
                        }
                    }

                keyPairGenerator.initialize(spec)
                keyPairGenerator.generateKeyPair()
            }
            .onFailure { Logger.error("Failed to generate key pair", it) }
            .getOrNull()

    fun generateKeyPair(
        uid: Int,
        descriptor: KeyDescriptor,
        attestKeyDescriptor: KeyDescriptor?,
        params: KeyGenParameters,
        securityLevel: Int = 1,
    ): Pair<KeyPair, List<Certificate>>? =
        runCatching {
                Logger.info("Requested KeyPair with alias: ${descriptor.alias}")

                val hasAttestKey = attestKeyDescriptor != null
                if (hasAttestKey) {
                    Logger.info("Requested KeyPair with attestKey: ${attestKeyDescriptor?.alias}")
                }

                val keyPair = generateKeyPair(params) ?: return null
                val keybox = getKeyboxForAlgorithm(uid, params.algorithm) ?: return null

                val (signingKeyPair, issuer) =
                    if (hasAttestKey) {
                        getAttestationKeyInfo(uid, attestKeyDescriptor!!)?.let {
                            it.first to it.second
                        }
                            ?: (keybox.keyPair to
                                X509CertificateHolder(keybox.certificates[0].encoded).subject)
                    } else {
                        keybox.keyPair to
                            X509CertificateHolder(keybox.certificates[0].encoded).subject
                    }

                val leaf =
                    buildCertificate(
                        keyPair,
                        keybox,
                        params,
                        issuer,
                        uid,
                        securityLevel,
                        signingKeyPair,
                    )
                val chain = buildList {
                    add(leaf)
                    if (!hasAttestKey) {
                        addAll(keybox.certificates)
                    }
                }

                Logger.debug("Successfully generated certificate for alias: ${descriptor.alias}")
                Pair(keyPair, chain)
            }
            .onFailure { Logger.error("Failed to generate key pair with certificates", it) }
            .getOrNull()

    private fun mapAlgorithmToName(algorithm: Int): String? =
        when (algorithm) {
            Algorithm.EC -> KeyProperties.KEY_ALGORITHM_EC
            Algorithm.RSA -> KeyProperties.KEY_ALGORITHM_RSA
            else -> {
                Logger.error("Unsupported algorithm: $algorithm")
                null
            }
        }

    private fun getKeyboxForAlgorithm(uid: Int, algorithm: Int): KeyBox? {
        val algorithmName = mapAlgorithmToName(algorithm) ?: return null
        val keyboxFileName = PkgConfig.getKeyboxFileForUid(uid)
        return KeyBoxManager.getAttestationKey(keyboxFileName, algorithmName)
    }

    private fun getAttestationKeyInfo(
        uid: Int,
        attestKeyDescriptor: KeyDescriptor,
    ): Pair<KeyPair, X500Name>? {
        Logger.debug("Looking for attestation key: uid=$uid alias=${attestKeyDescriptor.alias}")

        val keyId = KeyIdentifier(uid, attestKeyDescriptor.alias)
        val keyInfo = SecurityLevelInterceptor.generatedKeys[keyId]
        return if (keyInfo != null) {
            val certChain = CertificateHelper.getCertificateChain(keyInfo.response)!!
            val issuer = X509CertificateHolder(certChain[0].encoded).subject
            Pair(keyInfo.keyPair, issuer)
        } else {
            Logger.error("Attestation key info not found, falling back to default keybox")
            null
        }
    }

    private fun buildCertificate(
        keyPair: KeyPair,
        keybox: KeyBox,
        params: KeyGenParameters,
        issuer: X500Name,
        uid: Int,
        securityLevel: Int = 1,
        signingKeyPair: KeyPair = keybox.keyPair,
    ): Certificate {
        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                params.certificateSerial ?: BigInteger.ONE,
                params.certificateNotBefore ?: Date(),
                params.certificateNotAfter ?: (keybox.certificates[0] as X509Certificate).notAfter,
                params.certificateSubject ?: X500Name("CN=Android KeyStore Key"),
                keyPair.public,
            )

        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
        builder.addExtension(buildAttestExtension(params, uid, securityLevel))

        val signerAlgorithm =
            when (params.algorithm) {
                Algorithm.EC -> "SHA256withECDSA"
                Algorithm.RSA -> "SHA256withRSA"
                else -> throw IllegalArgumentException("Unsupported algorithm: ${params.algorithm}")
            }
        val contentSigner = JcaContentSignerBuilder(signerAlgorithm).build(signingKeyPair.private)

        return JcaX509CertificateConverter().getCertificate(builder.build(contentSigner))
    }

    private fun buildAttestExtension(
        params: KeyGenParameters,
        uid: Int,
        securityLevel: Int = 1,
    ): Extension {
        try {
            val key = AndroidUtils.bootKey
            val hash = AndroidUtils.getBootHashFromProperty()

            Logger.debug("Using boothash ${hash?.toHex() ?: 0}")

            val rootOfTrustEncodables =
                arrayOf(
                    DEROctetString(key),
                    ASN1Boolean.TRUE,
                    ASN1Enumerated(0),
                    DEROctetString(hash),
                )
            val rootOfTrustSeq = DERSequence(rootOfTrustEncodables)

            val purpose = DERSet(params.purpose.map { ASN1Integer(it.toLong()) }.toTypedArray())
            val algorithm = ASN1Integer(params.algorithm.toLong())
            val keySize = ASN1Integer(params.keySize.toLong())
            val digest = DERSet(params.digest.map { ASN1Integer(it.toLong()) }.toTypedArray())
            val ecCurve = ASN1Integer(params.ecCurve.toLong())
            val noAuthRequired = DERNull.INSTANCE

            val osVersion = ASN1Integer(AndroidUtils.osVersion.toLong())
            val osPatchLevel = ASN1Integer(AndroidUtils.patchLevel.toLong())
            val applicationID = createApplicationId(uid)
            val bootPatchLevel = ASN1Integer(AndroidUtils.bootPatchLevelLong.toLong())
            val vendorPatchLevel = ASN1Integer(AndroidUtils.vendorPatchLevelLong.toLong())
            val creationDateTime = ASN1Integer(System.currentTimeMillis())
            val origin = ASN1Integer(0L)
            val moduleHash = DEROctetString(AndroidUtils.moduleHash)

            val teeEnforcedObjects =
                mutableListOf(
                    DERTaggedObject(true, 1, purpose),
                    DERTaggedObject(true, 2, algorithm),
                    DERTaggedObject(true, 3, keySize),
                    DERTaggedObject(true, 5, digest),
                    DERTaggedObject(true, 10, ecCurve),
                    DERTaggedObject(true, 503, noAuthRequired),
                    DERTaggedObject(true, 702, origin),
                    DERTaggedObject(true, 704, rootOfTrustSeq),
                    DERTaggedObject(true, 705, osVersion),
                    DERTaggedObject(true, 706, osPatchLevel),
                    DERTaggedObject(true, 718, vendorPatchLevel),
                    DERTaggedObject(true, 719, bootPatchLevel),
                )

            if (AndroidUtils.attestVersion >= 400) {
                teeEnforcedObjects.add(DERTaggedObject(true, 724, moduleHash))
            }

            params.brand?.let {
                teeEnforcedObjects.add(DERTaggedObject(true, 710, DEROctetString(it)))
            }
            params.device?.let {
                teeEnforcedObjects.add(DERTaggedObject(true, 711, DEROctetString(it)))
            }
            params.product?.let {
                teeEnforcedObjects.add(DERTaggedObject(true, 712, DEROctetString(it)))
            }
            params.manufacturer?.let {
                teeEnforcedObjects.add(DERTaggedObject(true, 716, DEROctetString(it)))
            }
            params.model?.let {
                teeEnforcedObjects.add(DERTaggedObject(true, 717, DEROctetString(it)))
            }

            params.serialno?.let {
                teeEnforcedObjects.add(DERTaggedObject(true, 713, DEROctetString(it)))
            }
            params.imei1?.let {
                teeEnforcedObjects.add(DERTaggedObject(true, 714, DEROctetString(it)))
            }
            params.meid?.let {
                teeEnforcedObjects.add(DERTaggedObject(true, 715, DEROctetString(it)))
            }

            if (AndroidUtils.attestVersion >= 300) {
                params.imei2?.let {
                    teeEnforcedObjects.add(DERTaggedObject(true, 723, DEROctetString(it)))
                }
            }

            teeEnforcedObjects.sortBy { it.tagNo }

            val softwareEnforcedObjects =
                arrayOf<ASN1Encodable>(
                    DERTaggedObject(true, 709, applicationID),
                    DERTaggedObject(true, 701, creationDateTime),
                )

            return Extension(
                ATTESTATION_OID,
                false,
                buildKeyDescriptionOctet(
                    teeEnforcedObjects.toTypedArray(),
                    softwareEnforcedObjects,
                    params,
                    securityLevel,
                ),
            )
        } catch (t: Throwable) {
            Logger.error("Failed to create attestation extension", t)
            throw t
        }
    }

    private fun buildKeyDescriptionOctet(
        teeEnforcedEncodables: Array<ASN1Encodable>,
        softwareEnforcedEncodables: Array<ASN1Encodable>,
        params: KeyGenParameters,
        securityLevel: Int = 1,
    ): ASN1OctetString {
        val attestationVersion = ASN1Integer(AndroidUtils.attestVersion.toLong())
        val attestationSecurityLevel = ASN1Enumerated(securityLevel)
        val keymasterVersion = ASN1Integer(AndroidUtils.keymasterVersion.toLong())
        val keymasterSecurityLevel = ASN1Enumerated(securityLevel)
        val attestationChallenge = DEROctetString(params.attestationChallenge ?: ByteArray(0))
        val uniqueId = DEROctetString(ByteArray(0))
        val softwareEnforced = DERSequence(softwareEnforcedEncodables)
        val teeEnforced = DERSequence(teeEnforcedEncodables)

        val keyDescriptionEncodables =
            arrayOf(
                attestationVersion,
                attestationSecurityLevel,
                keymasterVersion,
                keymasterSecurityLevel,
                attestationChallenge,
                uniqueId,
                softwareEnforced,
                teeEnforced,
            )

        val keyDescriptionSeq = DERSequence(keyDescriptionEncodables)
        return DEROctetString(keyDescriptionSeq.encoded)
    }

    @Throws(Throwable::class)
    private fun createApplicationId(uid: Int): DEROctetString {
        val pm =
            PkgConfig.getPackageManager()
                ?: throw IllegalStateException("PackageManager not found!")
        val packages =
            pm.getPackagesForUid(uid) ?: throw IllegalStateException("No packages for UID $uid")

        val messageDigest = MessageDigest.getInstance("SHA-256")
        val signatures = mutableSetOf<Digest>()

        val packageInfos =
            packages.map { packageName ->
                val info =
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        pm.getPackageInfo(
                            packageName,
                            PackageManager.GET_SIGNING_CERTIFICATES.toLong(),
                            uid / 100000,
                        )
                    } else {
                        pm.getPackageInfo(
                            packageName,
                            PackageManager.GET_SIGNING_CERTIFICATES,
                            uid / 100000,
                        )
                    }

                info.signingInfo?.signingCertificateHistory?.forEach { signature ->
                    signatures.add(Digest(messageDigest.digest(signature.toByteArray())))
                }

                info
            }

        val packageInfoArray =
            packageInfos
                .map { info ->
                    DERSequence(
                        arrayOf(
                            DEROctetString(info.packageName.toByteArray(StandardCharsets.UTF_8)),
                            ASN1Integer(info.longVersionCode),
                        )
                    )
                }
                .toTypedArray()

        val signaturesArray = signatures.map { DEROctetString(it.digest) }.toTypedArray()

        val applicationIdArray = arrayOf(DERSet(packageInfoArray), DERSet(signaturesArray))

        return DEROctetString(DERSequence(applicationIdArray).encoded)
    }
}
