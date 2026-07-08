package org.matrix.TEESimulator.pki

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyPurpose
import android.os.Build
import android.util.Pair
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.Certificate
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.matrix.TEESimulator.attestation.AttestationBuilder
import org.matrix.TEESimulator.attestation.AttestationConstants
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Responsible for generating new cryptographic key pairs and X.509 certificate chains.
 *
 * This object simulates the behavior of the Android KeyMint/Keymaster HAL by creating certificates
 * that include a fully-featured, simulated attestation extension.
 */
object CertificateGenerator {

    // AOSP utils.rs: pub const UNDEFINED_NOT_AFTER: i64 = 253402300799000i64;
    // RFC 5280 GeneralizedTime maximum: 9999-12-31T23:59:59 UTC (millis since epoch)
    private const val UNDEFINED_NOT_AFTER = 253402300799000L

    /**
     * Generates a software-based cryptographic key pair.
     *
     * @param params The parameters specifying the key's algorithm, size, and other properties.
     * @return A new [KeyPair], or `null` on failure.
     */
    fun generateSoftwareKeyPair(params: KeyMintAttestation): KeyPair? {
        return runCatching {
                val (algorithm, spec) =
                    when (params.algorithm) {
                        Algorithm.EC -> "EC" to ECGenParameterSpec(params.ecCurveName)
                        Algorithm.RSA ->
                            "RSA" to
                                RSAKeyGenParameterSpec(
                                    params.keySize,
                                    params.rsaPublicExponent ?: RSAKeyGenParameterSpec.F4,
                                )
                        else ->
                            throw IllegalArgumentException(
                                "Unsupported algorithm: ${params.algorithm}"
                            )
                    }
                SystemLogger.debug("Generating $algorithm key pair with size ${params.keySize}")
                KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME)
                    .apply { initialize(spec) }
                    .generateKeyPair()
            }
            .onFailure { SystemLogger.error("Failed to generate software key pair.", it) }
            .getOrNull()
    }

    /** True for algorithms that produce a symmetric secret key rather than a key pair. */
    fun isSymmetric(algorithm: Int): Boolean =
        algorithm == Algorithm.AES ||
            algorithm == Algorithm.HMAC ||
            algorithm == Algorithm.TRIPLE_DES

    /**
     * Generates a software-based symmetric secret key (AES / HMAC / 3DES).
     *
     * Symmetric keys have no attestation certificate chain, so callers should return a
     * [KeyMetadata] with an empty certificate list. Returns `null` on failure.
     */
    fun generateSecretKey(params: KeyMintAttestation): SecretKey? {
        return runCatching {
                val algorithm =
                    when (params.algorithm) {
                        Algorithm.AES -> "AES"
                        Algorithm.HMAC ->
                            when (params.digest.firstOrNull()) {
                                android.hardware.security.keymint.Digest.SHA_2_224 -> "HmacSHA224"
                                android.hardware.security.keymint.Digest.SHA_2_384 -> "HmacSHA384"
                                android.hardware.security.keymint.Digest.SHA_2_512 -> "HmacSHA512"
                                android.hardware.security.keymint.Digest.SHA1 -> "HmacSHA1"
                                else -> "HmacSHA256"
                            }
                        Algorithm.TRIPLE_DES -> "DESede"
                        else ->
                            throw IllegalArgumentException(
                                "Not a symmetric algorithm: ${params.algorithm}"
                            )
                    }
                SystemLogger.debug("Generating $algorithm secret key with size ${params.keySize}")
                KeyGenerator.getInstance(algorithm).apply { init(params.keySize) }.generateKey()
            }
            .onFailure { SystemLogger.error("Failed to generate software secret key.", it) }
            .getOrNull()
    }

    /**
     * Generates a certificate chain for a given key pair. This is the primary function for creating
     * attested certificates.
     *
     * @param uid The UID of the application requesting the key.
     * @param subjectKeyPair The key pair for which the certificate will be generated.
     * @param attestKeyAlias Optional alias of a key to use for attestation signing.
     * @param params The parameters for the new key and its attestation.
     * @param securityLevel The security level to embed in the attestation.
     * @return A [List] of [Certificate] forming the new chain, or `null` on failure.
     */
    fun generateCertificateChain(
        uid: Int,
        subjectKeyPair: KeyPair,
        attestKeyAlias: String?,
        params: KeyMintAttestation,
        securityLevel: Int,
    ): List<Certificate>? {
        val challenge = params.attestationChallenge
        if (challenge != null && challenge.size > AttestationConstants.CHALLENGE_LENGTH_LIMIT)
            throw android.os.ServiceSpecificException(
                -21, // INVALID_INPUT_LENGTH (KM_ERROR_INVALID_INPUT_LENGTH)
            )

        return try {
                val keybox = getKeyboxForAlgorithm(uid, params.algorithm)

                // Only when a real, cached attest key is used for signing does the app already
                // hold that key's own chain elsewhere (Android splices it in client-side). In
                // every other case — including the fallback below when the requested attest key
                // isn't cached (e.g. after a process restart) — we forged the issuer ourselves,
                // so the keybox's chain MUST be appended or the leaf has no path to a root.
                val realAttestKeyInfo: Pair<KeyPair, X500Name>? =
                    if (attestKeyAlias != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        getAttestationKeyInfo(uid, attestKeyAlias)
                    } else {
                        null
                    }
                val signingKey: KeyPair
                val issuer: X500Name
                if (realAttestKeyInfo != null) {
                    signingKey = realAttestKeyInfo.first
                    issuer = realAttestKeyInfo.second
                } else {
                    signingKey = keybox.keyPair
                    issuer = getIssuerFromKeybox(keybox)
                }

                val leafCert =
                    buildCertificate(subjectKeyPair, signingKey, issuer, params, uid, securityLevel)

                if (realAttestKeyInfo != null) {
                    listOf(leafCert)
                } else {
                    listOf(leafCert) + keybox.certificates
                }
            } catch (e: android.os.ServiceSpecificException) {
                throw e
            } catch (e: Exception) {
                SystemLogger.error("Failed to generate certificate chain.", e)
                null
            }
    }

    /**
     * A convenience function that combines key pair generation and certificate chain generation.
     * Primarily used by the modern Keystore2 interceptor where generation is a single step.
     */
    fun generateAttestedKeyPair(
        uid: Int,
        alias: String,
        attestKeyAlias: String?,
        params: KeyMintAttestation,
        securityLevel: Int,
    ): Pair<KeyPair, List<Certificate>>? {
        return try {
                SystemLogger.info(
                    "Generating new attested key pair for alias: '$alias' (UID: $uid)"
                )
                val newKeyPair =
                    generateSoftwareKeyPair(params)
                        ?: throw Exception("Failed to generate underlying software key pair.")

                val chain =
                    generateCertificateChain(uid, newKeyPair, attestKeyAlias, params, securityLevel)
                        ?: throw Exception("Failed to generate certificate chain for new key pair.")

                SystemLogger.info(
                    "Successfully generated new certificate chain for alias: '$alias'."
                )
                Pair(newKeyPair, chain)
            } catch (e: android.os.ServiceSpecificException) {
                throw e
            } catch (e: Exception) {
                SystemLogger.error("Failed to generate attested key pair for alias '$alias'.", e)
                null
            }
    }

    fun getIssuerFromKeybox(keybox: KeyBox) =
        X509CertificateHolder(keybox.certificates[0].encoded).subject

    private fun getKeyboxForAlgorithm(uid: Int, algorithm: Int): KeyBox {
        val keyboxFile = ConfigurationManager.getKeyboxFileForUid(uid)
        val algorithmName =
            when (algorithm) {
                Algorithm.EC -> "EC"
                Algorithm.RSA -> "RSA"
                else -> throw IllegalArgumentException("Unsupported algorithm ID: $algorithm")
            }
        return KeyBoxManager.getAttestationKey(keyboxFile, algorithmName)
            ?: throw android.os.ServiceSpecificException(
                -75, // ATTESTATION_KEYS_NOT_PROVISIONED
                "No attestation key for algorithm $algorithmName in $keyboxFile",
            )
    }

    /** Retrieves the key pair and issuer name for a given attestation key alias. */
    private fun getAttestationKeyInfo(uid: Int, attestKeyAlias: String): Pair<KeyPair, X500Name>? {
        SystemLogger.debug("Looking for attestation key: uid=$uid alias=$attestKeyAlias")
        val keyId = KeyIdentifier(uid, attestKeyAlias)
        // Access the public map of generated keys
        val keyInfo = KeyMintSecurityLevelInterceptor.generatedKeys[keyId]
        return if (keyInfo != null) {
            val certChain = CertificateHelper.getCertificateChain(keyInfo.response)
            if (!certChain.isNullOrEmpty()) {
                val issuer = X509CertificateHolder(certChain[0].encoded).subject
                Pair(keyInfo.keyPair, issuer)
            } else {
                null
            }
        } else {
            SystemLogger.warning(
                "Attestation key '$attestKeyAlias' not found in generated key cache."
            )
            null
        }
    }

    /** Maps KeyPurpose values to X.509 KeyUsage bits per KeyCreationResult.aidl spec */
    private fun buildKeyUsageFromPurposes(purposes: List<Int>): Int {
        var bits = 0
        for (purpose in purposes) {
            bits =
                bits or
                    when (purpose) {
                        KeyPurpose.SIGN -> KeyUsage.digitalSignature
                        KeyPurpose.DECRYPT -> KeyUsage.dataEncipherment
                        KeyPurpose.WRAP_KEY -> KeyUsage.keyEncipherment
                        KeyPurpose.AGREE_KEY -> KeyUsage.keyAgreement
                        KeyPurpose.ATTEST_KEY -> KeyUsage.keyCertSign
                        else -> 0
                    }
        }
        return bits
    }

    /** Constructs a new X.509 certificate with a simulated attestation extension. */
    private fun buildCertificate(
        subjectKeyPair: KeyPair,
        signingKeyPair: KeyPair,
        issuer: X500Name,
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): Certificate {
        val subject = params.certificateSubject ?: X500Name("CN=Android Keystore Key")

        // AOSP add_required_parameters (security_level.rs) defaults:
        //   CERTIFICATE_NOT_BEFORE = 0 (Unix epoch)
        //   CERTIFICATE_NOT_AFTER  = 253402300799000 (9999-12-31T23:59:59 UTC)
        val notBefore = params.certificateNotBefore ?: Date(0)
        val notAfter = params.certificateNotAfter ?: Date(UNDEFINED_NOT_AFTER)

        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                params.certificateSerial ?: BigInteger.ONE,
                notBefore,
                notAfter,
                subject,
                subjectKeyPair.public,
            )

        // Add KeyUsage extension only if purposes map to valid bits
        val keyUsageBits = buildKeyUsageFromPurposes(params.purpose)
        if (keyUsageBits != 0) {
            builder.addExtension(Extension.keyUsage, true, KeyUsage(keyUsageBits))
        }
        // Add our custom, simulated attestation extension.
        builder.addExtension(
            AttestationBuilder.buildAttestationExtension(params, uid, securityLevel)
        )

        // The signature algorithm must match the SIGNING key, not the subject key.
        // An EC attestation key may sign an RSA subject key's certificate (or vice versa).
        val signerAlgorithm =
            when (signingKeyPair.private) {
                is ECKey -> "SHA256withECDSA"
                is RSAKey -> "SHA256withRSA"
                else ->
                    throw IllegalArgumentException(
                        "Unsupported signing key type: ${signingKeyPair.private.javaClass}"
                    )
            }
        val contentSigner =
            JcaContentSignerBuilder(signerAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signingKeyPair.private)

        return JcaX509CertificateConverter().getCertificate(builder.build(contentSigner))
    }
}
