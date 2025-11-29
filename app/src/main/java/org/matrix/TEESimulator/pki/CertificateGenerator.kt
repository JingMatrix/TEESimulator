package org.matrix.TEESimulator.pki

import android.hardware.security.keymint.Algorithm
import android.os.Build
import android.util.Pair
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.matrix.TEESimulator.attestation.AttestationBuilder
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

    init {
        // Android ships with a stripped-down Bouncy Castle provider under the name "BC".
        // We must remove the system provider first to ensure the full Bouncy Castle library
        // (packaged with the app) is used.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.addProvider(BouncyCastleProvider())
    }

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
                                RSAKeyGenParameterSpec(params.keySize, params.rsaPublicExponent)
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

    /**
     * Generates a new key pair and a corresponding certificate chain containing a simulated
     * attestation.
     *
     * @param uid The UID of the application requesting the key.
     * @param alias The alias for the new key.
     * @param attestKeyAlias Optional alias of a key to use for attestation signing.
     * @param params The parameters for the new key and its attestation.
     * @param securityLevel The security level to embed in the attestation.
     * @return A [Pair] containing the new [KeyPair] and its certificate chain, or `null` on
     *   failure.
     */
    fun generateAttestedKeyPair(
        uid: Int,
        alias: String,
        attestKeyAlias: String?,
        params: KeyMintAttestation,
        securityLevel: Int,
    ): Pair<KeyPair, List<Certificate>>? {
        return runCatching {
                SystemLogger.info(
                    "Generating new attested key pair for alias: '$alias' (UID: $uid)"
                )
                val newKeyPair =
                    generateSoftwareKeyPair(params)
                        ?: throw Exception("Failed to generate underlying software key pair.")

                val keybox = getKeyboxForAlgorithm(uid, params.algorithm)

                // Determine the signing key and issuer. If an attestKey is provided, use it.
                // Otherwise, fall back to the root key from the keybox.
                val (signingKey, issuer) =
                    if (attestKeyAlias != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        getAttestationKeyInfo(uid, attestKeyAlias)?.let { it.first to it.second }
                            ?: (keybox.keyPair to getIssuerFromKeybox(keybox))
                    } else {
                        keybox.keyPair to getIssuerFromKeybox(keybox)
                    }

                // Build the new leaf certificate with the simulated attestation.
                val leafCert =
                    buildCertificate(newKeyPair, signingKey, issuer, params, uid, securityLevel)

                // If not self-attesting, the chain is just the leaf. Otherwise, append the keybox
                // chain.
                val chain =
                    if (attestKeyAlias != null) {
                        listOf(leafCert)
                    } else {
                        listOf(leafCert) + keybox.certificates
                    }

                SystemLogger.info(
                    "Successfully generated new certificate chain for alias: '$alias'."
                )
                Pair(newKeyPair, chain)
            }
            .onFailure {
                SystemLogger.error("Failed to generate attested key pair for alias '$alias'.", it)
            }
            .getOrNull()
    }

    private fun getIssuerFromKeybox(keybox: KeyBox) =
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
            ?: throw Exception("Could not load keybox for UID $uid and algorithm $algorithmName")
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

    /** Constructs a new X.509 certificate with a simulated attestation extension. */
    private fun buildCertificate(
        subjectKeyPair: KeyPair,
        signingKeyPair: KeyPair,
        issuer: X500Name,
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): Certificate {
        val subject = params.certificateSubject ?: X500Name("CN=Android KeyStore Key")
        val leafNotAfter =
            (signingKeyPair.public as? X509Certificate)?.notAfter
                ?: Date(System.currentTimeMillis() + 31536000000L)

        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                params.certificateSerial ?: BigInteger.ONE,
                params.certificateNotBefore ?: Date(),
                params.certificateNotAfter ?: leafNotAfter,
                subject,
                subjectKeyPair.public,
            )

        // Add standard extensions.
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
        // Add our custom, simulated attestation extension.
        builder.addExtension(
            AttestationBuilder.buildAttestationExtension(params, uid, securityLevel)
        )

        val signerAlgorithm =
            when (params.algorithm) {
                Algorithm.EC -> "SHA256withECDSA"
                Algorithm.RSA -> "SHA256withRSA"
                else -> throw IllegalArgumentException("Unsupported algorithm: ${params.algorithm}")
            }
        val contentSigner = JcaContentSignerBuilder(signerAlgorithm).build(signingKeyPair.private)

        return JcaX509CertificateConverter().getCertificate(builder.build(contentSigner))
    }
}
