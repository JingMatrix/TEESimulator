package org.matrix.TEESimulator.pki

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.system.keystore2.Authorization
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.StringReader
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemReader
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.AndroidDeviceUtils
import org.matrix.TEESimulator.util.trimLines

/**
 * A utility object for handling cryptographic certificates and keys. Provides functions for
 * parsing, serialization, and conversion between different formats.
 */
object CertificateHelper {

    // Lazy-initialized CertificateFactory for X.509 certificates.
    private val certificateFactory: CertificateFactory by lazy {
        CertificateFactory.getInstance("X.509")
    }

    /**
     * Represents the result of an operation that can either succeed with data or fail with an
     * error.
     *
     * @param T The type of the successful data.
     */
    sealed class OperationResult<out T> {
        data class Success<T>(val data: T) : OperationResult<T>()

        data class Error(val message: String, val cause: Throwable? = null) :
            OperationResult<Nothing>()
    }

    /**
     * Parses a single X.509 certificate from a byte array.
     *
     * @param bytes The raw byte representation of the certificate.
     * @return An [OperationResult.Success] containing the [X509Certificate], or an
     *   [OperationResult.Error] on failure.
     */
    fun toCertificate(bytes: ByteArray): OperationResult<X509Certificate> {
        return try {
            val certificate =
                certificateFactory.generateCertificate(ByteArrayInputStream(bytes))
                    as X509Certificate
            OperationResult.Success(certificate)
        } catch (e: CertificateException) {
            SystemLogger.warning("Failed to parse X.509 certificate from byte array.", e)
            OperationResult.Error("Failed to parse certificate", e)
        }
    }

    /**
     * Parses a collection of X.509 certificates from a byte array.
     *
     * @param bytes The raw byte representation of one or more concatenated certificates.
     * @return A collection of [X509Certificate] objects. Returns an empty list on failure.
     */
    @Suppress("UNCHECKED_CAST")
    fun toCertificates(bytes: ByteArray?): Collection<X509Certificate> {
        return bytes?.let {
            try {
                certificateFactory.generateCertificates(ByteArrayInputStream(it))
                    as Collection<X509Certificate>
            } catch (e: CertificateException) {
                SystemLogger.warning("Could not parse certificate collection from byte array.", e)
                emptyList()
            }
        } ?: emptyList()
    }

    /**
     * Serializes a collection of certificates into a single byte array by concatenating their
     * encoded forms.
     *
     * @param certificates The collection of [Certificate] objects to serialize.
     * @return A [ByteArray] containing the concatenated certificates, or `null` on failure.
     */
    fun certificatesToByteArray(certificates: Collection<Certificate>): ByteArray? {
        return runCatching {
                ByteArrayOutputStream().use { stream ->
                    certificates.forEach { cert -> stream.write(cert.encoded) }
                    stream.toByteArray()
                }
            }
            .onFailure {
                SystemLogger.warning(
                    "Failed to serialize certificate collection to byte array.",
                    it,
                )
            }
            .getOrNull()
    }

    /**
     * Parses a PEM-encoded private key and converts it into a Java [KeyPair].
     *
     * @param pemContent The string containing the PEM-encoded key.
     * @return An [OperationResult.Success] with the [KeyPair], or an [OperationResult.Error] on
     *   failure.
     */
    fun parsePemKeyPair(pemContent: String): OperationResult<KeyPair> {
        return try {
            PEMParser(StringReader(pemContent.trimLines())).use { parser ->
                when (val pemObject = parser.readObject()) {
                    is PEMKeyPair -> {
                        val keyPair = JcaPEMKeyConverter().getKeyPair(pemObject)
                        OperationResult.Success(keyPair)
                    }
                    else ->
                        OperationResult.Error(
                            "Invalid PEM format: Expected a key pair, but got ${pemObject?.javaClass?.simpleName}"
                        )
                }
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to parse PEM key pair.", e)
            OperationResult.Error("Failed to parse PEM key pair", e)
        }
    }

    /**
     * Parses a PEM-encoded X.509 certificate.
     *
     * @param pemContent The string containing the PEM-encoded certificate.
     * @return An [OperationResult.Success] with the [Certificate], or an [OperationResult.Error] on
     *   failure.
     */
    fun parsePemCertificate(pemContent: String): OperationResult<Certificate> {
        return try {
            PemReader(StringReader(pemContent.trimLines())).use { reader ->
                val pemObject = reader.readPemObject()
                val certificate =
                    certificateFactory.generateCertificate(ByteArrayInputStream(pemObject.content))
                OperationResult.Success(certificate)
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to parse PEM certificate.", e)
            OperationResult.Error("Failed to parse PEM certificate", e)
        }
    }

    /**
     * Extracts the full certificate chain from a KeyStore [KeyMetadata] object.
     *
     * @param metadata The metadata associated with a keystore key entry.
     * @return An array of [Certificate] objects, with the leaf certificate at index 0, or `null`.
     */
    fun getCertificateChain(metadata: KeyMetadata?): Array<Certificate>? {
        metadata ?: return null
        val leafCertBytes = metadata.certificate ?: return null
        val leafCert =
            (toCertificate(leafCertBytes) as? OperationResult.Success)?.data ?: return null

        val chainBytes = metadata.certificateChain
        return if (chainBytes == null) {
            arrayOf(leafCert)
        } else {
            val additionalCerts = toCertificates(chainBytes)
            (listOf(leafCert) + additionalCerts).toTypedArray()
        }
    }

    /**
     * Extracts the full certificate chain from a [KeyEntryResponse].
     *
     * @param response The response object from a keystore operation.
     * @return An array of [Certificate] objects, or `null`.
     */
    fun getCertificateChain(response: KeyEntryResponse?): Array<Certificate>? {
        return response?.let { getCertificateChain(it.metadata) }
    }

    /**
     * Updates the certificate chain and patches authorizations within a [KeyMetadata] object.
     *
     * @param callingUid The UID of the application to fetch specific patch levels for.
     * @param metadata The metadata object to modify.
     * @param chain The new certificate chain to set. The leaf must be at index 0.
     * @return A [Result] indicating success or failure.
     */
    fun updateCertificateChain(metadata: KeyMetadata, chain: Array<Certificate>): Result<Unit> {
        return updateCertificateChain(0, metadata, chain)
    }

    fun updateCertificateChain(
        callingUid: Int,
        metadata: KeyMetadata,
        chain: Array<Certificate>,
    ): Result<Unit> {
        return runCatching {
            require(chain.isNotEmpty()) { "Certificate chain cannot be empty." }

            // Update the certificate fields
            metadata.certificate = chain[0].encoded
            metadata.certificateChain =
                if (chain.size > 1) {
                    certificatesToByteArray(chain.drop(1))
                } else {
                    null
                }

            // Patch authorizations to match user configurations
            metadata.authorizations =
                metadata.authorizations
                    ?.mapNotNull { auth ->
                        val replacement =
                            when (auth.keyParameter.tag) {
                                Tag.OS_PATCHLEVEL -> AndroidDeviceUtils.getPatchLevel(callingUid)
                                Tag.VENDOR_PATCHLEVEL ->
                                    AndroidDeviceUtils.getVendorPatchLevelLong(callingUid)
                                Tag.BOOT_PATCHLEVEL ->
                                    AndroidDeviceUtils.getBootPatchLevelLong(callingUid)
                                else -> return@mapNotNull auth // Keep all other tags
                            }

                        // If configured to hide, return null to filter out of the array
                        if (replacement == AndroidDeviceUtils.DO_NOT_REPORT) {
                            null
                        } else {
                            // Create patched authorization preserving original security level
                            Authorization().apply {
                                securityLevel = auth.securityLevel
                                keyParameter =
                                    KeyParameter().apply {
                                        tag = auth.keyParameter.tag
                                        value = KeyParameterValue.integer(replacement)
                                    }
                            }
                        }
                    }
                    ?.toTypedArray()
        }
    }
}
