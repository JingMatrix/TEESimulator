package org.matrix.TEESimulator.legacy

import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.StringReader
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemReader
import org.matrix.TEESimulator.logging.SystemLogger as Logger
import org.matrix.TEESimulator.util.trimLines as trimLine

object CertificateUtils {
    sealed class CertificateResult<out T> {
        data class Success<T>(val data: T) : CertificateResult<T>()

        data class Error(val message: String, val cause: Throwable? = null) :
            CertificateResult<Nothing>()

        inline fun <R> map(transform: (T) -> R): CertificateResult<R> =
            when (this) {
                is Success -> Success(transform(data))
                is Error -> this
            }

        fun getOrNull(): T? =
            when (this) {
                is Success -> data
                is Error -> null
            }
    }

    sealed class ParseResult<out T> {
        data class Success<T>(val data: T) : ParseResult<T>()

        data class Error(val message: String, val cause: Throwable? = null) : ParseResult<Nothing>()
    }

    fun ByteArray?.toCertificate(): X509Certificate? {
        return this?.let { bytes ->
            try {
                val certFactory = CertificateFactory.getInstance("X.509")
                certFactory.generateCertificate(ByteArrayInputStream(bytes)) as? X509Certificate
            } catch (e: CertificateException) {
                Logger.warning("Couldn't parse certificate in keystore", e)
                null
            }
        }
    }

    fun ByteArray.toCertificateResult(): CertificateResult<X509Certificate> {
        return try {
            val certFactory = CertificateFactory.getInstance("X.509")
            val certificate =
                certFactory.generateCertificate(ByteArrayInputStream(this)) as X509Certificate
            CertificateResult.Success(certificate)
        } catch (e: CertificateException) {
            CertificateResult.Error("Failed to parse certificate", e)
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun ByteArray?.toCertificates(): Collection<X509Certificate> {
        return this?.let { bytes ->
            try {
                val certFactory = CertificateFactory.getInstance("X.509")
                certFactory.generateCertificates(ByteArrayInputStream(bytes))
                    as Collection<X509Certificate>
            } catch (e: CertificateException) {
                // Logger.w("Couldn't parse certificates in keystore", e)
                emptyList()
            }
        } ?: emptyList()
    }

    fun Collection<Certificate>.toByteArray(): ByteArray? =
        runCatching {
                ByteArrayOutputStream().use { outputStream ->
                    forEach { cert -> outputStream.write(cert.encoded) }
                    outputStream.toByteArray()
                }
            }
            // .onFailure { Logger.w("Failed to convert certificates to byte array", it) }
            .getOrNull()

    fun Collection<Certificate>.toByteArrayList(): List<ByteArray>? =
        runCatching { map { it.encoded } }
            // .onFailure { Logger.w("Failed to convert certificates to byte array list", it) }
            .getOrNull()

    fun KeyMetadata?.getCertificateChain(): Array<Certificate>? {
        val metadata = this ?: return null
        val leafCert = metadata.certificate?.toCertificate() ?: return null

        return when (val chainBytes = metadata.certificateChain) {
            null -> arrayOf(leafCert) // If there's no chain, return the leaf.
            else -> {
                // If there is a chain, combine the leaf with the rest of the chain.
                val additionalCerts = chainBytes.toCertificates()
                buildList {
                        add(leafCert)
                        addAll(additionalCerts)
                    }
                    .toTypedArray()
            }
        }
    }

    fun KeyEntryResponse?.getCertificateChain(): Array<Certificate>? {
        return this?.metadata?.getCertificateChain()
    }

    fun KeyEntryResponse.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
        return runCatching { metadata.putCertificateChain(chain) }
    }

    fun KeyMetadata.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
        return runCatching {
            if (chain.isEmpty()) return@runCatching

            certificate = chain[0].encoded

            if (chain.size > 1) {
                ByteArrayOutputStream().use { output ->
                    for (i in 1 until chain.size) {
                        output.write(chain[i].encoded)
                    }
                    certificateChain = output.toByteArray()
                }
            } else {
                certificateChain = null
            }
        }
    }

    // Certificate parsing utilities
    fun parseKeyPair(keyContent: String): ParseResult<PEMKeyPair> {
        return try {
            PEMParser(StringReader(keyContent.trimLine())).use { parser ->
                val pemObject = parser.readObject()
                if (pemObject is PEMKeyPair) {
                    ParseResult.Success(pemObject)
                } else {
                    ParseResult.Error("Invalid PEM key pair format")
                }
            }
        } catch (t: Throwable) {
            ParseResult.Error("Failed to parse PEM key pair", t)
        }
    }

    fun parseCertificate(certContent: String): ParseResult<Certificate> {
        return try {
            PemReader(StringReader(certContent.trimLine())).use { reader ->
                val pemObject = reader.readPemObject()
                val certificate =
                    CertificateFactory.getInstance("X.509")
                        .generateCertificate(ByteArrayInputStream(pemObject.content))
                ParseResult.Success(certificate)
            }
        } catch (t: Throwable) {
            ParseResult.Error("Failed to parse certificate", t)
        }
    }

    fun convertPemToKeyPair(pemKeyPair: PEMKeyPair): KeyPair {
        return JcaPEMKeyConverter().getKeyPair(pemKeyPair)
    }

    @Throws(CertificateParsingException::class)
    fun getByteArrayFromAsn1(asn1Encodable: ASN1Encodable): ByteArray {
        return when (asn1Encodable) {
            is DEROctetString -> asn1Encodable.octets
            else ->
                throw CertificateParsingException(
                    "Expected DEROctetString, got ${asn1Encodable::class.simpleName}"
                )
        }
    }
}

fun ByteArray?.toX509Certificate(): X509Certificate? =
    CertificateUtils.run { this@toX509Certificate.toCertificate() }

fun ByteArray?.toX509Certificates(): Collection<X509Certificate> =
    CertificateUtils.run { this@toX509Certificates.toCertificates() }

fun Collection<Certificate>.encodedBytes(): ByteArray? =
    CertificateUtils.run { this@encodedBytes.toByteArray() }

fun Collection<Certificate>.encodedBytesList(): List<ByteArray>? =
    CertificateUtils.run { this@encodedBytesList.toByteArrayList() }

fun KeyEntryResponse.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
    return runCatching { metadata.putCertificateChain(chain).getOrThrow() }
}

fun KeyMetadata.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
    return runCatching {
        if (chain.isEmpty()) return@runCatching

        certificate = chain[0].encoded

        if (chain.size > 1) {
            ByteArrayOutputStream().use { output ->
                for (i in 1 until chain.size) {
                    output.write(chain[i].encoded)
                }
                certificateChain = output.toByteArray()
            }
        } else {
            certificateChain = null
        }
    }
}
