package org.matrix.teesim

import java.io.StringReader
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils
import org.bouncycastle.asn1.x509.AuthorityInformationAccess
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.CRLDistPoint
import org.bouncycastle.asn1.x509.CertificatePolicies
import org.bouncycastle.asn1.x509.DistributionPointName
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.json.JSONArray
import org.json.JSONObject

/**
 * The per-certificate and per-private-key reading behind the keybox inspector. [KeyboxInspector]
 * decides what a chain *is* (does it verify, what root does it reach, is it revoked); this decides
 * what each piece of it *says*, which is the part a user reads when the verdict is not the whole
 * story — a keybox that verifies can still be the wrong keybox, carry a private key belonging to a
 * different certificate, or name a build fingerprint that gives away where it came from.
 *
 * Three things here are worth more than the rest:
 *
 * * **Does the private key belong to the leaf.** A keybox pairs a `<PrivateKey>` with a
 *   `<CertificateChain>` and nothing in the file ties them together, so a mismatched pair parses
 *   perfectly and only fails later, at signing time, with no explanation. It is settled here by
 *   signing a fixed probe and verifying it against the leaf's public key: that is a proof of
 *   correspondence rather than a comparison of encodings, and it holds for every key type without
 *   special-casing any of them.
 * * **Is the subjectKeyIdentifier the digest RFC 5280 asks for.** Method 1 defines it as the SHA-1
 *   of the subjectPublicKey BIT STRING, and Google's and AOSP's certificates all follow it, so it
 *   can be recomputed — and a certificate whose identifier does not match the key it carries has
 *   had one of the two swapped.
 * * **provisioningInfo.** Google's RKP certificates carry a small CBOR map (OID …2.1.30) holding,
 *   among other things, the build fingerprint of the device the key was provisioned for. It is the
 *   most identifying thing in a keybox and it is invisible unless something decodes it.
 *
 * Everything returned is text and numbers for the WebUI; no key material ever leaves this object.
 */
object KeyboxDetail {

    private const val OID_SKI = "2.5.29.14"
    private const val OID_AKI = "2.5.29.35"
    private const val OID_CRL_DP = "2.5.29.31"
    private const val OID_POLICIES = "2.5.29.32"
    private const val OID_AIA = "1.3.6.1.5.5.7.1.1"
    private const val OID_BASIC_CONSTRAINTS = "2.5.29.19"
    private const val OID_KEY_USAGE = "2.5.29.15"
    private const val OID_EKU = "2.5.29.37"
    private const val OID_SAN = "2.5.29.17"

    /** Android's two Google-private certificate extensions. */
    private const val OID_ATTESTATION = "1.3.6.1.4.1.11129.2.1.17"
    private const val OID_PROVISIONING = "1.3.6.1.4.1.11129.2.1.30"

    /** The extensions below are reported in their own fields; the rest are listed as raw OIDs. */
    private val HANDLED =
        setOf(
            OID_SKI,
            OID_AKI,
            OID_CRL_DP,
            OID_POLICIES,
            OID_AIA,
            OID_BASIC_CONSTRAINTS,
            OID_KEY_USAGE,
            OID_EKU,
            OID_SAN,
            OID_ATTESTATION,
            OID_PROVISIONING,
        )

    /** keyUsage bits, in the order X509Certificate.getKeyUsage() returns them. */
    private val KEY_USAGE_NAMES =
        listOf(
            "digitalSignature",
            "nonRepudiation",
            "keyEncipherment",
            "dataEncipherment",
            "keyAgreement",
            "keyCertSign",
            "cRLSign",
            "encipherOnly",
            "decipherOnly",
        )

    private val EKU_NAMES =
        mapOf(
            "1.3.6.1.5.5.7.3.1" to "serverAuth",
            "1.3.6.1.5.5.7.3.2" to "clientAuth",
            "1.3.6.1.5.5.7.3.3" to "codeSigning",
            "1.3.6.1.5.5.7.3.4" to "emailProtection",
            "1.3.6.1.5.5.7.3.8" to "timeStamping",
            "1.3.6.1.5.5.7.3.9" to "OCSPSigning",
            "2.5.29.37.0" to "anyExtendedKeyUsage",
        )

    private val ACCESS_METHODS =
        mapOf("1.3.6.1.5.5.7.48.1" to "OCSP", "1.3.6.1.5.5.7.48.2" to "caIssuers")

    /**
     * provisioningInfo's integer keys. The structure is not published, so these labels are read off
     * what the field holds in practice; one that keeps a question mark is a plausible reading
     * rather than a known meaning, which is still better to show than a bare "key 3".
     *
     * The nested map under key 5 is laid out as pairs: an odd key states a verdict on one attribute
     * of the device, and the even key after it carries the value that verdict was passed on. A
     * negative verdict comes with no value at all — the issuer records that it refused, not what it
     * refused — which is why a map can hold a verdict alone but never a value alone.
     *
     * Key 1 is not a count of anything cumulative: it only ever takes powers of two, and the same
     * device is issued different ones over time, so it reads as the size of the batch rather than a
     * running total. Key 3 names the device's manufacturer — not its brand, which on some devices
     * is a different string entirely — and is only ever present where no fingerprint is.
     */
    private val PROVISIONING_FIELDS =
        mapOf(
            1L to "keys in this batch?",
            2L to "attested entity?",
            3L to "manufacturer",
            5L to "checked at provisioning",
        )

    private val PROVISIONING_SUBFIELDS =
        mapOf(
            1L to "verified boot verdict",
            2L to "verified boot hash",
            3L to "build verdict",
            4L to "build fingerprint",
        )

    // --- Certificates -------------------------------------------------------------------

    /** Everything readable in [cert] beyond the fields [KeyboxInspector] already reports. */
    fun details(cert: X509Certificate): JSONObject {
        val out = JSONObject()
        try {
            out.put("fingerprint", sha256(cert.encoded))
        } catch (_: Exception) {}
        curveOf(cert)?.let { out.put("curve", it) }
        // basicConstraints: -1 means "not a CA"; Integer.MAX_VALUE means "CA with no path limit".
        val bc = cert.basicConstraints
        if (bc >= 0) out.put("pathLen", if (bc == Int.MAX_VALUE) -1 else bc)
        cert.keyUsage?.let { bits ->
            val used = JSONArray()
            for (i in KEY_USAGE_NAMES.indices) if (i < bits.size && bits[i])
                used.put(KEY_USAGE_NAMES[i])
            out.put("keyUsage", used)
        }
        try {
            cert.extendedKeyUsage?.let { ekus ->
                val arr = JSONArray()
                for (oid in ekus) arr.put(EKU_NAMES[oid] ?: oid)
                out.put("extendedKeyUsage", arr)
            }
        } catch (_: Exception) {}

        subjectKeyId(cert)?.let { out.put("ski", it) }
        authorityKeyId(cert)?.let { out.put("aki", it) }
        crlPoints(cert)?.let { if (it.length() > 0) out.put("crl", it) }
        accessDescriptions(cert)?.let { if (it.length() > 0) out.put("aia", it) }
        subjectAltNames(cert)?.let { if (it.length() > 0) out.put("san", it) }
        policies(cert)?.let { if (it.length() > 0) out.put("policies", it) }

        if (cert.getExtensionValue(OID_ATTESTATION) != null) out.put("hasAttestation", true)
        provisioning(cert)?.let { out.put("provisioning", it) }

        val others = JSONArray()
        for (oid in (cert.criticalExtensionOIDs ?: emptySet())) if (oid !in HANDLED)
            others.put("$oid (critical)")
        for (oid in (cert.nonCriticalExtensionOIDs ?: emptySet())) if (oid !in HANDLED)
            others.put(oid)
        if (others.length() > 0) out.put("otherExtensions", others)
        return out
    }

    /** The named curve of an EC certificate, by the OID in its SubjectPublicKeyInfo. */
    private fun curveOf(cert: X509Certificate): String? =
        try {
            val spki = SubjectPublicKeyInfo.getInstance(cert.publicKey.encoded)
            val oid = ASN1ObjectIdentifier.getInstance(spki.algorithm.parameters)
            ECNamedCurveTable.getName(oid) ?: oid.id
        } catch (_: Exception) {
            null
        }

    /**
     * The subjectKeyIdentifier, with the RFC 5280 method-1 digest it should be. `expected` is only
     * reported when it differs, so a correct certificate stays quiet.
     */
    private fun subjectKeyId(cert: X509Certificate): JSONObject? {
        val present = extensionOctets(cert, OID_SKI) ?: return null
        return try {
            val id = SubjectKeyIdentifier.getInstance(present).keyIdentifier
            val spki = SubjectPublicKeyInfo.getInstance(cert.publicKey.encoded)
            val expected = MessageDigest.getInstance("SHA-1").digest(spki.publicKeyData.bytes)
            val matches = id.contentEquals(expected)
            JSONObject().put("value", hex(id)).put("isPublicKeySha1", matches).apply {
                if (!matches) put("expected", hex(expected))
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun authorityKeyId(cert: X509Certificate): JSONObject? {
        val present = extensionOctets(cert, OID_AKI) ?: return null
        return try {
            val aki = AuthorityKeyIdentifier.getInstance(present)
            val out = JSONObject()
            aki.keyIdentifierObject?.octets?.let { out.put("value", hex(it)) }
            aki.authorityCertIssuer?.let { out.put("issuer", names(it)) }
            aki.authorityCertSerialNumber?.let { out.put("serial", it.toString(16)) }
            if (out.length() == 0) null else out
        } catch (_: Exception) {
            null
        }
    }

    private fun crlPoints(cert: X509Certificate): JSONArray? {
        val present = extensionOctets(cert, OID_CRL_DP) ?: return null
        return try {
            val out = JSONArray()
            for (dp in CRLDistPoint.getInstance(present).distributionPoints) {
                val name = dp.distributionPoint ?: continue
                if (name.type == DistributionPointName.FULL_NAME) {
                    for (gn in GeneralNames.getInstance(name.name).names) out.put(generalName(gn))
                } else {
                    out.put(name.name.toString())
                }
            }
            out
        } catch (_: Exception) {
            null
        }
    }

    private fun accessDescriptions(cert: X509Certificate): JSONArray? {
        val present = extensionOctets(cert, OID_AIA) ?: return null
        return try {
            val out = JSONArray()
            for (ad in AuthorityInformationAccess.getInstance(present).accessDescriptions) {
                val method = ACCESS_METHODS[ad.accessMethod.id] ?: ad.accessMethod.id
                out.put(method + " " + generalName(ad.accessLocation))
            }
            out
        } catch (_: Exception) {
            null
        }
    }

    private fun subjectAltNames(cert: X509Certificate): JSONArray? =
        try {
            val entries = cert.subjectAlternativeNames ?: return null
            val out = JSONArray()
            for (e in entries) {
                val tag = (e.firstOrNull() as? Int) ?: continue
                out.put(generalNameLabel(tag) + ":" + (e.getOrNull(1)?.toString() ?: ""))
            }
            out
        } catch (_: Exception) {
            null
        }

    private fun policies(cert: X509Certificate): JSONArray? {
        val present = extensionOctets(cert, OID_POLICIES) ?: return null
        return try {
            val out = JSONArray()
            for (pi in CertificatePolicies.getInstance(present).policyInformation) out.put(
                pi.policyIdentifier.id
            )
            out
        } catch (_: Exception) {
            null
        }
    }

    /**
     * provisioningInfo, decoded: every key the map carries, flattened one level with the nested
     * map's entries indented by their label. There is no one-line summary — it could only repeat
     * rows that are listed here anyway.
     */
    /**
     * What an RKP keybox states about the device it was provisioned for, in the two fields that the
     * module can be consistent with: the verified boot hash its issuer recorded, and the
     * manufacturer. Both are optional — a factory keybox carries no provisioningInfo at all, and an
     * issuance that was refused carries the verdict without the hash.
     */
    data class Provisioning(val bootHash: ByteArray?, val manufacturer: String?) {
        // ByteArray in a data class compares by identity; these are compared field-wise when the
        // resolver decides whether anything changed.
        override fun equals(other: Any?): Boolean =
            other is Provisioning &&
                manufacturer == other.manufacturer &&
                (bootHash?.contentEquals(other.bootHash ?: ByteArray(0))
                    ?: (other.bootHash == null))

        override fun hashCode(): Int =
            31 * (bootHash?.contentHashCode() ?: 0) + manufacturer.hashCode()
    }

    /**
     * The first provisioningInfo in [certs], read for those two fields. The extension sits on
     * whichever certificate the issuer attached it to — the keybox's own leaf, or the RKP-issued
     * certificate above an attested key — so every certificate is tried in order and the first that
     * decodes wins.
     */
    fun provisioningOf(certs: List<X509Certificate>): Provisioning? {
        for (cert in certs) {
            val raw = extensionOctets(cert, OID_PROVISIONING) ?: continue
            val decoded = Cbor.decode(raw) as? Map<*, *> ?: continue
            val device = decoded[5L] as? Map<*, *>
            // 5.2 is the hash as 64 lowercase hex characters; anything else is not one.
            val hash =
                (device?.get(2L) as? String)
                    ?.takeIf { HEX64.matches(it) }
                    ?.let { hex ->
                        ByteArray(32) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
                    }
            val manufacturer = (decoded[3L] as? String)?.trim()?.takeIf { it.isNotEmpty() }
            if (hash != null || manufacturer != null) return Provisioning(hash, manufacturer)
        }
        return null
    }

    private val HEX64 = Regex("^[0-9a-f]{64}$")

    private fun provisioning(cert: X509Certificate): JSONObject? {
        val raw = extensionOctets(cert, OID_PROVISIONING) ?: return null
        val decoded = Cbor.decode(raw)
        if (decoded !is Map<*, *>) {
            return JSONObject()
                .put(
                    "fields",
                    JSONArray()
                        .put(row("undecodable CBOR", "${raw.size} bytes"))
                        .put(row("raw", hex(raw, 16))),
                )
        }
        val fields = JSONArray()
        for ((k, v) in decoded) {
            val label = PROVISIONING_FIELDS[k as? Long] ?: "key $k"
            if (v is Map<*, *>) {
                fields.put(row(label, "${v.size} field(s)"))
                for ((sk, sv) in v) {
                    val sub = PROVISIONING_SUBFIELDS[sk as? Long] ?: "key $sk"
                    fields.put(row("  $sub", value(sv)))
                }
            } else {
                fields.put(row(label, value(v)))
            }
        }
        return JSONObject().put("fields", fields)
    }

    private fun row(label: String, value: String) =
        JSONObject().put("label", label).put("value", value)

    private fun value(v: Any?): String =
        when (v) {
            null -> "—"
            is ByteArray -> hex(v, 16)
            is Map<*, *> -> "${v.size} field(s)"
            is List<*> -> v.joinToString(", ") { value(it) }
            else -> v.toString()
        }

    // --- Private keys -------------------------------------------------------------------

    /**
     * What the `<PrivateKey>` block holds and whether it belongs to [leaf]. [algorithmAttr] is the
     * `<Key algorithm>` attribute, which is checked against the key actually found rather than
     * trusted. Never returns key material.
     */
    private val PEM_BLOCK =
        Regex("-----BEGIN ([^-]+)-----(.*?)-----END \\1-----", RegexOption.DOT_MATCHES_ALL)

    /**
     * Rebuild a PEM block as 64-column base64. Keyboxes travel through chat channels, and what
     * comes out the other end is often whitespace-collapsed onto one line, or carries a blank line
     * after the BEGIN marker — which a PEM reader takes for an RFC 822 header and rejects. Both
     * decode fine once the body is stripped of whitespace and re-wrapped, so the file is normalised
     * rather than refused.
     */
    private fun normalizePem(text: String): String {
        val m = PEM_BLOCK.find(text.trim()) ?: return text.trim()
        val label = m.groupValues[1].trim()
        val body = m.groupValues[2].replace(Regex("\\s"), "")
        return buildString {
            append("-----BEGIN ").append(label).append("-----\n")
            var i = 0
            while (i < body.length) {
                append(body, i, minOf(i + 64, body.length)).append('\n')
                i += 64
            }
            append("-----END ").append(label).append("-----\n")
        }
    }

    fun privateKey(pem: String?, algorithmAttr: String, leaf: X509Certificate?): JSONObject {
        val out = JSONObject().put("present", pem != null)
        if (pem == null) return out
        val label =
            pem.lineSequence()
                .map { it.trim() }
                .firstOrNull { it.startsWith("-----BEGIN") }
                ?.removePrefix("-----BEGIN ")
                ?.removeSuffix("-----")
                ?.trim()
        if (label != null) {
            out.put("pemLabel", label)
            out.put(
                "encoding",
                when (label) {
                    "PRIVATE KEY" -> "PKCS#8"
                    "RSA PRIVATE KEY" -> "PKCS#1"
                    "EC PRIVATE KEY" -> "SEC1"
                    "ENCRYPTED PRIVATE KEY" -> "PKCS#8 (encrypted)"
                    else -> "unknown"
                },
            )
        }

        val key =
            try {
                val parsed = PEMParser(StringReader(normalizePem(pem))).readObject()
                val conv = JcaPEMKeyConverter().setProvider("BC")
                when (parsed) {
                    is PEMKeyPair -> conv.getKeyPair(parsed).private
                    is org.bouncycastle.asn1.pkcs.PrivateKeyInfo -> conv.getPrivateKey(parsed)
                    is PKCS8EncryptedPrivateKeyInfo -> {
                        out.put("error", "the private key is encrypted; no passphrase to open it")
                        return out
                    }
                    null -> {
                        out.put("error", "no PEM object found in the PrivateKey element")
                        return out
                    }
                    else -> {
                        out.put("error", "unsupported PEM object: ${parsed.javaClass.simpleName}")
                        return out
                    }
                }
            } catch (e: Exception) {
                out.put(
                    "error",
                    e.message?.lineSequence()?.firstOrNull() ?: "could not read the key",
                )
                return out
            }

        val type =
            when (key) {
                is RSAPrivateKey -> "RSA"
                is ECPrivateKey -> "EC"
                else -> key.algorithm ?: "?"
            }
        out.put("type", type)
        when (key) {
            is RSAPrivateKey -> out.put("size", key.modulus.bitLength())
            is ECPrivateKey -> out.put("size", key.params.curve.field.fieldSize)
        }
        val expected =
            when (algorithmAttr.lowercase()) {
                "rsa" -> "RSA"
                "ecdsa",
                "ec" -> "EC"
                else -> type
            }
        out.put("algorithmAgrees", expected == type)
        if (leaf != null) out.put("matchesLeaf", provesOwnership(key, type, leaf))
        return out
    }

    /**
     * Whether [key] is the private half of [leaf]'s public key, settled by signing a fixed probe
     * and verifying it against the certificate. A false here is the one keybox fault that nothing
     * else in the inspector would catch, and it is fatal: every attestation signed with this key
     * would carry a chain that cannot verify.
     */
    private fun provesOwnership(key: PrivateKey, type: String, leaf: X509Certificate): Boolean =
        try {
            val alg =
                when (type) {
                    "EC" -> "SHA256withECDSA"
                    "RSA" -> "SHA256withRSA"
                    else -> return false
                }
            val probe = "teesim keybox pairing probe".toByteArray()
            val signer = Signature.getInstance(alg, "BC")
            signer.initSign(key)
            signer.update(probe)
            val sig = signer.sign()
            val verifier = Signature.getInstance(alg, "BC")
            verifier.initVerify(leaf.publicKey)
            verifier.update(probe)
            verifier.verify(sig)
        } catch (_: Exception) {
            false
        }

    // --- Distinguished names ------------------------------------------------------------

    /**
     * Attribute types a DN can carry, by OID. X500Principal.getName() knows only a handful of these
     * and prints everything else as `2.5.4.5=#131035633234…` — the DER of the value, in hex.
     * Google's attestation DNs are made of exactly the types it does not know (SERIALNUMBER on
     * every batch certificate, TITLE on the RKP ones), so a keybox that is perfectly readable to
     * the TA renders as a row of raw bits. BCStyle knows the full table; this map only fixes the
     * few labels where its abbreviation is less recognisable than the field's usual name.
     */
    private val DN_LABELS =
        mapOf(
            "2.5.4.3" to "CN",
            "2.5.4.4" to "SN",
            "2.5.4.5" to "SERIALNUMBER",
            "2.5.4.6" to "C",
            "2.5.4.7" to "L",
            "2.5.4.8" to "ST",
            "2.5.4.9" to "STREET",
            "2.5.4.10" to "O",
            "2.5.4.11" to "OU",
            "2.5.4.12" to "TITLE",
            "2.5.4.42" to "GIVENNAME",
            "1.2.840.113549.1.9.1" to "EMAIL",
            "0.9.2342.19200300.100.1.1" to "UID",
            "0.9.2342.19200300.100.1.25" to "DC",
        )

    /**
     * A DN as text: `TITLE=TEE, SERIALNUMBER=5c249f147b646038`, most specific component first — the
     * order RFC 2253 prints and the one the rest of the UI already shows. A value that is not a
     * string type still falls back to `#hex`, because that is what it is.
     */
    fun dn(principal: X500Principal): String =
        try {
            val rdns = X500Name.getInstance(principal.encoded).rdNs
            val parts =
                rdns.indices.reversed().map { i ->
                    rdns[i].typesAndValues.joinToString("+") { tv ->
                        val label =
                            DN_LABELS[tv.type.id]
                                ?: BCStyle.INSTANCE.oidToDisplayName(tv.type)
                                ?: tv.type.id
                        label + "=" + IETFUtils.valueToString(tv.value)
                    }
                }
            if (parts.isEmpty()) "(empty)" else parts.joinToString(", ")
        } catch (_: Exception) {
            principal.name // better the name Java gives than nothing at all
        }

    // --- Shared helpers -----------------------------------------------------------------

    /**
     * The DER inside an extension's extnValue. getExtensionValue returns the OCTET STRING wrapper,
     * so the content has to be unwrapped once before it is the structure the extension defines.
     */
    private fun extensionOctets(cert: X509Certificate, oid: String): ByteArray? =
        try {
            cert.getExtensionValue(oid)?.let { ASN1OctetString.getInstance(it).octets }
        } catch (_: Exception) {
            null
        }

    private fun names(gns: GeneralNames): String = gns.names.joinToString(", ") { generalName(it) }

    private fun generalName(gn: GeneralName): String {
        val body =
            when (gn.tagNo) {
                // The same raw-bits problem as a certificate's own DN, so the same formatter.
                GeneralName.directoryName ->
                    dn(X500Principal(X500Name.getInstance(gn.name).encoded))
                else -> gn.name.toString()
            }
        return generalNameLabel(gn.tagNo) + ":" + body
    }

    private fun generalNameLabel(tag: Int): String =
        when (tag) {
            GeneralName.otherName -> "other"
            GeneralName.rfc822Name -> "email"
            GeneralName.dNSName -> "DNS"
            GeneralName.directoryName -> "dirName"
            GeneralName.uniformResourceIdentifier -> "URI"
            GeneralName.iPAddress -> "IP"
            GeneralName.registeredID -> "OID"
            else -> "name$tag"
        }

    private fun sha256(data: ByteArray): String =
        hex(MessageDigest.getInstance("SHA-256").digest(data))

    private fun hex(data: ByteArray, limit: Int = 0): String {
        val take = if (limit > 0 && data.size > limit) limit else data.size
        val sb = StringBuilder(take * 2)
        for (i in 0 until take) sb.append("%02x".format(data[i]))
        if (take < data.size) sb.append("… (${data.size} bytes)")
        return sb.toString()
    }
}
