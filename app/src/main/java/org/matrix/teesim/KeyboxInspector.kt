package org.matrix.teesim

import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import javax.xml.parsers.DocumentBuilderFactory
import org.json.JSONArray
import org.json.JSONObject
import org.w3c.dom.Element

/**
 * Parses a keybox.xml for the WebUI's keybox inspector. For each `<Key algorithm>` block it decodes
 * the certificate chain and reports the fields that let a user spot a bad keybox — subject/issuer,
 * validity (with expiry), key type and size, and whether the chain links up — plus whether a private
 * key is present. Read-only: the private key material is never returned, only that it exists.
 *
 * It also runs the checks that decide whether a keybox would pass Play Integrity / hardware attestation:
 * each cert's signature is verified against its parent, [RootPublicKey] classifies the root the chain
 * terminates in (Google, AOSP software, Knox, or unknown), and every serial is looked up in Google's
 * revocation list ([RevocationList]). A Google-rooted, cryptographically linked, unrevoked chain is a
 * genuine live keybox; a revoked or software-rooted one is not.
 */
object KeyboxInspector {

    private val NAME_RE = Regex("^[A-Za-z0-9._-]+\\.xml$")

    /** Coerce to a safe *.xml basename inside the module dir, or null. Mirrors the WebUI's safeName. */
    private fun safeName(raw: String): String? {
        val name = raw.trim().substringAfterLast('/').substringAfterLast('\\')
        if (name.isEmpty() || name.contains("..") || !NAME_RE.matches(name)) return null
        return name
    }

    fun inspect(rawName: String, forceRefresh: Boolean = false): JSONObject {
        val name = safeName(rawName) ?: return fail("invalid keybox name")
        val file = File(Const.DATA_DIR, name)
        if (!file.isFile) return fail("no such keybox: $name")
        // Pull-to-refresh on the detail page re-fetches Google's revocation list before re-checking.
        if (forceRefresh) RevocationList.forceRefresh()
        return try {
            val doc = newSafeBuilder().parse(file)
            val root = doc.documentElement
            val kb = firstChild(root, "Keybox")
            val scope = kb ?: root
            val keyNodes = scope.getElementsByTagName("Key")
            val keys = JSONArray()
            for (i in 0 until keyNodes.length) {
                (keyNodes.item(i) as? Element)?.let { keys.put(inspectKey(it)) }
            }
            JSONObject()
                .put("ok", true)
                .put("name", name)
                .put("deviceId", kb?.getAttribute("DeviceID") ?: "")
                .put("revocationListAvailable", RevocationList.available())
                .put("keys", keys)
        } catch (e: Exception) {
            SystemLogger.warning("KeyboxInspector: failed to parse $name", e)
            fail("could not parse keybox: ${e.message}")
        }
    }

    /**
     * Canonical subject-DN -> keybox filename, across every `*.xml` keybox in the module dir. Used to
     * attribute a stored attestation key to the keybox that signed it: the key's leaf certificate is
     * issued by the keybox's signing (batch) cert, whose subject appears here, and the batch/intermediate/
     * root certs of the key's chain are keybox subjects too — so a hit on either the leaf's issuer or any
     * chain subject names the signer. Best effort: an unparseable keybox simply contributes nothing.
     */
    fun signerIndex(): Map<String, String> {
        val out = HashMap<String, String>()
        val files = File(Const.DATA_DIR).listFiles { f -> f.isFile && NAME_RE.matches(f.name) } ?: return out
        for (file in files) {
            try {
                val certNodes = newSafeBuilder().parse(file).documentElement.getElementsByTagName("Certificate")
                for (i in 0 until certNodes.length) {
                    val cert = parsePem(certNodes.item(i).textContent) ?: continue
                    out[canonicalDn(cert.subjectX500Principal)] = file.name
                }
            } catch (e: Exception) {
                SystemLogger.warning("KeyboxInspector.signerIndex: skipping ${file.name}", e)
            }
        }
        return out
    }

    /** RFC 2253 canonical form of a DN, so subject/issuer strings compare regardless of encoding quirks. */
    fun canonicalDn(p: javax.security.auth.x500.X500Principal): String =
        p.getName(javax.security.auth.x500.X500Principal.CANONICAL)

    private fun inspectKey(ke: Element): JSONObject {
        val out = JSONObject().put("algorithm", ke.getAttribute("algorithm").ifBlank { "?" })

        val priv = firstChild(ke, "PrivateKey")
        out.put("privateKeyPresent", priv != null && priv.textContent.contains("PRIVATE KEY"))

        val certParent = firstChild(ke, "CertificateChain") ?: ke
        val certNodes = certParent.getElementsByTagName("Certificate")

        // Parse every slot; a null keeps its position so the signature pairing (cert[i] signed by
        // cert[i+1], the top cert self-signed) stays aligned even when one cert fails to decode.
        val parsed = ArrayList<X509Certificate?>()
        for (i in 0 until certNodes.length) parsed.add(parsePem(certNodes.item(i).textContent))
        val valid = parsed.filterNotNull()

        val revChecked = RevocationList.available()
        val certs = JSONArray()
        var anyRevoked = false
        var chainVerified = valid.isNotEmpty() && valid.size == parsed.size
        for (i in parsed.indices) {
            val cert = parsed[i]
            if (cert == null) {
                certs.put(JSONObject().put("index", i).put("error", "could not parse certificate"))
                chainVerified = false
                continue
            }
            val j = certJson(i, cert)

            // Cryptographic linkage: every cert is signed by the next one up; a self-signed root signs
            // itself. When the top cert is not self-signed the real root is not embedded (the chain ends
            // at an intermediate) — there is nothing in-chain to check it against, so leave it and let
            // RootPublicKey.authorityOf decide its trust.
            val isTop = i == parsed.size - 1
            val selfSigned = cert.subjectX500Principal == cert.issuerX500Principal
            val parentKey = when {
                isTop && !selfSigned -> null
                isTop -> cert.publicKey
                else -> parsed[i + 1]?.publicKey
            }
            val sigValid = parentKey?.let {
                try {
                    cert.verify(it)
                    true
                } catch (_: Exception) {
                    false
                }
            }
            if (sigValid != null) j.put("signatureValid", sigValid)
            if (sigValid == false) chainVerified = false

            j.put("revocationChecked", revChecked)
            if (revChecked) {
                val rev = RevocationList.status(cert.serialNumber)
                if (rev != null) {
                    anyRevoked = true
                    j.put("revoked", true)
                        .put("revocationStatus", rev.optString("status", "REVOKED"))
                        .put("revocationReason", rev.optString("reason", ""))
                } else {
                    j.put("revoked", false)
                }
            }
            certs.put(j)
        }

        val authority = RootPublicKey.authorityOf(valid)
        // Tag the top-most parsed cert with the verdict, so the root row can show it.
        val topIndex = parsed.indexOfLast { it != null }
        if (topIndex >= 0) certs.optJSONObject(topIndex)?.put("rootAuthority", authority)

        out.put("chainLength", certNodes.length)
        out.put("certs", certs)
        out.put("linkage", linkage(valid))
        out.put("rootAuthority", authority)
        out.put("googleSigned", authority == RootPublicKey.GOOGLE)
        out.put("chainVerified", chainVerified)
        out.put("revoked", anyRevoked)
        out.put("revocationChecked", revChecked)
        return out
    }

    private fun certJson(index: Int, cert: X509Certificate): JSONObject {
        val now = System.currentTimeMillis()
        val (keyAlgo, keySize) = keyInfo(cert)
        return JSONObject()
            .put("index", index)
            .put("subject", cert.subjectX500Principal.name)
            .put("issuer", cert.issuerX500Principal.name)
            .put("serial", cert.serialNumber.toString(16))
            .put("notBefore", cert.notBefore.time)
            .put("notAfter", cert.notAfter.time)
            .put("expired", cert.notAfter.time < now)
            .put("notYetValid", cert.notBefore.time > now)
            .put("sigAlg", cert.sigAlgName)
            .put("keyAlgorithm", keyAlgo)
            .put("keySize", keySize)
            .put("isCa", cert.basicConstraints >= 0)
            .put("selfSigned", cert.subjectX500Principal == cert.issuerX500Principal)
    }

    private fun keyInfo(cert: X509Certificate): Pair<String, Int> =
        when (val pk = cert.publicKey) {
            is RSAPublicKey -> "RSA" to pk.modulus.bitLength()
            is ECPublicKey -> "EC" to pk.params.curve.field.fieldSize
            else -> (pk.algorithm ?: "?") to 0
        }

    /** "ok" when each cert's issuer is the next cert's subject; "broken" otherwise. */
    private fun linkage(chain: List<X509Certificate>): String {
        if (chain.isEmpty()) return "empty"
        if (chain.size == 1) return "single"
        for (i in 0 until chain.size - 1) {
            if (chain[i].issuerX500Principal != chain[i + 1].subjectX500Principal) return "broken"
        }
        return "ok"
    }

    private fun parsePem(text: String): X509Certificate? =
        try {
            val body =
                text.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replace(Regex("\\s"), "")
            if (body.isEmpty()) null
            else
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode(body)))
                    as X509Certificate
        } catch (e: Exception) {
            null
        }

    /** A DocumentBuilder with DTD/external-entity processing off — it parses an untrusted file. */
    private fun newSafeBuilder() =
        DocumentBuilderFactory.newInstance()
            .apply {
                isNamespaceAware = false
                for (f in
                    listOf(
                        "http://apache.org/xml/features/disallow-doctype-decl" to true,
                        "http://xml.org/sax/features/external-general-entities" to false,
                        "http://xml.org/sax/features/external-parameter-entities" to false,
                    )) {
                    try {
                        setFeature(f.first, f.second)
                    } catch (_: Exception) {}
                }
                isExpandEntityReferences = false
            }
            .newDocumentBuilder()

    private fun firstChild(parent: Element, tag: String): Element? {
        val n = parent.getElementsByTagName(tag)
        return if (n.length > 0) n.item(0) as? Element else null
    }

    private fun fail(msg: String) = JSONObject().put("ok", false).put("error", msg)
}
