package org.matrix.teesim

import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Classifies the root a keybox certificate chain terminates in, so the WebUI can tell a genuine
 * Google-signed keybox from an AOSP software root or a Samsung Knox one. The trust anchors are the
 * public keys Google publishes for hardware key attestation; we pin the *public key* (not a whole
 * cert) so every re-issued root with the same key collapses to one anchor.
 *
 * The authoritative machine-readable set is served at
 * https://android.googleapis.com/attestation/root (documented at
 * https://developer.android.com/privacy-and-security/security-key-attestation). It currently
 * publishes two roots, both pinned below: the long-standing RSA-4096 root (subject serial
 * f92009e853b6b045, valid 2022-2042) and the EC P-384 "Key Attestation CA1" root that signs Remote
 * Key Provisioning chains — live since 2026-02-01 and, since 2026-04-10, the exclusive root for
 * RKP-enabled devices (i.e. most modern hardware). Trust anchors are pinned in-binary on purpose:
 * fetching a root you then trust would be circular. The AOSP and Knox keys mirror the vvb2060
 * KeyAttestation reference.
 */
object RootPublicKey {

    /** RSA-4096 Google hardware-attestation root SubjectPublicKeyInfo (base64 DER). */
    private const val GOOGLE_ROOT_RSA =
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU" +
            "FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j" +
            "lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y" +
            "//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X" +
            "pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI" +
            "mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB" +
            "+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q" +
            "uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp" +
            "Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7" +
            "gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82" +
            "ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+" +
            "NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ=="

    /** EC P-384 Google root, effective 2026-02-01 (full cert; its key is derived at load). */
    private const val GOOGLE_ROOT_EC_CERT =
        "-----BEGIN CERTIFICATE-----\n" +
            "MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc\n" +
            "MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET\n" +
            "MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4\n" +
            "WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex\n" +
            "MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG\n" +
            "EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt\n" +
            "G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5\n" +
            "Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB\n" +
            "/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA\n" +
            "MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH\n" +
            "EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY\n" +
            "uR2zh/80lQyu9vAFCj6E4AXc+osmRg==\n" +
            "-----END CERTIFICATE-----\n"

    /** AOSP software roots — a chain rooted here is a software keybox, not hardware-attested. */
    private const val AOSP_ROOT_EC =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu" +
            "D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA=="
    private const val AOSP_ROOT_RSA =
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf" +
            "d5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg" +
            "MdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm" +
            "+Vfkl5YLCazOkjWFmwIDAQAB"

    /** Samsung Knox attestation roots (SAKV1/SAKV2/SAKMV1). */
    private const val KNOX_SAKV1 =
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBs9Qjr//REhkXW7jUqjY9KNwWac4r" +
            "5+kdUGk+TZjRo1YEa47Axwj6AJsbOjo4QsHiYRiWTELvFeiuBsKqyuF0xyAAKvDo" +
            "fBqrEq1/Ckxo2mz7Q4NQes3g4ahSjtgUSh0k85fYwwHjCeLyZ5kEqgHG9OpOH526" +
            "FFAK3slSUgC8RObbxys="
    private const val KNOX_SAKV2 =
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhbGuLrpql5I2WJmrE5kEVZOo+dgA" +
            "46mKrVJf/sgzfzs2u7M9c1Y9ZkCEiiYkhTFE9vPbasmUfXybwgZ2EM30A1ABPd12" +
            "4n3JbEDfsB/wnMH1AcgsJyJFPbETZiy42Fhwi+2BCA5bcHe7SrdkRIYSsdBRaKBo" +
            "ZsapxB0gAOs0jSPRX5M="
    private const val KNOX_SAKMV1 =
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB9XeEN8lg6p5xvMVWG42P2Qi/aRKX" +
            "2rPRNgK92UlO9O/TIFCKHC1AWCLFitPVEow5W+yEgC2wOiYxgepY85TOoH0AuEkL" +
            "oiC6ldbF2uNVU3rYYSytWAJg3GFKd1l9VLDmxox58Hyw2Jmdd5VSObGiTFQ/SgKs" +
            "n2fbQPtpGlNxgEfd6Y8="

    /** Chain-root classification, as reported to the WebUI. */
    const val GOOGLE = "google"
    const val AOSP = "aosp"
    const val KNOX = "knox"
    const val UNKNOWN = "unknown"
    const val NONE = "none"

    private val googleKeys: List<PublicKey> = buildList {
        spkiToKey(GOOGLE_ROOT_RSA)?.let { add(it) }
        certToKey(GOOGLE_ROOT_EC_CERT)?.let { add(it) }
    }
    private val aospKeys: List<PublicKey> =
        listOfNotNull(spkiToKey(AOSP_ROOT_EC), spkiToKey(AOSP_ROOT_RSA))
    private val knoxKeys: List<PublicKey> =
        listOfNotNull(spkiToKey(KNOX_SAKV1), spkiToKey(KNOX_SAKV2), spkiToKey(KNOX_SAKMV1))

    init {
        SystemLogger.info(
            "RootPublicKey: pinned ${googleKeys.size} Google, ${aospKeys.size} AOSP, ${knoxKeys.size} Knox anchors"
        )
    }

    /**
     * The authority the chain terminates in. Prefers an exact key match on the top cert (a
     * self-signed root that IS a known anchor); if the top cert is not itself an anchor, tries to
     * verify it against each anchor key, so a chain whose Google root is present as issuer-only
     * (not embedded) still reads as Google. Returns [NONE] for an empty chain.
     */
    fun authorityOf(chain: List<X509Certificate>): String {
        val top = chain.lastOrNull() ?: return NONE
        val enc = top.publicKey.encoded
        when {
            matches(enc, googleKeys) -> return GOOGLE
            matches(enc, aospKeys) -> return AOSP
            matches(enc, knoxKeys) -> return KNOX
        }
        // Root not embedded: does a pinned anchor sign the top cert?
        if (signedByAny(top, googleKeys)) return GOOGLE
        if (signedByAny(top, aospKeys)) return AOSP
        if (signedByAny(top, knoxKeys)) return KNOX
        return UNKNOWN
    }

    private fun matches(encoded: ByteArray, keys: List<PublicKey>): Boolean = keys.any {
        it.encoded.contentEquals(encoded)
    }

    private fun signedByAny(cert: X509Certificate, keys: List<PublicKey>): Boolean = keys.any {
        try {
            cert.verify(it)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun spkiToKey(base64: String): PublicKey? {
        val der =
            try {
                Base64.getDecoder().decode(base64)
            } catch (e: Exception) {
                SystemLogger.warning("RootPublicKey: bad SPKI base64", e)
                return null
            }
        val spec = X509EncodedKeySpec(der)
        for (algo in listOf("EC", "RSA")) {
            try {
                return KeyFactory.getInstance(algo).generatePublic(spec)
            } catch (_: Exception) {}
        }
        SystemLogger.warning("RootPublicKey: SPKI matched neither EC nor RSA")
        return null
    }

    private fun certToKey(pem: String): PublicKey? =
        try {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(pem.toByteArray()))
                .publicKey
        } catch (e: Exception) {
            SystemLogger.warning("RootPublicKey: could not parse pinned root cert", e)
            null
        }
}
