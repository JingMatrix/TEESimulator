package org.matrix.teesim

import java.io.ByteArrayOutputStream

/**
 * Re-roots pre-existing keys' attestation on a config push. A key generated before its app was
 * covered (or under a previous keybox) still carries the real hardware attestation — an unlocked
 * root of trust rooted in the device's real attestation key. For each target app, every stored key
 * that carries such a leaf is re-signed under its profile's keybox — the same patch the router
 * applies to a freshly generated key — and written back with [Keystore2Service.updateSubcomponent].
 * The key blob is never touched, so the real hardware key keeps working; only the certificate the app
 * reads changes.
 *
 * Idempotent and record-less: it re-scans the live keystore each run and re-signs whatever it finds,
 * so a re-run, a keybox swap, or a newly installed app all converge on the next push.
 */
object ReAttest {

    /** Re-attest every eligible pre-existing key of [config]'s target apps against the live profiles. */
    fun run(config: ConfigStore.Config) {
        // uid -> the profile whose keybox should sign that app's keys (one profile per package).
        val uidToProfile = HashMap<Int, String>()
        for (profile in config.profiles) {
            for (pkg in profile.apps) {
                val uid = Packages.uidForPackage(pkg)
                if (uid >= 0) uidToProfile[uid] = profile.id
            }
        }
        if (uidToProfile.isEmpty()) return

        val keys = KeystoreDb.attestedKeys(uidToProfile.keys)
        if (keys.isEmpty()) return

        var done = 0
        for (key in keys) {
            val profileId = uidToProfile[key.uid] ?: continue
            val chain = Control.resign(profileId, key.leaf) ?: continue
            if (chain.isEmpty()) continue
            // keystore2 stores the leaf (CERT) and the rest of the chain (CERT_CHAIN) separately.
            val leaf = chain[0]
            val rest = concatFrom(chain, 1)
            if (Keystore2Service.updateSubcomponent(key.id, leaf, rest)) done++
        }
        SystemLogger.info("re-attest: re-rooted $done of ${keys.size} pre-existing target key(s) to the keybox")
    }

    /** DER concatenation of [certs] from index [from] onward (empty when there are no further certs). */
    private fun concatFrom(certs: List<ByteArray>, from: Int): ByteArray {
        val bos = ByteArrayOutputStream()
        for (i in from until certs.size) bos.write(certs[i])
        return bos.toByteArray()
    }
}
