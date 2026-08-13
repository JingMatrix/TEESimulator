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

    /**
     * Delete every target app's existing attestation key so the app regenerates it, and return whether
     * keystore2 was restarted as a result. Run ONCE at daemon start: an attest key made before we
     * covered the app (or under an old build) is real/foreign, and an attest key must be OURS for its
     * delegated leaves to get a patched root of trust. Clearing it forces the app's next attestation to
     * re-create it, which now always mints in the TA (generation).
     *
     * keystore2 only lets a key's OWNER delete it (KeyPerm::Delete, confirmed in service.rs), so the
     * daemon can't remove another app's key through the API — [KeystoreDb.deleteTargetAttestKeys] falls
     * back to a direct database delete, which removes the row but does NOT evict keystore2's in-memory
     * cache, so the app would keep using the cached key. We therefore restart keystore2 after a purge so
     * it reloads from the (now smaller) database; the injector re-injects on the new pid.
     */
    fun purgeTargetAttestKeys(config: ConfigStore.Config): Boolean {
        // Every effective target uid across the config (resolved packages + raw uid:N + auto-include),
        // computed and logged once by Scope.
        val uids = Scope.allTargetUids(config)
        if (uids.isEmpty()) return false
        // deleteTargetAttestKeys removes each key as its owning app first (which evicts keystore2's cache);
        // it returns only the count that could not be owner-deleted and fell back to a raw database delete.
        // Those need a keystore2 restart to actually leave its cache; owner-deleted keys need nothing more.
        val needRestart = KeystoreDb.deleteTargetAttestKeys(uids)
        if (needRestart == 0) return false
        SystemLogger.info("re-attest: $needRestart attest key(s) fell back to a database delete; restarting keystore2 to evict them from its cache")
        return restartKeystore2()
    }

    /** Ask init to restart keystore2 so it reloads keys from the database (dropping any cached copy of a
     *  key we deleted directly). Best-effort: returns true if the restart command was issued. */
    private fun restartKeystore2(): Boolean {
        return try {
            val p = ProcessBuilder("setprop", "ctl.restart", "keystore2").redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            SystemLogger.info("re-attest: requested keystore2 restart (exit ${p.exitValue()}${if (out.isEmpty()) "" else ", $out"})")
            true
        } catch (e: Throwable) {
            SystemLogger.warning("re-attest: could not restart keystore2; the purge will take effect on next boot", e)
            false
        }
    }

    /** Re-attest every eligible pre-existing key of [config]'s target apps against the live profiles. */
    fun run(config: ConfigStore.Config) {
        // uid -> the profile whose keybox should sign that app's keys (one profile per package),
        // resolved and logged centrally by Scope so raw uid:N tokens and auto-include are covered too.
        val uidToProfile = Scope.uidToProfile(config)
        if (uidToProfile.isEmpty()) return

        val keys = KeystoreDb.attestedKeys(uidToProfile.keys)
        SystemLogger.info(
            "re-attest: ${keys.size} pre-existing target key(s) to re-root across ${uidToProfile.size} uid(s)"
        )
        if (keys.isEmpty()) return

        var done = 0
        for (key in keys) {
            val profileId = uidToProfile[key.uid] ?: continue
            val chain =
                Control.resign(profileId, key.leaf)
                    ?: run {
                        SystemLogger.warning("re-attest: key id=${key.id} uid=${key.uid} — resign failed; skipping")
                        continue
                    }
            if (chain.isEmpty()) continue
            // keystore2 stores the leaf (CERT) and the rest of the chain (CERT_CHAIN) separately.
            val leaf = chain[0]
            val rest = concatFrom(chain, 1)
            if (Keystore2Service.updateSubcomponent(key.id, leaf, rest)) {
                done++
                SystemLogger.info(
                    "re-attest: key id=${key.id} uid=${key.uid} profile=$profileId re-rooted (${chain.size}-cert chain)"
                )
            }
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
