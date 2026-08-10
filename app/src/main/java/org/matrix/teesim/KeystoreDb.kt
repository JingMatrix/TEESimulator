package org.matrix.teesim

import android.database.sqlite.SQLiteDatabase
import android.os.Build
import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import org.json.JSONObject

/**
 * Read/manage window into keystore2's on-disk database, so the WebUI can list and remove the keys THIS
 * MODULE generated for target apps (gms, key-attestation, …). Those keys live in keystore2's per-app
 * namespaces, not in the daemon's own AndroidKeyStore, so [KeyAdmin.listKeys] can never see them. Only
 * meaningful on Android 12+ (API 31+), where keystore2 replaced the legacy keystore; on 10/11 there is
 * no such database and [available] returns false.
 *
 * "Ours" is decided by fact, not heuristics: our KeyMint TA prepends the routing marker `TEESIMkm\0` to
 * every key blob it emits (teesim-km `BLOB_MARKER` / `mark_blob`), and keystore2 stores that blob in
 * `blobentry`. A key whose blob starts with the marker is one we minted; every other key on the device
 * is ignored. (A key keystore2 super-encrypts before storing would hide the marker, but the attestation
 * keys these apps create are not auth-bound, so their blobs are stored as the TA returned them.)
 *
 * The keybox that signed a key is recovered from its stored certificate chain: the leaf attestation
 * cert is issued by the keybox's signing (batch) cert, so the leaf's issuer DN — and the batch/root
 * subjects in the chain — match an entry in [KeyboxInspector.signerIndex].
 *
 * Reads never touch the live file: keystore2 owns persistent.sqlite in WAL mode under a live lock, so we
 * snapshot it (+ its -wal / -shm siblings) into a private dir under [Const.DATA_DIR], open the COPY
 * read-only, and delete the snapshot. Deletion is the one write path and DOES open the live database —
 * safely, because it is already a WAL database that supports a second writer (we set a busy timeout and
 * only ever remove rows we re-verify as our own target-app keys). Root can read and write the
 * keystore-owned files.
 *
 * Schema (AOSP system/security/keystore2/src/database.rs, confirmed against a live API 37 device):
 * ```
 *   keyentry(id, key_type, domain, namespace, alias BLOB, state, km_uuid)
 *     domain    Domain::APP = 0  -> namespace is the app uid
 *     state     KeyLifeCycle: Live = 1 (usable), Existing = 0 (mid-create), Unreferenced = 2
 *     alias     UTF-8 text stored as a BLOB; CAST(... AS TEXT) so the cursor yields a String
 *   blobentry(id, subcomponent_type, keyentryid, blob)  -- the KM key blob and the attestation certs
 *   keymetadata(keyentryid, tag, data)  -- creation date = ms-since-epoch in an INTEGER `data` cell,
 *     recognised by SHAPE (a plausible epoch-millis integer) since the tag number drifts across releases.
 * ```
 *
 * Every path is wrapped so a schema/lock/IO surprise yields an empty result, never a throw.
 */
object KeystoreDb {

    private const val KEYSTORE2_DB = "/data/misc/keystore/persistent.sqlite"
    private val snapshotDir = File(Const.DATA_DIR, ".ks-snapshot")

    // The routing marker teesim-km prepends to every key blob (`b"TEESIMkm\x00"`), as a SQLite blob
    // literal so `substr(blob,1,9) = X'…'` selects the keys we minted.
    private const val MARKER_HEX = "54454553494D6B6D00"

    // The KeyMint attestation extension OID; a leaf carrying it has attestation content to re-root.
    private const val ATTEST_EXT_OID = "1.3.6.1.4.1.11129.2.1.17"

    // Plausible epoch-millis window (~2014-05 .. ~2128), used to spot a creation-date metadata cell
    // without depending on the release-specific tag number.
    private const val TS_MIN = 1_400_000_000_000L
    private const val TS_MAX = 5_000_000_000_000L

    @Volatile private var schemaLogged = false

    /** keystore2 — and thus a readable database — only exists on Android 12+. */
    fun available(): Boolean = Build.VERSION.SDK_INT >= 31

    /**
     * The live keys THIS MODULE minted for the given apps, read from a snapshot of keystore2's database.
     * [targets] maps each target app uid (keystore2's `namespace`) to its package name; the map's keys are
     * the uids we query for, its values decorate each returned row. Yields one JSON object per key:
     * `{ id, alias, uid, package, state, created?, keybox? }` — `id` is keyentry.id (the handle
     * [deleteKeys] removes by), `keybox` is the signing keybox filename when the chain could be
     * attributed. Returns an empty list on any failure, when [available] is false, or when [targets] is
     * empty — never throws.
     */
    fun listKeys(targets: Map<Int, String>): List<JSONObject> {
        if (!available() || targets.isEmpty()) return emptyList()

        val src = File(KEYSTORE2_DB)
        if (!src.isFile) {
            SystemLogger.warning("KeystoreDb: $KEYSTORE2_DB not present")
            return emptyList()
        }

        var db: SQLiteDatabase? = null
        return try {
            val copy = snapshot(src)
            db = SQLiteDatabase.openDatabase(copy.absolutePath, null, SQLiteDatabase.OPEN_READONLY)
            logSchemaOnce(db)
            query(db, targets)
        } catch (e: Throwable) {
            SystemLogger.warning("KeystoreDb.listKeys failed", e)
            emptyList()
        } finally {
            try {
                db?.close()
            } catch (_: Throwable) {}
            try {
                snapshotDir.deleteRecursively()
            } catch (_: Throwable) {}
        }
    }

    /** One pre-existing key to re-attest: its owning app uid, keyentry id, and leaf certificate DER. */
    data class AttestedKey(val uid: Int, val id: Long, val leaf: ByteArray)

    /**
     * Every stored key of the given app [uids] that carries a hardware attestation leaf and is NOT one
     * of ours (no marker blob) — the pre-existing keys whose attestation the daemon re-roots to the
     * keybox on a config push. One snapshot read for all uids; best effort, never throws. Our own
     * generation keys (marker blobs) are skipped, and keys with no attestation extension (a plain key
     * generated without a challenge) have nothing to re-root and are skipped too.
     */
    fun attestedKeys(uids: Set<Int>): List<AttestedKey> {
        if (!available() || uids.isEmpty()) return emptyList()
        val src = File(KEYSTORE2_DB)
        if (!src.isFile) return emptyList()

        var db: SQLiteDatabase? = null
        return try {
            val copy = snapshot(src)
            db = SQLiteDatabase.openDatabase(copy.absolutePath, null, SQLiteDatabase.OPEN_READONLY)
            if (!tableExists(db, "blobentry")) return emptyList()

            val uidList = uids.joinToString(",") // validated ints -> safe to inline
            val idToUid = LinkedHashMap<Long, Int>()
            db.rawQuery(
                    "SELECT k.id, k.namespace FROM keyentry k WHERE k.domain=0 AND k.namespace IN ($uidList) " +
                        "AND k.alias IS NOT NULL AND k.state=1 " +
                        "AND NOT EXISTS (SELECT 1 FROM blobentry b WHERE b.keyentryid=k.id " +
                        "AND substr(b.blob,1,9)=X'$MARKER_HEX')",
                    null,
                )
                .use { c -> while (c.moveToNext()) idToUid[c.getLong(0)] = c.getInt(1) }
            if (idToUid.isEmpty()) return emptyList()

            val blobsById = HashMap<Long, MutableList<ByteArray>>()
            db.rawQuery(
                    "SELECT keyentryid, blob FROM blobentry WHERE keyentryid IN (${idToUid.keys.joinToString(",")})",
                    null,
                )
                .use { c ->
                    while (c.moveToNext()) {
                        val kid = c.getLong(0)
                        val blob = c.getBlob(1) ?: continue
                        blobsById.getOrPut(kid) { ArrayList() }.add(blob)
                    }
                }
            val cf = CertificateFactory.getInstance("X.509")
            val signers = KeyboxInspector.signerIndex()
            val out = ArrayList<AttestedKey>()
            for ((id, uid) in idToUid) {
                val certs = parseCerts(blobsById[id], cf)
                val leaf = leafOf(certs) ?: continue
                if (leaf.getExtensionValue(ATTEST_EXT_OID) == null) continue // no attestation to re-root
                // Skip keys already rooted in a currently-configured keybox (ones we've patched, or a
                // generation key's chain): re-signing them would be redundant. A key rooted in a keybox
                // that is no longer configured (e.g. after a keybox swap) is NOT matched, so it is
                // re-signed under the new keybox — the re-attest self-heals a rotation.
                if (matchKeybox(certs, leaf, signers) != null) continue
                out.add(AttestedKey(uid, id, leaf.encoded))
            }
            out
        } catch (e: Throwable) {
            SystemLogger.warning("KeystoreDb.attestedKeys failed", e)
            emptyList()
        } finally {
            try {
                db?.close()
            } catch (_: Throwable) {}
            try {
                snapshotDir.deleteRecursively()
            } catch (_: Throwable) {}
        }
    }

    /**
     * Remove the given keys. [ids] are keyentry.id values from [listKeys]; each is first re-verified
     * (read-only, against a snapshot) to be one of our marked blobs belonging to a [targets] app, so a
     * stray or malicious id can never take out a system/banking key. Each eligible key is then deleted
     * the proper way — [Keystore2Service.deleteKeyById], letting keystore2 do it in its own context —
     * and only if that is rejected (e.g. SELinux) does it fall back to a direct database delete, which
     * is logged. Returns the number of keys removed; 0 on any failure — never throws.
     */
    fun deleteKeys(targets: Set<Int>, ids: List<Long>): Int {
        if (!available() || ids.isEmpty() || targets.isEmpty()) return 0

        val eligible = filterOurTargetIds(targets, ids)
        val refused = ids.size - eligible.size
        if (refused > 0)
            SystemLogger.warning("KeystoreDb.deleteKeys: skipping $refused id(s) that aren't marked target-app keys")
        if (eligible.isEmpty()) return 0

        var deleted = 0
        val dbFallback = ArrayList<Long>()
        for (id in eligible) {
            if (Keystore2Service.deleteKeyById(id)) deleted++ else dbFallback.add(id)
        }

        if (dbFallback.isNotEmpty()) {
            SystemLogger.warning(
                "KeystoreDb.deleteKeys: keystore2 API unavailable for ${dbFallback.size} key(s); " +
                    "falling back to direct database delete"
            )
            deleted += deleteFromDatabase(targets, dbFallback)
        }
        SystemLogger.info("KeystoreDb.deleteKeys: removed $deleted of ${ids.size} requested key(s)")
        return deleted
    }

    /** The subset of [ids] that are, right now, our marked blobs owned by a [targets] app (snapshot read). */
    private fun filterOurTargetIds(targets: Set<Int>, ids: List<Long>): List<Long> {
        val src = File(KEYSTORE2_DB)
        if (!src.isFile) return emptyList()
        var db: SQLiteDatabase? = null
        return try {
            val copy = snapshot(src)
            db = SQLiteDatabase.openDatabase(copy.absolutePath, null, SQLiteDatabase.OPEN_READONLY)
            if (!tableExists(db, "blobentry")) return emptyList()
            val uids = targets.joinToString(",")
            val idList = ids.joinToString(",")
            val out = ArrayList<Long>()
            db.rawQuery(
                    "SELECT k.id FROM keyentry k WHERE k.id IN ($idList) AND k.domain=0 " +
                        "AND k.namespace IN ($uids) AND EXISTS (SELECT 1 FROM blobentry b " +
                        "WHERE b.keyentryid=k.id AND substr(b.blob,1,9)=X'$MARKER_HEX')",
                    null,
                )
                .use { c -> while (c.moveToNext()) out.add(c.getLong(0)) }
            out
        } catch (e: Throwable) {
            SystemLogger.warning("KeystoreDb.filterOurTargetIds failed", e)
            emptyList()
        } finally {
            try {
                db?.close()
            } catch (_: Throwable) {}
            try {
                snapshotDir.deleteRecursively()
            } catch (_: Throwable) {}
        }
    }

    /**
     * Fallback delete: remove the keys directly from keystore2's LIVE database (WAL, matching keystore2's
     * mode, with a busy wait), clearing every child row — blobentry + its blobmetadata, keyparameter,
     * keymetadata, grant, … — before the keyentry. [ids] are already verified eligible; each is re-checked
     * against the live DB as a last guard. This write may itself be denied by SELinux for our context, in
     * which case nothing is removed and the failure is logged. Returns the number of keyentry rows deleted.
     */
    private fun deleteFromDatabase(targets: Set<Int>, ids: List<Long>): Int {
        val src = File(KEYSTORE2_DB)
        if (!src.isFile) return 0

        var db: SQLiteDatabase? = null
        var deleted = 0
        try {
            // Open WAL explicitly (keystore2's mode): matching it means we neither flip its journal
            // mode nor trip beginTransactionNonExclusive, which requires the connection be in WAL.
            db =
                SQLiteDatabase.openDatabase(
                    src.absolutePath,
                    null,
                    SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.ENABLE_WRITE_AHEAD_LOGGING,
                )
            // A bounded busy wait lets our writer take the write lock without failing the moment
            // keystore2 happens to be mid-transaction.
            db.rawQuery("PRAGMA busy_timeout=4000", null).use { it.moveToNext() }

            val childTables = tablesWithColumn(db, "keyentryid")
            val hasBlobMeta = tableExists(db, "blobmetadata") && tableExists(db, "blobentry")

            db.beginTransactionNonExclusive()
            try {
                for (id in ids) {
                    if (!isOurTargetKey(db, id, targets)) continue
                    // blobmetadata is keyed by blobentryid, so clear it before blobentry rows go.
                    if (hasBlobMeta) {
                        db.execSQL(
                            "DELETE FROM blobmetadata WHERE blobentryid IN " +
                                "(SELECT id FROM blobentry WHERE keyentryid=?)",
                            arrayOf(id),
                        )
                    }
                    for (t in childTables) db.delete(t, "keyentryid=?", arrayOf(id.toString()))
                    deleted += db.delete("keyentry", "id=?", arrayOf(id.toString()))
                }
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
            SystemLogger.info("KeystoreDb: direct database delete removed $deleted of ${ids.size} key(s)")
        } catch (e: Throwable) {
            SystemLogger.warning("KeystoreDb.deleteFromDatabase failed (SELinux may deny writing keystore2's DB)", e)
        } finally {
            try {
                db?.close()
            } catch (_: Throwable) {}
        }
        return deleted
    }

    /**
     * Copy the DB (and its WAL/SHM siblings when present) into [snapshotDir] and return the copied
     * main file. Copying dodges keystore2's live WAL lock; keeping the -wal/-shm next to the copy
     * (same basename) lets SQLite surface committed-but-uncheckpointed rows.
     */
    private fun snapshot(src: File): File {
        snapshotDir.deleteRecursively()
        if (!snapshotDir.mkdirs() && !snapshotDir.isDirectory)
            throw IllegalStateException("cannot create ${snapshotDir.absolutePath}")
        val dest = File(snapshotDir, src.name)
        src.copyTo(dest, overwrite = true)
        for (suffix in arrayOf("-wal", "-shm")) {
            val sib = File(src.parentFile, src.name + suffix)
            if (sib.isFile) sib.copyTo(File(snapshotDir, sib.name), overwrite = true)
        }
        return dest
    }

    /** Log the discovered table set and the keyentry DDL once, to keep the assumptions auditable. */
    private fun logSchemaOnce(db: SQLiteDatabase) {
        if (schemaLogged) return
        schemaLogged = true
        try {
            val tables = ArrayList<String>()
            db.rawQuery("SELECT name FROM sqlite_master WHERE type='table'", null).use { c ->
                while (c.moveToNext()) tables.add(c.getString(0))
            }
            var keyentrySql = ""
            db.rawQuery("SELECT sql FROM sqlite_master WHERE name='keyentry'", null).use { c ->
                if (c.moveToNext()) keyentrySql = c.getString(0) ?: ""
            }
            SystemLogger.info("KeystoreDb schema: tables=$tables")
            SystemLogger.info("KeystoreDb keyentry: ${keyentrySql.replace('\n', ' ').trim()}")
        } catch (e: Exception) {
            SystemLogger.warning("KeystoreDb: schema probe failed", e)
        }
    }

    private fun query(db: SQLiteDatabase, targets: Map<Int, String>): List<JSONObject> {
        if (!tableExists(db, "blobentry")) {
            // Without blobentry we cannot tell our keys from anyone else's, and listing every app key
            // is exactly what we must not do — so surface nothing.
            SystemLogger.warning("KeystoreDb: no blobentry table; cannot identify our keys")
            return emptyList()
        }

        val hasMeta = tableExists(db, "keymetadata")
        val uids = targets.keys.joinToString(",") // validated ints -> safe to inline
        val createdCol =
            if (hasMeta)
                "(SELECT m.data FROM keymetadata m " +
                    "WHERE m.keyentryid = k.id AND typeof(m.data) = 'integer' " +
                    "AND m.data BETWEEN $TS_MIN AND $TS_MAX ORDER BY m.data ASC LIMIT 1)"
            else "NULL"
        val sql =
            "SELECT k.id AS id, CAST(k.alias AS TEXT) AS alias, k.namespace AS uid, " +
                "k.state AS state, $createdCol AS created " +
                "FROM keyentry k " +
                "WHERE k.domain = 0 AND k.namespace IN ($uids) AND k.alias IS NOT NULL " +
                "AND EXISTS (SELECT 1 FROM blobentry b WHERE b.keyentryid = k.id " +
                "AND substr(b.blob, 1, 9) = X'$MARKER_HEX') " +
                "ORDER BY k.namespace, alias"

        val rows = ArrayList<JSONObject>()
        val ids = ArrayList<Long>()
        db.rawQuery(sql, null).use { c ->
            val iId = c.getColumnIndexOrThrow("id")
            val iAlias = c.getColumnIndexOrThrow("alias")
            val iUid = c.getColumnIndexOrThrow("uid")
            val iState = c.getColumnIndexOrThrow("state")
            val iCreated = c.getColumnIndexOrThrow("created")
            while (c.moveToNext()) {
                val id = c.getLong(iId)
                val uid = c.getInt(iUid)
                val o =
                    JSONObject()
                        // keystore2 assigns keyentry.id as a random 64-bit value, which overflows a
                        // JS Number (2^53); carry it as a string so the WebUI round-trips it losslessly
                        // and delete-by-id matches the same row this listing returned.
                        .put("id", id.toString())
                        .put("alias", c.getString(iAlias))
                        .put("uid", uid)
                        .put("package", targets[uid] ?: JSONObject.NULL)
                        .put("state", c.getInt(iState))
                if (!c.isNull(iCreated)) o.put("created", c.getLong(iCreated))
                rows.add(o)
                ids.add(id)
            }
        }

        if (rows.isNotEmpty()) attributeKeys(db, rows, ids)
        SystemLogger.info("KeystoreDb: ${rows.size} of our keys across ${targets.size} target uids")
        return rows
    }

    /**
     * Fill in each key's metadata that lives in its stored certificate chain: the signing algorithm of
     * the generated key (the leaf certificate's public key) and the keybox that signed it (the leaf's
     * issuer, or any chain subject, matched against [KeyboxInspector.signerIndex]). Fetches every blob of
     * the listed keys in one pass; rows and [ids] are index-aligned. Best effort — a key whose certs
     * don't parse simply gets neither field.
     */
    private fun attributeKeys(db: SQLiteDatabase, rows: List<JSONObject>, ids: List<Long>) {
        val blobsById = HashMap<Long, MutableList<ByteArray>>()
        val idList = ids.joinToString(",")
        try {
            db.rawQuery("SELECT keyentryid, blob FROM blobentry WHERE keyentryid IN ($idList)", null).use { c ->
                while (c.moveToNext()) {
                    val kid = c.getLong(0)
                    val blob = c.getBlob(1) ?: continue
                    blobsById.getOrPut(kid) { ArrayList() }.add(blob)
                }
            }
        } catch (e: Exception) {
            SystemLogger.warning("KeystoreDb: could not read blobs for key attribution", e)
            return
        }

        val signers = KeyboxInspector.signerIndex()
        val cf = CertificateFactory.getInstance("X.509")
        for (i in rows.indices) {
            val certs = parseCerts(blobsById[ids[i]], cf)
            if (certs.isEmpty()) continue
            val leaf = leafOf(certs)
            if (leaf != null) rows[i].put("keyAlgorithm", keyAlgorithm(leaf))
            matchKeybox(certs, leaf, signers)?.let { rows[i].put("keybox", it) }
        }
    }

    /** Every X.509 cert across a key's non-marker blobs (a blob may hold one cert or a concatenated chain). */
    private fun parseCerts(blobs: List<ByteArray>?, cf: CertificateFactory): List<X509Certificate> {
        if (blobs == null) return emptyList()
        val out = ArrayList<X509Certificate>()
        for (blob in blobs) {
            if (isMarked(blob)) continue // the key blob, not a cert
            try {
                cf.generateCertificates(ByteArrayInputStream(blob)).forEach {
                    (it as? X509Certificate)?.let(out::add)
                }
            } catch (_: Exception) {}
        }
        return out
    }

    /** The end-entity (the generated key's cert): the one whose subject is no other cert's issuer. */
    private fun leafOf(certs: List<X509Certificate>): X509Certificate? {
        if (certs.isEmpty()) return null
        val issuers = certs.map { KeyboxInspector.canonicalDn(it.issuerX500Principal) }.toHashSet()
        return certs.firstOrNull { KeyboxInspector.canonicalDn(it.subjectX500Principal) !in issuers }
            ?: certs.first()
    }

    /** The keybox that signed this chain: the leaf's issuer, else any chain cert that is a keybox subject. */
    private fun matchKeybox(
        certs: List<X509Certificate>,
        leaf: X509Certificate?,
        signers: Map<String, String>,
    ): String? {
        if (signers.isEmpty()) return null
        if (leaf != null) signers[KeyboxInspector.canonicalDn(leaf.issuerX500Principal)]?.let { return it }
        for (cert in certs) {
            signers[KeyboxInspector.canonicalDn(cert.issuerX500Principal)]?.let { return it }
            signers[KeyboxInspector.canonicalDn(cert.subjectX500Principal)]?.let { return it }
        }
        return null
    }

    /** Human-readable algorithm + size of a certificate's public key (i.e. the generated key). */
    private fun keyAlgorithm(cert: X509Certificate): String =
        when (val pk = cert.publicKey) {
            is RSAPublicKey -> "RSA ${pk.modulus.bitLength()}"
            is ECPublicKey -> "EC ${pk.params.curve.field.fieldSize}"
            else -> pk.algorithm ?: "?"
        }

    private fun isMarked(blob: ByteArray): Boolean {
        if (blob.size < 9) return false
        // "TEESIMkm\0"
        val m = byteArrayOf(0x54, 0x45, 0x45, 0x53, 0x49, 0x4D, 0x6B, 0x6D, 0x00)
        for (i in m.indices) if (blob[i] != m[i]) return false
        return true
    }

    /** True iff [id] is a Live target-app key whose blob still carries our marker (a delete precondition). */
    private fun isOurTargetKey(db: SQLiteDatabase, id: Long, targets: Set<Int>): Boolean {
        val uids = targets.joinToString(",")
        return db.rawQuery(
                "SELECT 1 FROM keyentry k WHERE k.id=? AND k.domain=0 AND k.namespace IN ($uids) " +
                    "AND EXISTS (SELECT 1 FROM blobentry b WHERE b.keyentryid=k.id " +
                    "AND substr(b.blob,1,9)=X'$MARKER_HEX')",
                arrayOf(id.toString()),
            )
            .use { it.moveToNext() }
    }

    /** Names of every table that has a `keyentryid` column — the child rows a key delete must clear. */
    private fun tablesWithColumn(db: SQLiteDatabase, column: String): List<String> {
        val out = ArrayList<String>()
        val tables = ArrayList<String>()
        db.rawQuery("SELECT name FROM sqlite_master WHERE type='table'", null).use { c ->
            while (c.moveToNext()) tables.add(c.getString(0))
        }
        for (t in tables) {
            if (t == "keyentry") continue // deleted last, by its own id
            try {
                db.rawQuery("PRAGMA table_info(${quoteIdent(t)})", null).use { c ->
                    val i = c.getColumnIndex("name")
                    while (c.moveToNext()) {
                        if (i >= 0 && c.getString(i) == column) {
                            out.add(t)
                            break
                        }
                    }
                }
            } catch (_: Exception) {}
        }
        return out
    }

    private fun quoteIdent(name: String): String = "\"" + name.replace("\"", "\"\"") + "\""

    private fun tableExists(db: SQLiteDatabase, name: String): Boolean =
        db.rawQuery("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", arrayOf(name)).use {
            it.moveToNext()
        }
}
