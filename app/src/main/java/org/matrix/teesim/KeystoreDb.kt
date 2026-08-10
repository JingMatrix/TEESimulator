package org.matrix.teesim

import android.database.sqlite.SQLiteDatabase
import android.os.Build
import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import org.json.JSONArray
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

    // keystore2 stores key parameters in `keyparameter(tag, data)`. Tag::PURPOSE is the KeyMint tag
    // enum (TagType.ENUM_REP<<28 | 1) and KeyPurpose::ATTEST_KEY is 7, so a row (PURPOSE, 7) marks an
    // attestation key. Confirmed against the live DB on-device.
    private const val PURPOSE_TAG = 536870913 // 0x20000001
    private const val ATTEST_KEY_PURPOSE = 7

    // KeyPurpose enum values keystore2 stores under Tag::PURPOSE, mapped to display labels. Value 4 is
    // unused by KeyMint; an unknown value falls back to its number so nothing is silently dropped.
    private val PURPOSE_LABELS = mapOf(
        0 to "Encrypt", 1 to "Decrypt", 2 to "Sign", 3 to "Verify",
        5 to "WrapKey", 6 to "AgreeKey", 7 to "AttestKey",
    )

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
    @Synchronized
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
    @Synchronized
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
            var skippedNoAttestation = 0
            var skippedRooted = 0
            for ((id, uid) in idToUid) {
                val certs = parseCerts(blobsById[id], cf)
                val leaf = leafOf(certs)
                if (leaf == null) {
                    skippedNoAttestation++
                    continue
                }
                if (leaf.getExtensionValue(ATTEST_EXT_OID) == null) {
                    skippedNoAttestation++ // no attestation extension to re-root
                    continue
                }
                // Skip keys already rooted in a currently-configured keybox (ones we've patched, or a
                // generation key's chain): re-signing them would be redundant. A key rooted in a keybox
                // that is no longer configured (e.g. after a keybox swap) is NOT matched, so it is
                // re-signed under the new keybox — the re-attest self-heals a rotation.
                if (matchKeybox(certs, leaf, signers) != null) {
                    skippedRooted++
                    continue
                }
                out.add(AttestedKey(uid, id, leaf.encoded))
            }
            SystemLogger.info(
                "KeystoreDb.attestedKeys: ${idToUid.size} non-marker candidate(s) across ${uids.size} uid(s) -> " +
                    "${out.size} to re-root ($skippedNoAttestation without attestation, $skippedRooted already keybox-rooted)"
            )
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
     * (read-only, against a snapshot) to belong to a [targets] app, so a stray or malicious id can never
     * take out a system/banking key. The page lists every target-app key — ours and pre-existing real
     * ones — and any of them may be deleted (the target apps are the user's chosen spoofing targets), so
     * this is scoped to the target uids but NOT to our marker. Each eligible key is deleted as its owning
     * app (via [Keystore2Service.deleteKeyByIdAsUid], which seteuid's so keystore2 accepts it and evicts
     * its cache); only a key that owner-delete cannot remove falls back to a direct database delete, which
     * is logged and takes effect once keystore2 next restarts. Returns the number removed; 0 on failure.
     */
    fun deleteKeys(targets: Set<Int>, ids: List<Long>): Int {
        if (!available() || ids.isEmpty() || targets.isEmpty()) return 0

        val eligible = filterTargetIds(targets, ids)
        val refused = ids.size - eligible.size
        if (refused > 0)
            SystemLogger.warning("KeystoreDb.deleteKeys: skipping $refused id(s) that aren't target-app keys")
        if (eligible.isEmpty()) return 0

        var deleted = 0
        val dbFallback = ArrayList<Long>()
        for ((id, uid) in eligible) {
            if (Keystore2Service.deleteKeyByIdAsUid(id, uid) == 0) deleted++ else dbFallback.add(id)
        }

        if (dbFallback.isNotEmpty()) {
            SystemLogger.warning(
                "KeystoreDb.deleteKeys: owner-delete refused for ${dbFallback.size} key(s); falling back to a " +
                    "direct database delete (takes effect after keystore2 next restarts)"
            )
            deleted += deleteFromDatabase(dbFallback) { db, id -> isTargetKey(db, id, targets) }
        }
        SystemLogger.info("KeystoreDb.deleteKeys: removed $deleted of ${ids.size} requested key(s)")
        return deleted
    }

    /**
     * Delete every FOREIGN (not-ours) ATTEST_KEY-purpose key owned by a [targets] app. Called once at
     * daemon start so a stale attestation key — one made before the app was covered (real, unlocked) or
     * under a previous build — is removed and the app is forced to regenerate it, which now always
     * goes through the TA's generation path (we hold the private key, so leaves it later attests get
     * root-of-trust patched). Our OWN marked attest keys are left alone: they are already keybox-rooted
     * and we hold their key. Scoped hard to target uids AND ATTEST_KEY purpose AND not-our-marker, so
     * it can never touch a system or banking key. Deletes each as its owning app first (so keystore2
     * evicts its cache); only a key that owner-delete cannot remove falls back to a direct database
     * delete. Returns the number that needed the database fallback — those require a keystore2 restart
     * to take effect, since a raw database delete does not evict keystore2's cache; 0 otherwise.
     */
    fun deleteTargetAttestKeys(targets: Set<Int>): Int {
        if (!available() || targets.isEmpty()) return 0
        val keys = targetAttestKeyIds(targets)
        if (keys.isEmpty()) return 0
        SystemLogger.info("KeystoreDb.deleteTargetAttestKeys: ${keys.size} attest key(s) to clear across ${targets.size} target uid(s)")

        var viaOwner = 0
        val dbFallback = ArrayList<Long>()
        for ((id, uid) in keys) {
            if (Keystore2Service.deleteKeyByIdAsUid(id, uid) == 0) viaOwner++ else dbFallback.add(id)
        }
        var viaDb = 0
        if (dbFallback.isNotEmpty()) {
            SystemLogger.warning(
                "KeystoreDb.deleteTargetAttestKeys: owner-delete refused for ${dbFallback.size} key(s); " +
                    "falling back to a direct database delete (needs a keystore2 restart to evict the cache)"
            )
            viaDb = deleteFromDatabase(dbFallback) { db, id -> isTargetAttestKey(db, id, targets) }
        }
        SystemLogger.info(
            "KeystoreDb.deleteTargetAttestKeys: removed ${viaOwner + viaDb} of ${keys.size} attest key(s) " +
                "($viaOwner as the owner, $viaDb via the database)"
        )
        return viaDb
    }

    /** (keyentry id, owner uid) for each ATTEST_KEY-purpose, not-ours key of a [targets] app (snapshot read). */
    @Synchronized
    private fun targetAttestKeyIds(targets: Set<Int>): List<Pair<Long, Int>> {
        val src = File(KEYSTORE2_DB)
        if (!src.isFile) return emptyList()
        var db: SQLiteDatabase? = null
        return try {
            val copy = snapshot(src)
            db = SQLiteDatabase.openDatabase(copy.absolutePath, null, SQLiteDatabase.OPEN_READONLY)
            if (!tableExists(db, "keyparameter")) return emptyList()
            val uids = targets.joinToString(",")
            val out = ArrayList<Pair<Long, Int>>()
            db.rawQuery(
                    "SELECT k.id, k.namespace FROM keyentry k WHERE k.domain=0 AND k.namespace IN ($uids) " +
                        "AND EXISTS (SELECT 1 FROM keyparameter p WHERE p.keyentryid=k.id " +
                        "AND p.tag=$PURPOSE_TAG AND p.data=$ATTEST_KEY_PURPOSE) " +
                        "AND NOT EXISTS (SELECT 1 FROM blobentry b WHERE b.keyentryid=k.id " +
                        "AND substr(b.blob,1,9)=X'$MARKER_HEX')",
                    null,
                )
                .use { c -> while (c.moveToNext()) out.add(c.getLong(0) to c.getInt(1)) }
            out
        } catch (e: Throwable) {
            SystemLogger.warning("KeystoreDb.targetAttestKeyIds failed", e)
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

    /** Live-DB re-check that [id] is a FOREIGN (not-our-marker) ATTEST_KEY-purpose key of a [targets] app. */
    private fun isTargetAttestKey(db: SQLiteDatabase, id: Long, targets: Set<Int>): Boolean {
        val uids = targets.joinToString(",")
        return db.rawQuery(
                "SELECT 1 FROM keyentry k WHERE k.id=? AND k.domain=0 AND k.namespace IN ($uids) " +
                    "AND EXISTS (SELECT 1 FROM keyparameter p WHERE p.keyentryid=k.id " +
                    "AND p.tag=$PURPOSE_TAG AND p.data=$ATTEST_KEY_PURPOSE) " +
                    "AND NOT EXISTS (SELECT 1 FROM blobentry b WHERE b.keyentryid=k.id " +
                    "AND substr(b.blob,1,9)=X'$MARKER_HEX')",
                arrayOf(id.toString()),
            )
            .use { it.moveToNext() }
    }

    /** The subset of [ids] that, right now, belong to a [targets] app, each with its owner uid (snapshot
     * read). Marker-agnostic: pre-existing real keys are deletable too, but the target-uid scope still
     * bars non-target keys. The uid lets the delete run as the key's owner so keystore2 accepts it. */
    @Synchronized
    private fun filterTargetIds(targets: Set<Int>, ids: List<Long>): List<Pair<Long, Int>> {
        val src = File(KEYSTORE2_DB)
        if (!src.isFile) return emptyList()
        var db: SQLiteDatabase? = null
        return try {
            val copy = snapshot(src)
            db = SQLiteDatabase.openDatabase(copy.absolutePath, null, SQLiteDatabase.OPEN_READONLY)
            if (!tableExists(db, "keyentry")) return emptyList()
            val uids = targets.joinToString(",")
            val idList = ids.joinToString(",")
            val out = ArrayList<Pair<Long, Int>>()
            db.rawQuery(
                    "SELECT k.id, k.namespace FROM keyentry k WHERE k.id IN ($idList) AND k.domain=0 " +
                        "AND k.namespace IN ($uids)",
                    null,
                )
                .use { c -> while (c.moveToNext()) out.add(c.getLong(0) to c.getInt(1)) }
            out
        } catch (e: Throwable) {
            SystemLogger.warning("KeystoreDb.filterTargetIds failed", e)
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
    private fun deleteFromDatabase(ids: List<Long>, guard: (SQLiteDatabase, Long) -> Boolean): Int {
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
                    if (!guard(db, id)) continue
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
                "AND EXISTS (SELECT 1 FROM blobentry b WHERE b.keyentryid = k.id) " +
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
        SystemLogger.info("KeystoreDb: ${rows.size} attested keys across ${targets.size} target uids")
        return rows
    }

    /**
     * Fill in each key's metadata that lives in its stored certificate chain: the signing algorithm of
     * the generated key (the leaf certificate's public key) and the keybox that signed it (the leaf's
     * issuer, or any chain subject, matched against [KeyboxInspector.signerIndex]). Fetches every blob of
     * the listed keys in one pass; rows and [ids] are index-aligned. Best effort — a key whose certs
     * don't parse simply gets neither field. Also attaches a "class" naming how the chain is
     * keybox-rooted (generated / delegated / patched / untouched), always set for every row. Also
     * attaches "purposes", the key's KeyPurpose labels (from its Tag::PURPOSE rows), when it has any.
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

        // keystore2 stores each key's purposes as repeated PURPOSE rows in keyparameter; read them all
        // in one batched pass, like the blobs above, so every row can report what its key may be used
        // for. Best effort: a missing table or a read error just leaves the purposes off.
        val purposesById = HashMap<Long, MutableList<Int>>()
        if (tableExists(db, "keyparameter")) {
            try {
                db.rawQuery(
                    "SELECT keyentryid, data FROM keyparameter WHERE tag=$PURPOSE_TAG AND keyentryid IN ($idList)",
                    null,
                ).use { c ->
                    while (c.moveToNext()) {
                        purposesById.getOrPut(c.getLong(0)) { ArrayList() }.add(c.getInt(1))
                    }
                }
            } catch (e: Exception) {
                SystemLogger.warning("KeystoreDb: could not read key purposes", e)
            }
        }

        val signers = KeyboxInspector.signerIndex()
        val cf = CertificateFactory.getInstance("X.509")
        for (i in rows.indices) {
            val blobs = blobsById[ids[i]]
            val marked = blobs?.any { isMarked(it) } ?: false
            val certs = parseCerts(blobs, cf)
            val leaf = if (certs.isEmpty()) null else leafOf(certs)
            if (leaf != null) rows[i].put("keyAlgorithm", keyAlgorithm(leaf))
            val keybox = matchKeybox(certs, leaf, signers)
            keybox?.let { rows[i].put("keybox", it) }
            // Classify the key by how (and whether) its chain is keybox-rooted. A generated key
            // carries our marker and its leaf is signed directly by a keybox batch; a delegated key
            // is marked but signed by our attestation key, keybox-rooted only through a deeper cert;
            // a patched key is a real hardware blob whose LEAF we re-rooted onto a keybox batch.
            // Patched keys the leaf must be batch-issued: a genuine untouched key shares Google's real
            // root/intermediate with the keybox, so matching any chain cert would misclassify it.
            val leafKeyboxIssued =
                leaf != null && signers[KeyboxInspector.canonicalDn(leaf.issuerX500Principal)] != null
            val cls =
                when {
                    marked && leafKeyboxIssued -> "generated"
                    marked && keybox != null -> "delegated"
                    !marked && leafKeyboxIssued -> "patched"
                    else -> "untouched"
                }
            rows[i].put("class", cls)
            purposesById[ids[i]]?.let { vals ->
                val labels = vals.toSortedSet().map { PURPOSE_LABELS[it] ?: it.toString() }
                rows[i].put("purposes", JSONArray(labels))
            }
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

    /** True iff [id] belongs to a [targets] app (the live-DB delete precondition; marker-agnostic). */
    private fun isTargetKey(db: SQLiteDatabase, id: Long, targets: Set<Int>): Boolean {
        val uids = targets.joinToString(",")
        return db.rawQuery(
                "SELECT 1 FROM keyentry k WHERE k.id=? AND k.domain=0 AND k.namespace IN ($uids)",
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
