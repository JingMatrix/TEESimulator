package org.matrix.teesim

import java.io.File
import org.json.JSONObject

/**
 * The persistent key-request frequency memory behind the Scope picker ([Const.usageFile]). Every
 * uid that asks keystore for a key is recorded by the lib and polled by [App]; that poll turns
 * per-uid deltas into per-APP updates here. The key is the app token — the package name, or
 * `pkg@user` outside the primary user, exactly as [Scope.entryToken] spells it — and not the uid,
 * because a uid is recycled on reinstall/clear-data while the app identity the user recognises
 * persists, so "com.foo asked for 42 keys" survives an uninstall/reinstall and even a factory boot.
 * The user is part of the key so a work profile's copy of an app keeps its own count rather than
 * inheriting the other's.
 *
 * On disk: { "version":1, "apps": { "com.foo": { "count":42, "lastUsed":<epochMs> } } }. [count]
 * accumulates across boots (the poller adds deltas); [lastUsed] is the wall-clock epoch of the most
 * recent request. Separately, [sinceBoot] is the in-memory set of packages seen during THIS daemon
 * run — the "Recent" group in the picker — and is deliberately NOT persisted (it means "since this
 * boot").
 *
 * Writes are debounced: a busy device can poll many packages in a burst, and rewriting usage.json
 * on every [record] would be wasteful, so a dirty flag is flushed at most once per
 * [WRITE_DEBOUNCE_MS] via an atomic temp-file rename, exactly like the other DATA_DIR stores.
 */
object UsageStore {

    private const val WRITE_DEBOUNCE_MS = 3_000L

    /**
     * One package's accumulated frequency and most-recent use. Mutable so [record] can update in
     * place.
     */
    data class Stat(var count: Long, var lastUsed: Long)

    private val lock = Object()
    private var loaded = false
    private val map = HashMap<String, Stat>()
    // Packages that requested a key during THIS daemon run — the picker's "Recent" group. Not
    // persisted.
    private val sinceBoot = HashSet<String>()
    // Per-uid "cumulative count already folded in": the lib reports counts cumulative since ITS
    // load, so each poll records only (current - cursor). This MUST persist, or a daemon-only
    // restart (the lib in keystore2 keeps counting) would see no cursor, treat the lib's whole
    // cumulative as a delta, and double-add it on top of the counts already in usage.json.
    // Persisted in usage.json under
    // "cursors";
    // deliberately NOT wiped by clear() (so a clear doesn't make the next poll re-add the lib's
    // history).
    private val cursors = HashMap<Int, Long>()

    // Debounce state: [dirty] means the in-memory map diverges from disk; [lastWriteMs] gates the
    // flush.
    private var dirty = false
    private var lastWriteMs = 0L

    /**
     * Lazily load usage.json the first time any accessor runs; never throws — a broken file just
     * means "no remembered usage yet" and starts fresh (the next flush overwrites it). Caller holds
     * [lock].
     */
    private fun ensureLoaded() {
        if (loaded) return
        loaded = true
        val f = Const.usageFile
        if (!f.exists()) {
            SystemLogger.info("UsageStore: no usage.json yet; starting empty")
            return
        }
        try {
            val root = JSONObject(f.readText())
            val apps = root.optJSONObject("apps") ?: JSONObject()
            for (pkg in apps.keys()) {
                val s = apps.optJSONObject(pkg) ?: continue
                map[pkg] = Stat(s.optLong("count", 0L), s.optLong("lastUsed", 0L))
            }
            val cur = root.optJSONObject("cursors")
            if (cur != null)
                for (k in cur.keys()) k.toIntOrNull()?.let { cursors[it] = cur.optLong(k, 0L) }
            SystemLogger.info(
                "UsageStore: loaded ${map.size} package(s), ${cursors.size} cursor(s) from usage.json"
            )
        } catch (e: Exception) {
            SystemLogger.warning("UsageStore: usage.json unreadable; starting empty", e)
            map.clear()
        }
    }

    /**
     * Fold one poll's worth of activity for [pkg] into the memory: add [deltaCount] new requests to
     * the running count, advance [lastUsed] to the newer of the stored/observed epoch, and mark the
     * package as seen this boot. A zero/negative delta with a fresh timestamp still updates recency
     * (the app was active) without inflating the count. Flushes to disk debounced.
     */
    fun record(pkg: String, deltaCount: Long, lastUsedEpoch: Long) {
        if (pkg.isEmpty()) return
        synchronized(lock) {
            ensureLoaded()
            val s = map.getOrPut(pkg) { Stat(0L, 0L) }
            if (deltaCount > 0) s.count += deltaCount
            if (lastUsedEpoch > s.lastUsed) s.lastUsed = lastUsedEpoch
            sinceBoot.add(pkg)
            dirty = true
            maybeFlush()
        }
    }

    /**
     * Fold one lib usage sample into the memory, computing the delta against the PERSISTED per-uid
     * cursor so a daemon-only restart never re-adds history. [currentCumulative] is the lib's count
     * for [uid] since the lib loaded; the delta is `current - cursor`, or `current` when the cursor
     * is unknown OR the value shrank (the lib restarted, resetting near zero). The delta lands on
     * [pkg] (package-keyed frequency), the cursor advances to [currentCumulative], and recency
     * updates. Doing the whole read-delta-update atomically here (under [lock]) is why [App]'s poll
     * needs no lock and must never hold one across the blocking control fetch.
     */
    fun applyLibSample(uid: Int, pkg: String, currentCumulative: Long, lastUsedEpoch: Long) {
        if (pkg.isEmpty()) return
        synchronized(lock) {
            ensureLoaded()
            val prev = cursors[uid]
            val delta =
                if (prev == null || currentCumulative < prev) currentCumulative
                else currentCumulative - prev
            cursors[uid] = currentCumulative
            val s = map.getOrPut(pkg) { Stat(0L, 0L) }
            if (delta > 0) s.count += delta
            if (lastUsedEpoch > s.lastUsed) s.lastUsed = lastUsedEpoch
            sinceBoot.add(pkg)
            dirty = true
            maybeFlush()
        }
    }

    /** Persisted request count for [pkg] (0 if never seen). */
    fun freqOf(pkg: String): Long =
        synchronized(lock) {
            ensureLoaded()
            map[pkg]?.count ?: 0L
        }

    /** Wall-clock epoch ms of [pkg]'s most recent key request (0 if never). */
    fun lastUsedOf(pkg: String): Long =
        synchronized(lock) {
            ensureLoaded()
            map[pkg]?.lastUsed ?: 0L
        }

    /** Whether [pkg] has requested a key since THIS daemon started — the picker's "Recent" test. */
    fun isRecent(pkg: String): Boolean =
        synchronized(lock) {
            ensureLoaded()
            pkg in sinceBoot
        }

    /**
     * Wipe the whole frequency memory (the /usage/clear route): clears both the persisted map and
     * the since-boot recency set and rewrites usage.json empty immediately (no debounce — the user
     * asked for it and expects it gone). Returns how many package entries were cleared.
     */
    fun clear(): Int =
        synchronized(lock) {
            ensureLoaded()
            val n = map.size
            map.clear()
            sinceBoot.clear()
            dirty = true
            flush(force = true)
            SystemLogger.info("UsageStore: cleared $n package(s) of usage memory")
            n
        }

    /** Flush if dirty and the debounce window has elapsed. Caller holds [lock]. */
    private fun maybeFlush() {
        val now = System.currentTimeMillis()
        if (dirty && now - lastWriteMs >= WRITE_DEBOUNCE_MS) flush(force = false)
    }

    /** Serialize the map to usage.json atomically (temp + rename). Caller holds [lock]. */
    private fun flush(force: Boolean) {
        if (!dirty && !force) return
        try {
            val apps = JSONObject()
            for ((pkg, s) in map) apps.put(
                pkg,
                JSONObject().put("count", s.count).put("lastUsed", s.lastUsed),
            )
            val cur = JSONObject()
            for ((uid, c) in cursors) cur.put(uid.toString(), c)
            val root = JSONObject().put("version", 1).put("apps", apps).put("cursors", cur)
            val f = Const.usageFile
            f.parentFile?.mkdirs()
            val tmp = File(f.parentFile, "${f.name}.tmp")
            tmp.writeText(root.toString())
            if (!tmp.renameTo(f)) {
                // rename can fail across some overlays; fall back to a direct overwrite so we still
                // persist.
                f.writeText(root.toString())
                tmp.delete()
            }
            dirty = false
            lastWriteMs = System.currentTimeMillis()
        } catch (e: Exception) {
            SystemLogger.warning("UsageStore: failed to write usage.json", e)
        }
    }
}
