package org.matrix.teesim

import java.io.File
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

/**
 * Google's attestation certificate revocation list — the same one Play Integrity / hardware
 * attestation consults. It is published as JSON at
 * https://android.googleapis.com/attestation/status, an object under "entries" keyed by
 * lowercase-hex certificate serial number, each value carrying a "status" (REVOKED/SUSPENDED) and a
 * "reason" (KEY_COMPROMISE, SOFTWARE_FLAW, …). A keybox whose chain contains a listed serial is
 * dead: attestations it signs are rejected.
 *
 * The daemon has network, so we fetch the live list and cache it to disk (attestation_status.json),
 * serving the cached copy immediately and refreshing in the background when stale. Offline, the
 * last cached copy is used; with no cache at all, one bounded synchronous fetch is attempted. When
 * nothing is available the lookups report "unknown" rather than a false "not revoked".
 */
object RevocationList {

    private const val STATUS_URL = "https://android.googleapis.com/attestation/status"
    private val cacheFile = File(Const.DATA_DIR, "attestation_status.json")
    private const val TTL_MS = 12 * 60 * 60 * 1000L // refresh at most twice a day

    @Volatile private var entries: JSONObject? = null
    @Volatile private var loadedAt = 0L
    @Volatile private var refreshing = false

    /**
     * The {status, reason} for a serial, or null if not listed. Null return != "list unavailable" —
     * pair that with [available] to tell a clean cert from an unknown one.
     */
    fun status(serial: BigInteger): JSONObject? {
        val e = ensureEntries() ?: return null
        val key = serial.toString(16).lowercase()
        return e.optJSONObject(key)
    }

    /** True when we hold a revocation list (fresh or stale) to check against. */
    fun available(): Boolean = ensureEntries() != null

    /** Kick a load/refresh at daemon start-up so the first inspect already has the list. */
    fun warm() {
        Thread(
                {
                    try {
                        ensureEntries()
                    } catch (e: Exception) {
                        SystemLogger.warning("RevocationList: warm failed", e)
                    }
                },
                "teesim-revocation-warm",
            )
            .apply {
                isDaemon = true
                start()
            }
    }

    private fun ensureEntries(): JSONObject? {
        val now = System.currentTimeMillis()
        entries?.let { if (now - loadedAt < TTL_MS) return it }

        // Nothing in memory yet — try the disk cache, adopting its file mtime as the fetch time.
        if (entries == null && cacheFile.isFile) {
            try {
                val parsed = JSONObject(cacheFile.readText()).getJSONObject("entries")
                entries = parsed
                loadedAt = cacheFile.lastModified()
                SystemLogger.info("RevocationList: loaded ${parsed.length()} entries from cache")
            } catch (e: Exception) {
                SystemLogger.warning("RevocationList: bad cache, ignoring", e)
            }
        }

        val have = entries
        val fresh = have != null && now - loadedAt < TTL_MS
        if (!fresh) {
            if (have == null) fetchNow() // no data at all — block once (bounded)
            else refreshAsync() // stale — serve what we have, refresh behind the scenes
        }
        return entries
    }

    /** Fetch synchronously and adopt the result; leaves any existing copy on failure. */
    private fun fetchNow() {
        try {
            val raw = httpGet(STATUS_URL)
            val parsed = JSONObject(raw).getJSONObject("entries")
            entries = parsed
            loadedAt = System.currentTimeMillis()
            try {
                cacheFile.parentFile?.mkdirs()
                cacheFile.writeText(raw)
            } catch (e: Exception) {
                SystemLogger.warning("RevocationList: could not write cache", e)
            }
            SystemLogger.info("RevocationList: fetched ${parsed.length()} entries from $STATUS_URL")
        } catch (e: Exception) {
            SystemLogger.warning("RevocationList: fetch failed (offline?)", e)
        }
    }

    private fun refreshAsync() {
        if (refreshing) return
        refreshing = true
        Thread(
                {
                    try {
                        fetchNow()
                    } finally {
                        refreshing = false
                    }
                },
                "teesim-revocation-refresh",
            )
            .apply {
                isDaemon = true
                start()
            }
    }

    private fun httpGet(url: String): String {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = 8000
        c.readTimeout = 8000
        c.instanceFollowRedirects = true
        c.setRequestProperty("Accept", "application/json")
        c.setRequestProperty("User-Agent", "TEESimulator")
        c.inputStream.use {
            return it.readBytes().toString(Charsets.UTF_8)
        }
    }
}
