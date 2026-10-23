package org.matrix.teesim

import android.os.SystemClock
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
 * last cached copy is used; with no cache at all, one bounded synchronous fetch is attempted and a
 * failure then holds off the next one for [FAIL_BACKOFF_MS], so lookups stay cheap offline. When
 * nothing is available the lookups report "unknown" rather than a false "not revoked".
 */
object RevocationList {

    private const val STATUS_URL = "https://android.googleapis.com/attestation/status"
    private val cacheFile = File(Const.DATA_DIR, "attestation_status.json")
    private const val TTL_MS = 12 * 60 * 60 * 1000L // refresh at most twice a day

    // How long a failed fetch suppresses the next unsolicited one. Without this, a device with no
    // cached list and no network re-attempted the fetch on EVERY lookup: one keybox inspect calls
    // available() once per <Key> plus once for the response, so opening the inspector offline
    // blocked the KeyAdmin handler thread for a multiple of the 8s connect timeout before the page
    // rendered. A minute is short enough that the list appears on the first inspect after the
    // network returns.
    private const val FAIL_BACKOFF_MS = 60 * 1000L

    @Volatile private var entries: JSONObject? = null
    @Volatile private var loadedAt = 0L
    @Volatile private var refreshing = false
    // Earliest time an unsolicited fetch may be tried again, on the MONOTONIC clock. The daemon
    // starts before the boot's time sync, so warm()'s failure is stamped with whatever the RTC
    // said, and a sync that moves the wall clock backwards would leave a wall-clock deadline
    // sitting in the future — suppressing every automatic fetch for the length of the correction.
    // [loadedAt] is wall-clock on purpose: it is compared against the cache file's mtime, which
    // outlives the process. This deadline never has to.
    @Volatile private var nextFetchAt = 0L
    // Whether the disk cache has been read at all; see [ensureEntries].
    @Volatile private var diskCacheTried = false

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

    /**
     * Force a fresh fetch straight from the server — bypassing the TTL and any edge cache — then
     * report availability. Backs the keybox inspector's pull-to-refresh, so a re-verify sees the
     * live list rather than a copy a CDN has been serving for hours.
     */
    fun forceRefresh(): Boolean {
        fetchNow()
        return entries != null
    }

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
        if (entries == null && !diskCacheTried && cacheFile.isFile) {
            // Once, not once per lookup: a cache that fails to parse leaves entries null, so the
            // read and its warning used to repeat on every call for the life of the daemon. A
            // successful fetch rewrites the file and fills entries, which retires this branch.
            diskCacheTried = true
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
            if (have == null) {
                // No data at all — block once (bounded), unless a recent failure is still holding
                // us off. [forceRefresh] goes straight to fetchNow and ignores this.
                if (SystemClock.elapsedRealtime() >= nextFetchAt) fetchNow()
            } else {
                refreshAsync() // stale — serve what we have, refresh behind the scenes
            }
        }
        return entries
    }

    /** Fetch synchronously and adopt the result; leaves any existing copy on failure. */
    private fun fetchNow() {
        try {
            // A unique query defeats any edge/CDN cache — Google serves this list with a one-day
            // max-age, so a plain GET can return a copy hours stale (a real Age header seen in the
            // wild). We want the live list here, and the disk copy is our own caching layer.
            val raw = httpGet("$STATUS_URL?ts=${System.currentTimeMillis()}")
            val parsed = JSONObject(raw).getJSONObject("entries")
            entries = parsed
            loadedAt = System.currentTimeMillis()
            nextFetchAt = 0L
            try {
                cacheFile.parentFile?.mkdirs()
                cacheFile.writeText(raw)
            } catch (e: Exception) {
                SystemLogger.warning("RevocationList: could not write cache", e)
            }
            SystemLogger.info("RevocationList: fetched ${parsed.length()} entries from $STATUS_URL")
        } catch (e: Exception) {
            nextFetchAt = SystemClock.elapsedRealtime() + FAIL_BACKOFF_MS
            SystemLogger.warning("RevocationList: fetch failed (offline?)", e)
        }
    }

    private fun refreshAsync() {
        if (refreshing) return
        // The backoff covers this path too. A stale cache that cannot be refreshed is the common
        // offline state — the cached list outlives the TTL long before the network comes back — and
        // without the check every lookup spawned another thread to block on the connect timeout and
        // fail. Async, so nothing stalled; it was a steady drip of threads and connections instead.
        if (SystemClock.elapsedRealtime() < nextFetchAt) return
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
        c.useCaches = false
        c.setRequestProperty("Accept", "application/json")
        c.setRequestProperty("Cache-Control", "no-cache")
        c.setRequestProperty("Pragma", "no-cache")
        c.setRequestProperty("User-Agent", "TEESimulator")
        c.inputStream.use {
            return it.readBytes().toString(Charsets.UTF_8)
        }
    }
}
