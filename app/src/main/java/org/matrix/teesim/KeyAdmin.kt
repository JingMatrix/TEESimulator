package org.matrix.teesim

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.Build
import android.security.keystore.KeyInfo
import android.system.Os
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.cert.X509CertificateHolder
import org.json.JSONArray
import org.json.JSONObject

/**
 * Key-management endpoint the WebUI calls to list / inspect / delete AndroidKeyStore entries the
 * daemon (a real root Context) can reach. Minimal HTTP/1.1 over a FILESYSTEM unix-domain socket at
 * [Const.adminSocketFile], inside the 0700 root-only [Const.DATA_DIR]. A loopback TCP port would be
 * connectable by any app uid — and a service answering there fingerprints the module — so it is served
 * on a unix socket instead: the kernel refuses a connect() from any non-root caller, making the
 * endpoint invisible to every other app. The WebView cannot reach a unix socket directly, so the WebUI
 * drives it through its root-exec bridge and the shipped `teesim-uds` client. Every request still
 * carries the random admin token (defense in depth on top of the socket's permissions); the peer uid is
 * additionally checked to be root at accept time.
 *
 * Contract (all responses application/json; send header `X-Teesim-Token: <token>`): GET /status ->
 * { ok, version, harvest{...}, lib{hook,api} } GET /keys -> { ok, keys:[ {alias, securityLevel, ours,
 * cert{...}} ] } GET /keys/db[?refresh=1] -> { ok, available, apiLevel, keys:[ {id, alias, uid, package,
 * state, class, created?, keybox?, keyAlgorithm?, purposes?} ] } (target-app keys with a stored
 * attestation cert, from keystore2's DB on API >= 31; empty + available=false on 10/11 where there is no
 * such database. The uid->app mapping comes from the resolved snapshot; refresh=1 — the WebUI's
 * pull-to-refresh only — forces a live re-resolve instead) GET /scope -> { ok, epoch, resolvedAtMs,
 * baselineReady, profiles:[ {id, autoInclude, packages:[..], explicitUids:[..], autoUids:[..]} ] } (what
 * the last push actually targets, per profile; the only place auto-included uids are visible, since the
 * rule needs the root-only known_packages.json baseline. Empty profiles[] with epoch 0 before the first
 * push) POST /rescan -> { ok, uids } (re-resolve against the live device and re-push; how a newly
 * installed app is discovered, there being no package watcher) GET
 * /packages -> { ok, firstAppUid, apps:[ {uid, packages:[..], label, system, launchable, enabled,
 * installTime, freq, lastUsed, recent} ] } (every installed app, one entry per uid, for the Scope
 * picker: installTime = epoch ms of first install; freq = persistent key-request count; lastUsed =
 * epoch ms of last request; recent = requested a key since this boot) GET /icon?pkg=P&token=T -> raw
 * image/png (query-token auth, like /logs/download; 404 when the package has no icon) POST /usage/clear
 * -> { ok, cleared } (wipes the frequency memory) POST
 * /keys/db/delete?ids=1,2,3 -> { ok, deleted, requested } (removes those keyentry ids from keystore2,
 * marker- and target-verified) GET /keys/inspect?alias=A -> { ok, alias, attestation{...} | null }
 * POST /keys/delete?alias=A -> { ok, deleted } GET /logs?after=N&max=M
 * -> { ok, lines:[{seq,level,tag,text}], nextAfter } GET /keybox/inspect?name=F -> { ok, name,
 * deviceId, revocationListAvailable, keys:[{algorithm, privateKeyPresent, chainLength, linkage,
 * rootAuthority(google|aosp|knox|unknown|none), googleSigned, chainVerified, revoked, revocationChecked,
 * certs:[{index, subject, issuer, serial, notBefore, notAfter, expired, sigAlg, keyAlgorithm, keySize,
 * isCa, selfSigned, signatureValid?, revocationChecked?, revoked?, revocationStatus?, revocationReason?,
 * rootAuthority?}]}] } GET /canary ->
 * { ok, currentCode, latest{...}|null, updateAvailable } POST /canary/install?tag=&variant= -> { ok,
 * message }
 */
object KeyAdmin {

    private const val ATTEST_OID = "1.3.6.1.4.1.11129.2.1.17"
    // A plausible package name for the /icon query, so a caller can't smuggle path/argument junk through
    // ?pkg= into PackageManager. Same shape ConfigStore validates apps[] package entries with (the
    // user an icon should be looked up in rides in its own ?user= parameter, not in the name).
    private val PKG_RE = Regex("^[A-Za-z0-9_.]+$")
    // Upper bound on a request body (bytes). The admin socket is root-only + token-authed, but a bogus
    // Content-Length should still never be trusted as an allocation size.
    private const val MAX_BODY_BYTES = 8 * 1024 * 1024
    // Highest rotated log-part index LogTail keeps on disk (teesim.1.log .. teesim.<N>.log); mirrors
    // kMaxParts in logcat.cpp so /logs/download reassembles the full set in chronological order.
    private const val LOG_PART_MAX = 4
    private val b64 = Base64.getEncoder()

    @Volatile private var token: String = ""
    @Volatile private var harvest: Harvester.Record? = null

    /**
     * Set by [App] to its resolve-and-push, and invoked by `POST /rescan` — the WebUI's pull-to-refresh
     * on the Profiles screen. This is what makes app discovery work without a package observer: the
     * re-resolve re-reads the live installed-app set, so a profile that auto-includes new apps picks up
     * anything installed since the last one. Returns the number of caller uids the new push targets, or
     * -1 if there was no valid config to push.
     */
    @Volatile var onRescan: (() -> Int)? = null

    fun start(record: Harvester.Record) {
        harvest = record
        token = newToken()
        return startInner()
    }

    /** Swap in a freshly re-merged record after an overrides.json change, so /status reflects the live
     *  override layer without restarting the daemon. */
    fun updateHarvest(record: Harvester.Record) {
        harvest = record
    }

    // Hold the listening socket and the LocalSocket that owns its bound fd for the life of the daemon,
    // so neither is garbage-collected out from under the accept loop (a finalizer would close the fd).
    @Volatile private var listenSocket: LocalServerSocket? = null
    @Volatile private var listenBinder: LocalSocket? = null

    private fun startInner() {
        try {
            Const.adminTokenFile.parentFile?.mkdirs()
            // The data dir holds the token and the admin socket; keep it root-only (0700) so neither is
            // reachable by another uid even before the socket's own permissions apply. /data/adb is
            // already 0700 on every supported root solution — this is belt-and-suspenders.
            runCatching { Os.chmod(Const.DATA_DIR, /* 0700 */ 448) }
            Const.adminTokenFile.writeText(token)
            Const.adminTokenFile.setReadable(false, false)
            Const.adminTokenFile.setReadable(true, true) // owner (root) only
        } catch (e: Exception) {
            SystemLogger.error("KeyAdmin: failed to write admin token", e)
        }
        Thread({ serve() }, "teesim-keyadmin").apply {
            isDaemon = true
            start()
        }
    }

    private fun newToken(): String {
        val b = ByteArray(24)
        SecureRandom().nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    /**
     * Constant-time comparison of a caller-supplied token against the in-memory admin token. A `null`
     * or length-mismatched candidate never matches. Length-independent so the compare time does not
     * leak how many leading characters were correct — the token is the only thing standing between an
     * app on the device and the admin surface, so it is compared without an early-out.
     */
    private fun tokensMatch(candidate: String?): Boolean {
        val expected = token
        if (candidate == null || expected.isEmpty()) return false
        var diff = candidate.length xor expected.length
        for (i in expected.indices) {
            diff = diff or (expected[i].code xor (candidate.getOrNull(i)?.code ?: 0))
        }
        return diff == 0
    }

    /**
     * Bind a fresh filesystem-namespaced unix socket at [path] and wrap its fd in a LocalServerSocket
     * (whose constructor calls listen()). A LocalServerSocket(String) would use the ABSTRACT namespace,
     * which ignores filesystem permissions and is reachable by any app — exactly what we are avoiding —
     * so we bind the filesystem path explicitly. Any prior binder/server is closed first, and the two
     * @Volatile fields are refreshed so the accept loop and any GC finalizer both see the live fd.
     * Returns the new server, or null if the bind failed. Called on first start AND on the recovery
     * path in [serve] when the listen fd is torn out from under us (see #265).
     */
    private fun bindListener(path: String): LocalServerSocket? {
        // Drop any prior listener explicitly so a rebind never leaks the old fd.
        runCatching { listenSocket?.close() }
        runCatching { listenBinder?.close() }
        return try {
            // A stale socket file (this run's dead node, or one left by a previous run) would make
            // bind() fail with EADDRINUSE.
            Const.adminSocketFile.delete()
            val binder = LocalSocket(LocalSocket.SOCKET_STREAM)
            binder.bind(LocalSocketAddress(path, LocalSocketAddress.Namespace.FILESYSTEM))
            listenBinder = binder
            // The 0700 data dir already blocks other uids; also mark the socket node 0600.
            runCatching { Os.chmod(path, /* 0600 */ 384) }
            LocalServerSocket(binder.fileDescriptor).also { listenSocket = it }
        } catch (e: Exception) {
            SystemLogger.error("KeyAdmin: cannot bind unix socket $path", e)
            null
        }
    }

    private fun serve() {
        val path = Const.adminSocketFile.absolutePath
        var server = bindListener(path) ?: return
        SystemLogger.info("KeyAdmin: listening on unix:$path")
        // Consecutive accept() failures without an intervening success. A healthy endpoint stays at 0;
        // a listen fd closed under us (EBADF — #265, MIUI power management reclaiming the fd on
        // screen-off) fails instantly and forever, so we count the streak, back off so the thread never
        // hot-spins at ~2.4 cores flooding the log, and rebind the socket to recover.
        var consecutiveFailures = 0
        while (true) {
            try {
                val client = server.accept()
                consecutiveFailures = 0
                // Defense in depth on top of the socket's filesystem permissions: only root may drive
                // the admin endpoint. A peer that is not uid 0 is dropped without a byte of response.
                val peerUid =
                    try {
                        client.peerCredentials.uid
                    } catch (_: Exception) {
                        -1
                    }
                if (peerUid != 0) {
                    SystemLogger.warning("KeyAdmin: rejecting non-root peer uid=$peerUid")
                    runCatching { client.close() }
                    continue
                }
                // Handle each connection on its own thread with a read timeout, so one slow, half-open,
                // or mis-framed client (e.g. a Content-Length that never fully arrives) can never wedge
                // the accept loop and take the whole admin endpoint down with it.
                client.soTimeout = 15000
                Thread({
                    try {
                        handle(client)
                    } catch (e: Exception) {
                        SystemLogger.warning("KeyAdmin: handle error", e)
                    }
                }, "teesim-keyadmin-conn").apply { isDaemon = true }.start()
            } catch (e: Exception) {
                consecutiveFailures++
                // Log the first failure of a burst with its stack, then stay quiet: a dead fd throws
                // thousands of times a second, and logging every one is itself the flood #265 reports.
                if (consecutiveFailures == 1) {
                    SystemLogger.warning("KeyAdmin: accept error; will back off and rebind", e)
                }
                // Back off (capped) so a persistently dead fd costs ~nothing instead of a whole core.
                try {
                    Thread.sleep(minOf(1000L, 50L * consecutiveFailures))
                } catch (_: InterruptedException) {
                    return
                }
                // The listen fd will not heal on its own — rebind a fresh socket so the WebUI becomes
                // reachable again without a daemon restart (which would never come: the process stays
                // alive under Looper.loop, so service.sh's respawn never fires).
                if (consecutiveFailures >= 3) {
                    val rebound = bindListener(path)
                    if (rebound != null) {
                        server = rebound
                        consecutiveFailures = 0
                        SystemLogger.info("KeyAdmin: rebound unix:$path after accept failures")
                    } else {
                        SystemLogger.warning("KeyAdmin: rebind failed; retrying")
                    }
                }
            }
        }
    }

    private fun handle(client: LocalSocket) {
        client.use {
            val reader = BufferedReader(InputStreamReader(client.inputStream, Charsets.UTF_8))
            val out = client.outputStream

            // Do NOT log the request line yet: nothing about a request is trusted or reflected until the
            // token check below passes, so an unauthenticated caller never sees its own path echoed into
            // the log. The request line is logged only after auth succeeds.
            val requestLine = reader.readLine() ?: return
            val t0 = System.currentTimeMillis()
            val parts = requestLine.split(" ")
            if (parts.size < 2) return // malformed: drop silently, emit nothing
            val method = parts[0]
            val rawPath = parts[1]

            var headerToken: String? = null
            var contentLength = 0
            while (true) {
                val line = reader.readLine() ?: break
                if (line.isEmpty()) break
                val idx = line.indexOf(':')
                if (idx <= 0) continue
                val hName = line.substring(0, idx).trim()
                val hVal = line.substring(idx + 1).trim()
                when {
                    hName.equals("X-Teesim-Token", true) -> headerToken = hVal
                    hName.equals("Content-Length", true) -> contentLength = hVal.toIntOrNull() ?: 0
                }
            }

            // The peer is already proven to be root (checked at accept) and reached us only through the
            // root-only socket; the token is the final gate. A request without it is dropped silently —
            // no response body, no reflected path, nothing to observe. There is no browser on this
            // transport any more, so no CORS/OPTIONS handling is needed.
            if (!tokensMatch(headerToken)) return
            SystemLogger.info("KeyAdmin: → ${requestLine.take(140)}")

            // Raw (non-JSON) routes: a PNG icon and a plain-text log stream. The WebUI reaches these
            // through the same token-authenticated helper as every other route (a browser <img>/download
            // navigation could not set the header, but the WebUI no longer fetches these directly — it
            // pipes the bytes in over the root bridge).
            val rawRoute = rawPath.substringBefore('?')
            if (method == "GET" && rawRoute == "/logs/download") {
                downloadLogs(out, parseQuery(rawPath.substringAfter('?', "")))
                return
            }
            if (method == "GET" && rawRoute == "/icon") {
                serveIcon(out, parseQuery(rawPath.substringAfter('?', "")))
                return
            }

            // Read the request body when one was announced. The request line and headers were
            // consumed through `reader`, whose buffer may already hold body bytes, so the body must
            // be read from the SAME reader — not the raw socket stream. Content-Length is a byte
            // count, so read decoded chars until that many UTF-8 bytes have been consumed.
            // A client-supplied Content-Length is untrusted: cap it so a bogus huge value cannot force a
            // multi-gigabyte allocation (an OutOfMemoryError would escape the per-connection catch, which
            // only handles Exception, and kill the thread). Our largest real body is a keybox, well under
            // this. The initial StringBuilder capacity is also bounded rather than trusting the header.
            if (contentLength > MAX_BODY_BYTES) {
                respond(out, 413, JSONObject().put("ok", false).put("error", "request body too large"))
                return
            }
            val requestBody =
                if (contentLength > 0) {
                    val sb = StringBuilder(minOf(contentLength, 64 * 1024))
                    val buf = CharArray(4096)
                    var bytes = 0
                    while (bytes < contentLength) {
                        val n = reader.read(buf, 0, buf.size)
                        if (n < 0) break
                        sb.append(buf, 0, n)
                        bytes += String(buf, 0, n).toByteArray(Charsets.UTF_8).size
                    }
                    sb.toString()
                } else {
                    ""
                }

            val path = rawPath.substringBefore('?')
            val query = parseQuery(rawPath.substringAfter('?', ""))
            try {
                val body =
                    when {
                        method == "GET" && path == "/status" -> status()
                        method == "GET" && path == "/keys" -> listKeys()
                        method == "GET" && path == "/keys/db" -> keysDb(query)
                        method == "GET" && path == "/scope" -> scope()
                        method == "GET" && path == "/packages" -> packages()
                        method == "POST" && path == "/rescan" -> rescan()
                        method == "POST" && path == "/usage/clear" -> usageClear()
                        method == "POST" && path == "/keys/db/delete" -> deleteDbKeys(query)
                        method == "GET" && path == "/keys/inspect" ->
                            inspect(query["alias"] ?: error("alias required"))
                        method == "POST" && path == "/keys/delete" ->
                            delete(query["alias"] ?: error("alias required"))
                        method == "GET" && path == "/logs" -> logs(query)
                        method == "GET" && path == "/keybox/inspect" ->
                            KeyboxInspector.inspect(
                                query["name"] ?: error("name required"),
                                query["refresh"] == "1",
                            )
                        method == "GET" && path == "/canary" -> Updater.status()
                        method == "POST" && path == "/canary/install" ->
                            Updater.install(
                                query["tag"] ?: error("tag required"),
                                query["variant"] ?: "release",
                            )
                        method == "POST" && path == "/logs/write" -> writeLogs(query, requestBody)
                        else -> JSONObject().put("ok", false).put("error", "not found")
                    }
                val ok = body.optBoolean("ok", true)
                respond(out, if (ok) 200 else 400, body)
                SystemLogger.info("KeyAdmin: ← ${method} ${path} ${if (ok) 200 else 400} in ${System.currentTimeMillis() - t0}ms")
            } catch (e: Exception) {
                respond(out, 500, JSONObject().put("ok", false).put("error", e.message ?: "error"))
                SystemLogger.warning("KeyAdmin: ← ${method} ${path} 500 in ${System.currentTimeMillis() - t0}ms: ${e.message}")
            }
        }
    }

    // --- operations -------------------------------------------------------------

    private fun androidKeyStore(): KeyStore =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun status(): JSONObject {
        val o = JSONObject().put("ok", true)
        o.put("version", Updater.currentVersion())
        harvest?.let { o.put("harvest", Harvester.toJson(it)) }
        o.put(
            "lib",
            JSONObject().put("hook", Control.libHook ?: JSONObject.NULL).put("api", Control.libApi),
        )
        return o
    }

    private fun listKeys(): JSONObject {
        val ks = androidKeyStore()
        val keys = JSONArray()
        val ours = harvest?.effectiveBootKey()
        val aliases = ks.aliases()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            val entry = JSONObject().put("alias", alias)
            val cert = ks.getCertificate(alias) as? X509Certificate
            entry.put("securityLevel", securityLevelForAlias(ks, alias))
            entry.put("ours", cert != null && isOurs(cert, ours))
            if (cert != null) {
                // The provenance the WebUI shows: which app asked (the attestation
                // application id), which profile/keybox would sign for it, and the key's
                // algorithm/created (from certSummary). Cert subject/issuer is not shown.
                entry.put("cert", certSummary(cert))
                val apps = attestationAppPackages(cert)
                if (apps.isNotEmpty()) entry.put("requestedBy", JSONArray(apps))
                keyboxForApps(apps)?.let { (profile, keybox) ->
                    entry.put("profile", profile)
                    entry.put("keybox", keybox)
                }
            }
            keys.put(entry)
        }
        return JSONObject().put("ok", true).put("keys", keys)
    }

    /**
     * The keys the target apps (every package named across the live config's profiles) hold in
     * keystore2's per-app namespaces, read from [KeystoreDb]. This is the visibility [listKeys]
     * cannot give: those keys live under the apps' uids, not the daemon's AndroidKeyStore. On
     * Android 10/11 there is no keystore2 database, so `available` is false and `keys` is empty —
     * the WebUI turns that into its "hidden" hint.
     */
    private fun keysDb(query: Map<String, String>): JSONObject {
        val targets = targetUidToPackage(query["refresh"] == "1")
        val keys = JSONArray()
        KeystoreDb.listKeys(targets).forEach { keys.put(it) }
        return JSONObject()
            .put("ok", true)
            .put("available", KeystoreDb.available())
            .put("apiLevel", Build.VERSION.SDK_INT)
            .put("keys", keys)
    }

    /**
     * Remove the given keystore2 keys (keyentry ids, comma-separated in `ids`) that this module minted.
     * [KeystoreDb.deleteKeys] re-checks, against the live database, that each id is one of OUR marked
     * blobs and belongs to a target app before deleting it, so an out-of-range id is a no-op rather than
     * a hazard. Deleting an attestation key just makes the app re-create (and re-attest) it.
     */
    private fun deleteDbKeys(query: Map<String, String>): JSONObject {
        val raw = query["ids"] ?: error("ids required")
        val ids = raw.split(",").mapNotNull { it.trim().toLongOrNull() }
        if (ids.isEmpty()) return JSONObject().put("ok", false).put("error", "no valid ids")
        val n = KeystoreDb.deleteKeys(targetUidToPackage().keys, ids)
        return JSONObject().put("ok", true).put("deleted", n).put("requested", ids.size)
    }

    /**
     * uid -> a representative package name for every effective target across the live config, via
     * [Scope.uidToPackage] (which folds in raw uid:N tokens and auto-included apps, mapping the
     * package-less ones to their uid:token). Keeps the try/catch + empty-map fallback so a broken
     * config just yields an empty stored-keys view rather than a 500.
     *
     * Economical by default: it answers from the resolved snapshot the last push published, which
     * costs nothing. [force] — set only by the WebUI's pull-to-refresh — pays for a live re-resolve
     * instead, which re-enumerates every installed app. That is the deal everywhere in this daemon:
     * automatic reads take the snapshot, a user asking for fresh data gets a fresh answer.
     *
     * The snapshot describes the last SUCCESSFULLY PUSHED config, so if config.json was edited and the
     * push then failed, this reflects last-good rather than the file on disk. That divergence is
     * transient — the ConfigStore watcher re-pushes — and it is arguably the more honest answer, since
     * the stored-keys view is about which apps are actually being attested for.
     */
    private fun targetUidToPackage(force: Boolean = false): Map<Int, String> =
        try {
            Scope.uidToPackage(ConfigStore.load(), force)
        } catch (e: Exception) {
            SystemLogger.warning("KeyAdmin: config load failed for /keys/db", e)
            emptyMap()
        }

    /**
     * The daemon's RESOLVED scope — per profile, what the last push actually targets. Read straight off
     * the snapshot [Scope.lastResolved] published by the push path: it never calls Scope.resolve (which
     * enumerates every installed app when a profile auto-includes) and takes no lock, so it is cheap
     * and safe on a KeyAdmin connection thread.
     *
     * This is the ONLY channel by which the WebUI can learn which apps are auto-included. The rule
     * needs known_packages.json, a root-only file the WebUI cannot read, so the answer has to come from
     * here rather than be recomputed client-side — which is also what keeps the rule from being
     * implemented twice and drifting.
     *
     * Before the first push there is no snapshot; that answers ok with an empty profiles[] and epoch 0
     * rather than an error, so a WebUI that loads first simply shows no auto data yet.
     */
    private fun scope(): JSONObject {
        val snap = Scope.lastResolved()
        val profiles = JSONArray()
        if (snap != null)
            for (s in snap.scopes) {
                val autos = s.autoUids.sorted()
                profiles.put(
                    JSONObject()
                        .put("id", s.profileId)
                        .put("autoInclude", s.autoInclude)
                        // The entries as written, so a pkg@user target reads as one — packageNames
                        // alone would show two users' copies of an app as the same line twice.
                        .put(
                            "packages",
                            JSONArray(
                                s.explicit.filter { it.pkg != null }.map { it.entry }
                            ),
                        )
                        .put("explicitUids", JSONArray((s.uids - s.autoUids).sorted()))
                        .put("autoUids", JSONArray(autos))
                )
            }
        SystemLogger.info(
            "KeyAdmin: /scope epoch=${snap?.epoch ?: 0} profiles=${profiles.length()} " +
                "auto=${snap?.scopes?.sumOf { it.autoUids.size } ?: 0} baselineReady=${snap?.baselineReady == true}"
        )
        return JSONObject()
            .put("ok", true)
            .put("epoch", snap?.epoch ?: 0L)
            .put("resolvedAtMs", snap?.atMs ?: 0L)
            .put("baselineReady", snap?.baselineReady == true)
            .put("profiles", profiles)
    }

    /**
     * Every installed app, one entry per uid, for the WebUI's Scope picker. The daemon runs as root so
     * [Packages.installedAppsByUid] sees all apps in every Android user — an app installed in both the
     * primary user and a work profile is two entries, with two uids, because it is two callers to
     * keystore. `system` additionally folds in any privileged uid (its app id below the first app uid,
     * in whichever user). Each entry also carries the usage face the picker sorts/badges on:
     * `installTime`, and (from [UsageStore], reduced over the entry's app tokens) `freq` (max count),
     * `lastUsed` (max epoch), `recent` (any package seen this boot). Sorted server-side by label then uid;
     * the client re-sorts per its chosen order. A best-effort usage poll runs first so the freq/recent
     * columns reflect the very latest requests without waiting for the 15s background poll.
     *
     * `users` lists the device's users so the picker can label and group by them without inventing
     * names from uid arithmetic.
     */
    private fun packages(): JSONObject {
        try {
            App.pollUsageOnce()
        } catch (e: Exception) {
            SystemLogger.verbose("KeyAdmin: pre-/packages usage poll skipped: ${e.message}")
        }
        val firstAppUid = Packages.firstAppUid()
        val entries =
            Packages.installedAppsByUid().sortedWith(
                compareBy({ it.label.lowercase() }, { it.uid })
            )
        val arr = JSONArray()
        for (e in entries) {
            // Usage is remembered per app token (pkg, or pkg@user outside the primary user), so the
            // work profile's copy of an app carries its own request count rather than the other's.
            val tokens = e.packages.map { Scope.entryToken(it, e.userId) }
            val freq = tokens.maxOfOrNull { UsageStore.freqOf(it) } ?: 0L
            val lastUsed = tokens.maxOfOrNull { UsageStore.lastUsedOf(it) } ?: 0L
            val recent = tokens.any { UsageStore.isRecent(it) }
            arr.put(
                JSONObject()
                    .put("uid", e.uid)
                    .put("userId", e.userId)
                    .put("packages", JSONArray(e.packages))
                    .put("label", e.label)
                    .put("system", e.system || Scope.isPrivilegedUid(e.uid))
                    .put("launchable", e.launchable)
                    .put("enabled", e.enabled)
                    .put("installTime", e.installTime)
                    .put("freq", freq)
                    .put("lastUsed", lastUsed)
                    .put("recent", recent)
            )
        }
        val users = JSONArray()
        for (u in Packages.users())
            users.put(JSONObject().put("id", u.id).put("name", u.name).put("managed", u.managed))
        SystemLogger.info(
            "KeyAdmin: /packages -> ${entries.size} uid entr(ies) across ${users.length()} user(s), " +
                "firstAppUid=$firstAppUid"
        )
        return JSONObject()
            .put("ok", true)
            .put("firstAppUid", firstAppUid)
            .put("users", users)
            .put("apps", arr)
    }

    /** Wipe the persistent frequency memory. Returns how many entries were cleared. */
    private fun usageClear(): JSONObject {
        val cleared = UsageStore.clear()
        return JSONObject().put("ok", true).put("cleared", cleared)
    }

    /**
     * Re-resolve the config against the live device and push it — the lazy half of app discovery, run
     * when the user pulls the Profiles screen down. Everything expensive already happens inside
     * [App.resolveAndPush] (config re-read, package enumeration, push, re-attest on the ack), so this
     * only reports the resulting target count for the WebUI's toast.
     */
    private fun rescan(): JSONObject {
        val hook =
            onRescan
                ?: return JSONObject().put("ok", false).put("error", "daemon not ready")
        val uids = hook()
        if (uids < 0)
            return JSONObject().put("ok", false).put("error", "no valid config to push")
        SystemLogger.info("KeyAdmin: rescan pushed a config targeting $uids caller uid(s)")
        return JSONObject().put("ok", true).put("uids", uids)
    }

    /**
     * Stream the rendered PNG icon for `?pkg=`, looked up in `?user=` (default 0, so an app that only
     * exists in a work profile still resolves). Validates the package shape before touching
     * PackageManager, answers 404 (as JSON) when the package has no icon or rendering fails, and relies
     * on [Packages.iconPng]'s in-memory cache so a scrolling list of <img> hits stays cheap.
     */
    private fun serveIcon(out: OutputStream, query: Map<String, String>) {
        val pkg = query["pkg"]
        if (pkg == null || !PKG_RE.matches(pkg)) {
            respond(out, 400, JSONObject().put("ok", false).put("error", "bad pkg"))
            return
        }
        val user = query["user"]?.toIntOrNull() ?: 0
        if (user < 0) {
            respond(out, 400, JSONObject().put("ok", false).put("error", "bad user"))
            return
        }
        val png = Packages.iconPng(pkg, user)
        if (png == null) {
            respond(out, 404, JSONObject().put("ok", false).put("error", "no icon"))
            return
        }
        respondRaw(out, 200, "image/png", listOf("Cache-Control: max-age=86400"), png)
    }

    private fun inspect(alias: String): JSONObject {
        val ks = androidKeyStore()
        val cert =
            ks.getCertificate(alias) as? X509Certificate
                ?: return JSONObject().put("ok", false).put("error", "no certificate for alias")
        val attestation = parseAttestation(cert)
        return JSONObject()
            .put("ok", true)
            .put("alias", alias)
            .put("cert", certSummary(cert))
            .put("attestation", attestation ?: JSONObject.NULL)
    }

    private fun delete(alias: String): JSONObject {
        val ks = androidKeyStore()
        if (!ks.containsAlias(alias))
            return JSONObject().put("ok", false).put("error", "alias not found")
        ks.deleteEntry(alias)
        SystemLogger.info("KeyAdmin: deleted alias $alias")
        return JSONObject().put("ok", true).put("deleted", alias)
    }

    /** Recent TEESimulator logcat lines with seq greater than `after`, for the WebUI's Logs tab. */
    private fun logs(query: Map<String, String>): JSONObject {
        val after = query["after"]?.toLongOrNull() ?: 0L
        val max = (query["max"]?.toIntOrNull() ?: 500).coerceIn(1, 2000)
        val (lines, next) = LogTail.snapshot(after, max)
        val arr = JSONArray()
        lines.forEach {
            arr.put(
                JSONObject()
                    .put("seq", it.seq)
                    .put("level", it.level.toString())
                    .put("tag", it.tag)
                    .put("text", it.text)
            )
        }
        return JSONObject().put("ok", true).put("lines", arr).put("nextAfter", next)
    }

    /**
     * Streams the daemon's persisted log as a plain-text attachment (the WebView's download handler
     * ignores an <a download> attribute, so a Content-Disposition header names the saved file). Unlike
     * the in-memory [logs] ring, this reads the rotating files [LogTail] writes under [Const.logDir],
     * oldest part first, so a download taken AFTER a crash or restart still carries the history the ring
     * has already dropped. The whole set is tail-capped so a pathological log can't blow the response
     * up; an optional `max` (MiB, 1..64) overrides the default cap.
     */
    private fun downloadLogs(out: OutputStream, query: Map<String, String>) {
        val capBytes = (query["max"]?.toIntOrNull() ?: 16).coerceIn(1, 64) * 1024 * 1024
        // teesim.<N>.log (oldest) .. teesim.1.log, then teesim.log (newest) — chronological order.
        val ordered =
            (LOG_PART_MAX downTo 1).map { File(Const.logDir, "teesim.$it.log") } +
                File(Const.logDir, "teesim.log")
        val present = ordered.filter { it.isFile }
        val total = present.sumOf { it.length() }
        val payload =
            try {
                val buf =
                    java.io.ByteArrayOutputStream(
                        minOf(total, capBytes.toLong()).toInt().coerceAtLeast(0)
                    )
                // When the on-disk log exceeds the cap, keep the NEWEST bytes: skip whole older parts,
                // then partially skip into the first part that fits.
                var skip = (total - capBytes).coerceAtLeast(0)
                for (f in present) {
                    val len = f.length()
                    if (skip >= len) {
                        skip -= len
                        continue
                    }
                    f.inputStream().use { ins ->
                        if (skip > 0) {
                            ins.skip(skip)
                            skip = 0
                        }
                        ins.copyTo(buf)
                    }
                }
                buf.toByteArray()
            } catch (e: Exception) {
                SystemLogger.warning("KeyAdmin: reading log files for download failed", e)
                ByteArray(0)
            }
        val name = safeDownloadName(query["name"])
        respondRaw(
            out,
            200,
            "text/plain; charset=utf-8",
            listOf("Content-Disposition: attachment; filename=\"$name\""),
            payload,
        )
    }

    /**
     * Reduces a client-supplied filename to a safe basename for a Content-Disposition header:
     * strips path separators, quotes, and control characters (CR/LF included, which would allow
     * header injection), caps the length, and falls back to a default when nothing survives.
     */
    private fun safeDownloadName(raw: String?): String {
        val cleaned =
            (raw ?: "")
                .replace(Regex("[\\x00-\\x1f/\\\\\"]"), "")
                .trim()
                .take(128)
        return if (cleaned.isEmpty()) "teesim-logs.log" else cleaned
    }

    /**
     * Writes the log text the WebUI shows to a caller-chosen file, so the saved file is named and
     * placed by the daemon (root) rather than the WebView, which ignores both the download filename
     * and Content-Disposition. The directory is an absolute path the user chose and is used verbatim;
     * the name is reduced to a safe basename. The resolved file must still sit inside that directory
     * (a canonical-path check rejects any traversal), then the directory is created and the bytes
     * written. Responds { ok, path } or { ok:false, error }.
     */
    private fun writeLogs(query: Map<String, String>, body: String): JSONObject {
        val dir = query["dir"] ?: return JSONObject().put("ok", false).put("error", "dir required")
        if (!dir.startsWith("/"))
            return JSONObject().put("ok", false).put("error", "dir must be an absolute path")
        val safeName = safeDownloadName(query["name"])
        val dirFile = File(dir)
        val canonicalDir = dirFile.canonicalPath
        val target = File(dirFile, safeName)
        val canonicalTarget = target.canonicalPath
        if (canonicalTarget != canonicalDir + File.separator + safeName &&
            !canonicalTarget.startsWith(canonicalDir + File.separator)) {
            return JSONObject().put("ok", false).put("error", "invalid path")
        }
        return try {
            dirFile.mkdirs()
            File(canonicalTarget).writeBytes(body.toByteArray(Charsets.UTF_8))
            SystemLogger.info("KeyAdmin: wrote ${body.length} chars of logs to $canonicalTarget")
            JSONObject().put("ok", true).put("path", canonicalTarget)
        } catch (e: Exception) {
            SystemLogger.warning("KeyAdmin: /logs/write failed for $canonicalTarget", e)
            JSONObject().put("ok", false).put("error", e.message ?: "write failed")
        }
    }

    // --- helpers ----------------------------------------------------------------

    // isInsideSecureHardware is the only pre-31 signal, and the fallback for an unknown level on 31+.
    @Suppress("DEPRECATION")
    private fun securityLevelForAlias(ks: KeyStore, alias: String): String {
        return try {
            val key = ks.getKey(alias, null) as? PrivateKey ?: return "unknown"
            val factory = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= 31) {
                when (info.securityLevel) {
                    0 -> "Software"
                    1 -> "TrustedEnvironment"
                    2 -> "StrongBox"
                    else -> if (info.isInsideSecureHardware) "TrustedEnvironment" else "Software"
                }
            } else {
                if (info.isInsideSecureHardware) "TrustedEnvironment" else "Software"
            }
        } catch (e: Exception) {
            "unknown"
        }
    }

    /** Ours = leaf carries an attestation whose RootOfTrust boot key is our frozen one. */
    private fun isOurs(cert: X509Certificate, ourBootKey: ByteArray?): Boolean {
        if (ourBootKey == null) return false
        val a = parseAttestation(cert) ?: return false
        val vbk = a.optString("verifiedBootKeyHex", "")
        return vbk.isNotEmpty() && vbk.equals(ourBootKey.toHex(), true)
    }

    private fun certSummary(cert: X509Certificate): JSONObject =
        JSONObject().apply {
            put("subject", cert.subjectX500Principal.name)
            put("issuer", cert.issuerX500Principal.name)
            put("serial", cert.serialNumber.toString(16))
            put("notBefore", cert.notBefore.time)
            put("notAfter", cert.notAfter.time)
            put("expired", cert.notAfter.time < System.currentTimeMillis())
            put("sigAlg", cert.sigAlgName)
            when (val pk = cert.publicKey) {
                is RSAPublicKey -> {
                    put("keyAlgorithm", "RSA")
                    put("keySize", pk.modulus.bitLength())
                }
                is ECPublicKey -> {
                    put("keyAlgorithm", "EC")
                    put("keySize", pk.params.curve.field.fieldSize)
                }
                else -> {
                    put("keyAlgorithm", pk.algorithm ?: "?")
                    put("keySize", 0)
                }
            }
        }

    /** Parse the leaf's KeyDescription extension into a flat JSON summary, or null. */
    private fun parseAttestation(cert: X509Certificate): JSONObject? {
        return try {
            val holder = X509CertificateHolder(cert.encoded)
            val ext = holder.getExtension(ASN1ObjectIdentifier(ATTEST_OID)) ?: return null
            val kd = ASN1Sequence.getInstance(ext.extnValue.octets)
            val fields = kd.toArray()
            val o = JSONObject()
            o.put("attestationVersion", ASN1Integer.getInstance(fields[0]).positiveValue.toInt())
            o.put("attestationSecurityLevel", ASN1Enumerated.getInstance(fields[1]).value.toInt())
            o.put("keymasterVersion", ASN1Integer.getInstance(fields[2]).positiveValue.toInt())
            o.put("keymasterSecurityLevel", ASN1Enumerated.getInstance(fields[3]).value.toInt())

            val tee = ASN1Sequence.getInstance(fields[7])
            tee.forEach { element ->
                val tagged = element as ASN1TaggedObject
                when (tagged.tagNo) {
                    704 -> { // RootOfTrust
                        val rot = ASN1Sequence.getInstance(tagged.baseObject.toASN1Primitive())
                        if (rot.size() >= 4) {
                            o.put(
                                "verifiedBootKeyHex",
                                ASN1OctetString.getInstance(rot.getObjectAt(0)).octets.toHex(),
                            )
                            o.put(
                                "deviceLocked",
                                ASN1Boolean.getInstance(rot.getObjectAt(1)).isTrue,
                            )
                            o.put(
                                "verifiedBootState",
                                ASN1Enumerated.getInstance(rot.getObjectAt(2)).value.toInt(),
                            )
                            o.put(
                                "verifiedBootHashHex",
                                ASN1OctetString.getInstance(rot.getObjectAt(3)).octets.toHex(),
                            )
                        }
                    }
                    705 -> o.put("osVersion", intOf(tagged))
                    706 -> o.put("osPatchLevel", intOf(tagged))
                    718 -> o.put("vendorPatchLevel", intOf(tagged))
                    719 -> o.put("bootPatchLevel", intOf(tagged))
                }
            }
            o.put("extensionB64", b64.encodeToString(ext.extnValue.octets))
            o
        } catch (e: Exception) {
            SystemLogger.warning("KeyAdmin: could not parse attestation for cert", e)
            null
        }
    }

    private fun intOf(t: ASN1TaggedObject): Int =
        ASN1Integer.getInstance(t.baseObject.toASN1Primitive()).positiveValue.toInt()

    /**
     * Package names from the leaf's ATTESTATION_APPLICATION_ID (tag 709, in
     * softwareEnforced) — i.e. which app requested the key. Empty when absent/unparseable.
     */
    private fun attestationAppPackages(cert: X509Certificate): List<String> =
        try {
            val holder = X509CertificateHolder(cert.encoded)
            val ext = holder.getExtension(ASN1ObjectIdentifier(ATTEST_OID))
            if (ext == null) {
                emptyList()
            } else {
                val kd = ASN1Sequence.getInstance(ext.extnValue.octets)
                val sw = ASN1Sequence.getInstance(kd.toArray()[6]) // softwareEnforced
                val appId = sw.toArray().firstOrNull { (it as? ASN1TaggedObject)?.tagNo == 709 }
                if (appId == null) {
                    emptyList()
                } else {
                    val octets =
                        ASN1OctetString.getInstance((appId as ASN1TaggedObject).baseObject).octets
                    val seq = ASN1Sequence.getInstance(octets)
                    // AttestationApplicationId ::= { SET OF AttestationPackageInfo, SET OF digests }
                    val pkgSet = ASN1Set.getInstance(seq.getObjectAt(0))
                    pkgSet.toArray().map { e ->
                        val info = ASN1Sequence.getInstance(e)
                        String(ASN1OctetString.getInstance(info.getObjectAt(0)).octets, Charsets.UTF_8)
                    }
                }
            }
        } catch (e: Exception) {
            emptyList()
        }

    /** The (profile id, keybox) that would sign for any of [apps], from the live config. */
    private fun keyboxForApps(apps: List<String>): Pair<String, String>? {
        if (apps.isEmpty()) return null
        val cfg =
            try {
                ConfigStore.load()
            } catch (e: Exception) {
                return null
            }
        val p = cfg.profiles.firstOrNull { prof -> prof.apps.any { it in apps } } ?: return null
        return p.id to p.keybox
    }

    private fun parseQuery(q: String): Map<String, String> {
        if (q.isEmpty()) return emptyMap()
        return q.split("&")
            .mapNotNull {
                val i = it.indexOf('=')
                if (i <= 0) null
                else
                    java.net.URLDecoder.decode(it.substring(0, i), "UTF-8") to
                        java.net.URLDecoder.decode(it.substring(i + 1), "UTF-8")
            }
            .toMap()
    }

    private fun respond(out: OutputStream, code: Int, body: JSONObject?) {
        val reason =
            when (code) {
                200 -> "OK"
                204 -> "No Content"
                400 -> "Bad Request"
                403 -> "Forbidden"
                404 -> "Not Found"
                500 -> "Internal Server Error"
                else -> "OK"
            }
        val payload = body?.toString()?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
        val sb = StringBuilder()
        sb.append("HTTP/1.1 $code $reason\r\n")
        sb.append("Content-Type: application/json\r\n")
        sb.append("Content-Length: ${payload.size}\r\n")
        sb.append("Access-Control-Allow-Origin: *\r\n")
        sb.append("Access-Control-Allow-Headers: X-Teesim-Token, Content-Type\r\n")
        sb.append("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n")
        sb.append("Connection: close\r\n")
        sb.append("\r\n")
        out.write(sb.toString().toByteArray(Charsets.UTF_8))
        if (payload.isNotEmpty()) out.write(payload)
        out.flush()
    }

    /**
     * Writes a raw HTTP/1.1 response with a caller-chosen Content-Type and extra header lines,
     * for downloads that can't use the JSON [respond]. Sends the same CORS and Connection headers.
     */
    private fun respondRaw(
        out: OutputStream,
        code: Int,
        contentType: String,
        extraHeaders: List<String>,
        payload: ByteArray,
    ) {
        val reason =
            when (code) {
                200 -> "OK"
                204 -> "No Content"
                400 -> "Bad Request"
                403 -> "Forbidden"
                404 -> "Not Found"
                500 -> "Internal Server Error"
                else -> "OK"
            }
        val sb = StringBuilder()
        sb.append("HTTP/1.1 $code $reason\r\n")
        sb.append("Content-Type: $contentType\r\n")
        sb.append("Content-Length: ${payload.size}\r\n")
        extraHeaders.forEach { sb.append(it).append("\r\n") }
        sb.append("Access-Control-Allow-Origin: *\r\n")
        sb.append("Access-Control-Allow-Headers: X-Teesim-Token, Content-Type\r\n")
        sb.append("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n")
        sb.append("Connection: close\r\n")
        sb.append("\r\n")
        out.write(sb.toString().toByteArray(Charsets.UTF_8))
        if (payload.isNotEmpty()) out.write(payload)
        out.flush()
    }
}
