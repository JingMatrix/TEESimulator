package org.matrix.teesim

import android.os.Build
import android.security.keystore.KeyInfo
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
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
 * daemon (a real root Context) can reach. Minimal HTTP/1.1 on loopback, guarded by a random token
 * written to [Const.adminTokenFile] (0600) — only root (the WebUI's manager bridge) can read the
 * token, so other apps on the device can't drive it.
 *
 * Contract (all responses application/json; send header `X-Teesim-Token: <token>`): GET /status ->
 * { ok, version, harvest{...}, lib{hook,api} } GET /keys -> { ok, keys:[ {alias, securityLevel, ours,
 * cert{...}} ] } GET /keys/db -> { ok, available, apiLevel, keys:[ {id, alias, uid, package, state, class,
 * created?, keybox?, keyAlgorithm?, purposes?} ] } (target-app keys with a stored attestation cert, from
 * keystore2's DB on API >= 31; empty + available=false on 10/11 where there is no such database) POST
 * /keys/db/delete?ids=1,2,3 -> { ok, deleted, requested } (removes those keyentry ids from keystore2,
 * marker- and target-verified) GET /keys/inspect?alias=A -> { ok, alias, attestation{...} | null }
 * POST /keys/delete?alias=A -> { ok, deleted } GET /logs?after=N&max=M
 * -> { ok, lines:[{seq,level,tag,text}], nextAfter } GET /keybox/inspect?name=F -> { ok, name,
 * deviceId, keys:[{algorithm, privateKeyPresent, chainLength, linkage, certs:[{...}]}] } GET /canary ->
 * { ok, currentCode, latest{...}|null, updateAvailable } POST /canary/install?tag=&variant= -> { ok,
 * message }
 */
object KeyAdmin {

    private const val ATTEST_OID = "1.3.6.1.4.1.11129.2.1.17"
    // Upper bound on a request body (bytes). The admin socket is localhost + token-authed, but a bogus
    // Content-Length should still never be trusted as an allocation size.
    private const val MAX_BODY_BYTES = 8 * 1024 * 1024
    private val b64 = Base64.getEncoder()

    @Volatile private var token: String = ""
    @Volatile private var harvest: Harvester.Record? = null

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

    private fun startInner() {
        try {
            Const.adminTokenFile.parentFile?.mkdirs()
            Const.adminTokenFile.writeText(token)
            Const.adminTokenFile.setReadable(false, false)
            Const.adminTokenFile.setReadable(true, true) // owner (root) only
        } catch (e: Exception) {
            SystemLogger.error("KeyAdmin: failed to write admin token", e)
        }
        LogTail.start()
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

    private fun serve() {
        val server =
            try {
                ServerSocket(Const.ADMIN_PORT, 8, InetAddress.getByName("127.0.0.1"))
            } catch (e: Exception) {
                SystemLogger.error("KeyAdmin: cannot bind 127.0.0.1:${Const.ADMIN_PORT}", e)
                return
            }
        SystemLogger.info("KeyAdmin: listening on 127.0.0.1:${Const.ADMIN_PORT}")
        while (true) {
            try {
                val client = server.accept()
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
                SystemLogger.warning("KeyAdmin: accept error", e)
            }
        }
    }

    private fun handle(client: Socket) {
        client.use {
            val reader = BufferedReader(InputStreamReader(client.getInputStream(), Charsets.UTF_8))
            val out = client.getOutputStream()

            val requestLine = reader.readLine() ?: return
            val t0 = System.currentTimeMillis()
            SystemLogger.info("KeyAdmin: → ${requestLine.take(140)}")
            val parts = requestLine.split(" ")
            if (parts.size < 2) {
                respond(out, 400, JSONObject().put("ok", false).put("error", "bad request"))
                return
            }
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
                if (hName.equals("X-Teesim-Token", true)) headerToken = hVal
                else if (hName.equals("Content-Length", true)) contentLength = hVal.toIntOrNull() ?: 0
            }

            if (method == "OPTIONS") { // CORS preflight
                respond(out, 204, null)
                return
            }
            // The log download is opened by a browser navigation, which cannot set the
            // X-Teesim-Token header, so this one route authenticates with a ?token= query
            // parameter (validated against the same in-memory token) and streams plain text
            // named by a Content-Disposition header instead of the JSON envelope. Handled here,
            // ahead of the header-token check that every other route still requires.
            if (method == "GET" && rawPath.substringBefore('?') == "/logs/download") {
                val dlQuery = parseQuery(rawPath.substringAfter('?', ""))
                if (dlQuery["token"] != token) {
                    respond(out, 403, JSONObject().put("ok", false).put("error", "invalid token"))
                    return
                }
                downloadLogs(out, dlQuery)
                return
            }
            if (headerToken == null || headerToken != token) {
                respond(out, 403, JSONObject().put("ok", false).put("error", "invalid token"))
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
                        method == "GET" && path == "/keys/db" -> keysDb()
                        method == "POST" && path == "/keys/db/delete" -> deleteDbKeys(query)
                        method == "GET" && path == "/keys/inspect" ->
                            inspect(query["alias"] ?: error("alias required"))
                        method == "POST" && path == "/keys/delete" ->
                            delete(query["alias"] ?: error("alias required"))
                        method == "GET" && path == "/logs" -> logs(query)
                        method == "GET" && path == "/keybox/inspect" ->
                            KeyboxInspector.inspect(query["name"] ?: error("name required"))
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
    private fun keysDb(): JSONObject {
        val targets = targetUidToPackage()
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

    /** uid -> package for every installed app named across the live config's profiles. */
    private fun targetUidToPackage(): Map<Int, String> {
        val cfg =
            try {
                ConfigStore.load()
            } catch (e: Exception) {
                SystemLogger.warning("KeyAdmin: config load failed for /keys/db", e)
                return emptyMap()
            }
        val map = HashMap<Int, String>()
        for (p in cfg.profiles) for (pkg in p.apps) {
            val uid = Packages.uidForPackage(pkg)
            if (uid >= 0) map[uid] = pkg
        }
        return map
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
     * Streams the same recent log buffer as [logs] but as a plain-text attachment, so a browser
     * navigation names and saves the file from the Content-Disposition header (the WebView's
     * download handler ignores an <a download> attribute). Honors the same optional `after`/`max`
     * params as [logs]; with neither present it dumps the full recent buffer.
     */
    private fun downloadLogs(out: OutputStream, query: Map<String, String>) {
        val after = query["after"]?.toLongOrNull() ?: 0L
        val max = (query["max"]?.toIntOrNull() ?: 2000).coerceIn(1, 2000)
        val (lines, _) = LogTail.snapshot(after, max)
        // Each Line.text is already the full logcat line the Logs tab renders, so one line per
        // entry joined by newlines reproduces exactly what the on-screen Save produced.
        val body = lines.joinToString("\n") { it.text }
        val payload = (if (body.isEmpty()) body else body + "\n").toByteArray(Charsets.UTF_8)
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
