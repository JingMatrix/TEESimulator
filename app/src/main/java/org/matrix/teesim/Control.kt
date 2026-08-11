package org.matrix.teesim

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.InputStream
import java.io.OutputStream
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONArray
import org.json.JSONObject

/**
 * Control-channel CLIENT. Connects the abstract unix socket `@teesim`, verifies the peer is
 * keystore (SO_PEERCRED uid == 1017) before sending the keybox bytes, then speaks the control.cpp
 * framing: [u32 BE length][UTF-8 JSON].
 *
 * Wire sequence: the lib sends its `hello` on accept; we send our `hello` then the latest `config`,
 * and read back `hello`/`ack`/`pong`. Only ever the newest config is sent (full replace).
 * Reconnects with backoff and re-pushes on every reconnect.
 */
object Control {

    private const val MAX_FRAME = 8 * 1024 * 1024

    private const val RESIGN_TIMEOUT_MS = 10_000L

    private const val USAGE_TIMEOUT_MS = 5_000L

    private val lock = Object()
    @Volatile private var latest: String? = null
    private var seq = 0L
    @Volatile private var running = false

    // The live connection's output stream, or null when disconnected — used to send resign requests
    // outside the writer loop (writeFrame is stream-synchronized, so concurrent sends are safe).
    @Volatile private var activeOut: OutputStream? = null
    // Responses to the one in-flight resign request. Buffered (size 1) so a reply that arrives before
    // the sender polls is not lost; the sender drains it before each request.
    private val resignReplies = LinkedBlockingQueue<JSONObject>(1)

    // The one in-flight usage-poll reply, same buffered(1) rationale as [resignReplies]. [usageLock]
    // serializes fetchUsage() so only a single getUsage request is ever outstanding on the wire.
    private val usageReplies = LinkedBlockingQueue<JSONObject>(1)
    private val usageLock = Object()

    // Invoked (on [commitExecutor]) after the lib acks a config commit, so the daemon can re-attest
    // pre-existing keys against the just-committed profile set. Coalesced by [commitPending].
    @Volatile var onCommitted: (() -> Unit)? = null
    private val commitExecutor = Executors.newSingleThreadExecutor { r -> Thread(r, "teesim-reattest").apply { isDaemon = true } }
    private val commitPending = AtomicBoolean(false)

    @Volatile
    var libHook: String? = null
        private set

    @Volatile
    var libApi: Int = 0
        private set

    fun start() {
        if (running) return
        running = true
        Thread({ supervise() }, "teesim-control").apply {
            isDaemon = true
            start()
        }
    }

    /** Queue the newest resolved config; the connection thread pushes it. */
    fun push(configJson: String) {
        synchronized(lock) {
            latest = configJson
            seq++
            lock.notifyAll()
        }
    }

    private class Conn(val socket: LocalSocket, val out: OutputStream) {
        @Volatile var alive = true
        var sentSeq = -1L
    }

    private fun supervise() {
        var backoff = 500L
        while (running) {
            var socket: LocalSocket? = null
            try {
                socket = LocalSocket()
                socket.connect(
                    LocalSocketAddress(Const.CONTROL_SOCKET, LocalSocketAddress.Namespace.ABSTRACT)
                )
                val peerUid =
                    try {
                        socket.peerCredentials.uid
                    } catch (e: Exception) {
                        -1
                    }
                if (peerUid != Const.AID_KEYSTORE) {
                    SystemLogger.error(
                        "control: peer uid $peerUid != keystore ${Const.AID_KEYSTORE}; refusing to send"
                    )
                    socket.close()
                    sleep(backoff)
                    backoff = (backoff * 2).coerceAtMost(10_000)
                    continue
                }
                SystemLogger.info(
                    "control: connected to @${Const.CONTROL_SOCKET} (peer uid=$peerUid)"
                )
                backoff = 500L

                val out = socket.outputStream
                val inp = socket.inputStream
                writeFrame(out, "{\"type\":\"hello\",\"role\":\"daemon\",\"protocol\":1}")
                activeOut = out

                val conn = Conn(socket, out)
                val writer =
                    Thread({ writerLoop(conn) }, "teesim-control-writer").apply {
                        isDaemon = true
                        start()
                    }
                try {
                    while (running) {
                        val frame = readFrame(inp) ?: break
                        handleFrame(frame)
                    }
                } finally {
                    conn.alive = false
                    activeOut = null
                    synchronized(lock) { lock.notifyAll() }
                    writer.interrupt()
                }
            } catch (e: Exception) {
                SystemLogger.warning("control: connection error: ${e.message}")
            } finally {
                try {
                    socket?.close()
                } catch (ignored: Exception) {}
            }
            if (running) {
                sleep(backoff)
                backoff = (backoff * 2).coerceAtMost(10_000)
            }
        }
    }

    private fun writerLoop(conn: Conn) {
        try {
            while (conn.alive && running) {
                var toSend: String? = null
                var doPing = false
                synchronized(lock) {
                    if (latest != null && conn.sentSeq != seq) {
                        toSend = latest
                        conn.sentSeq = seq
                    } else {
                        lock.wait(30_000)
                        if (!(conn.alive && running)) return
                        if (latest != null && conn.sentSeq != seq) {
                            toSend = latest
                            conn.sentSeq = seq
                        } else {
                            doPing = true
                        }
                    }
                }
                when {
                    toSend != null -> {
                        writeFrame(conn.out, toSend!!)
                        SystemLogger.info("control: pushed config (epoch=$seq)")
                    }
                    doPing -> writeFrame(conn.out, "{\"type\":\"ping\",\"epoch\":$seq}")
                }
            }
        } catch (e: Exception) {
            conn.alive = false
            try {
                conn.socket.close()
            } catch (ignored: Exception) {}
        }
    }

    private fun handleFrame(frame: String) {
        val msg =
            try {
                JSONObject(frame)
            } catch (e: Exception) {
                SystemLogger.warning("control: unparseable frame from lib")
                return
            }
        when (msg.optString("type")) {
            "hello" -> {
                libHook = if (msg.has("hook")) msg.optString("hook") else null
                libApi = msg.optInt("androidApi", 0)
                SystemLogger.info(
                    "control: lib hello hook=$libHook api=$libApi pid=${msg.optInt("keystorePid", 0)}"
                )
            }
            "ack" -> {
                SystemLogger.info(
                    "control: ack epoch=${msg.optLong("epoch")} ok=${msg.optBoolean("ok")} " +
                        "applied=${msg.optInt("profilesApplied")} failed=${msg.optInt("profilesFailed")}"
                )
                // The ack means the lib has committed the new profile set — the point at which
                // pre-existing keys can be re-attested against it. Coalesce bursts of pushes into one
                // run and never run it on this reader thread (resign responses arrive here).
                val cb = onCommitted
                if (cb != null && commitPending.compareAndSet(false, true)) {
                    commitExecutor.execute {
                        commitPending.set(false)
                        try {
                            cb()
                        } catch (e: Throwable) {
                            SystemLogger.warning("control: re-attest run failed: ${e.message}")
                        }
                    }
                }
            }
            "resigned" -> {
                resignReplies.clear()
                resignReplies.offer(msg)
            }
            "usage" -> {
                // The poll thread parks on usageReplies; hand the frame over and never do the (uid->pkg,
                // disk) merge here — this is the reader thread, and the merge can block on PackageManager.
                usageReplies.clear()
                usageReplies.offer(msg)
            }
            "pong" -> SystemLogger.verbose("control: pong ${msg.optLong("epoch")}")
        }
    }

    /**
     * Ask the lib to re-sign an existing key's attestation [leaf] under profile [profileId]'s keybox,
     * returning the patched chain (leaf first) or null if there is no live connection, the request
     * times out, or the lib reports failure. Called from [onCommitted] on [commitExecutor]; the reader
     * thread delivers the reply, so this must not run on that thread.
     */
    fun resign(profileId: String, leaf: ByteArray): List<ByteArray>? {
        val out =
            activeOut
                ?: run {
                    SystemLogger.warning("control: resign for '$profileId' skipped — no live connection")
                    return null
                }
        resignReplies.clear()
        val req =
            JSONObject()
                .put("type", "resign")
                .put("profile", profileId)
                .put("leafB64", Base64.getEncoder().encodeToString(leaf))
        SystemLogger.info("control: resign request (profile=$profileId, leaf=${leaf.size} bytes)")
        try {
            writeFrame(out, req.toString())
        } catch (e: Exception) {
            SystemLogger.warning("control: resign send failed: ${e.message}")
            return null
        }
        val reply =
            resignReplies.poll(RESIGN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                ?: run {
                    SystemLogger.warning("control: resign timed out (profile $profileId)")
                    return null
                }
        if (!reply.optBoolean("ok")) {
            SystemLogger.warning("control: resign rejected by lib (profile $profileId)")
            return null
        }
        val arr = reply.optJSONArray("chainB64") ?: return null
        val dec = Base64.getDecoder()
        return try {
            val chain = (0 until arr.length()).map { dec.decode(arr.getString(it)) }
            SystemLogger.info("control: resign returned a ${chain.size}-cert chain for '$profileId'")
            chain
        } catch (e: Exception) {
            SystemLogger.warning("control: resign reply undecodable: ${e.message}")
            null
        }
    }

    /**
     * Poll the lib for its per-uid key-request usage (spec C1), mirroring [resign]'s request/reply
     * shape: write `{"type":"getUsage"}`, wait for the matching `usage` frame, and hand back its `apps`
     * array (one entry per uid that has requested a key since the lib loaded), or null on no connection /
     * timeout / malformed reply. Serialized by [usageLock] so at most one request is outstanding.
     *
     * MUST be called off the reader thread ([App]'s poll thread) — [handleFrame] delivers the reply, so
     * blocking here on that same thread would deadlock. The reply is consumed as-is; the caller resolves
     * uid->package and folds deltas into [UsageStore].
     */
    fun fetchUsage(): JSONArray? =
        synchronized(usageLock) {
            val out =
                activeOut
                    ?: run {
                        SystemLogger.verbose("control: getUsage skipped — no live connection")
                        return null
                    }
            usageReplies.clear()
            try {
                writeFrame(out, "{\"type\":\"getUsage\"}")
            } catch (e: Exception) {
                SystemLogger.warning("control: getUsage send failed: ${e.message}")
                return null
            }
            val reply =
                usageReplies.poll(USAGE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                    ?: run {
                        SystemLogger.warning("control: getUsage timed out")
                        return null
                    }
            reply.optJSONArray("apps")
        }

    // --- framing: [u32 BE length][UTF-8 JSON] -----------------------------------

    private fun writeFrame(out: OutputStream, payload: String) {
        val bytes = payload.toByteArray(Charsets.UTF_8)
        require(bytes.size in 1..MAX_FRAME) { "frame length ${bytes.size} out of range" }
        val hdr =
            byteArrayOf(
                (bytes.size ushr 24).toByte(),
                (bytes.size ushr 16).toByte(),
                (bytes.size ushr 8).toByte(),
                bytes.size.toByte(),
            )
        synchronized(out) {
            out.write(hdr)
            out.write(bytes)
            out.flush()
        }
    }

    private fun readFrame(inp: InputStream): String? {
        val hdr = ByteArray(4)
        if (!readFully(inp, hdr)) return null
        val len =
            ((hdr[0].toInt() and 0xFF) shl 24) or
                ((hdr[1].toInt() and 0xFF) shl 16) or
                ((hdr[2].toInt() and 0xFF) shl 8) or
                (hdr[3].toInt() and 0xFF)
        if (len <= 0 || len > MAX_FRAME) return null
        val body = ByteArray(len)
        if (!readFully(inp, body)) return null
        return String(body, Charsets.UTF_8)
    }

    private fun readFully(inp: InputStream, buf: ByteArray): Boolean {
        var off = 0
        while (off < buf.size) {
            val r = inp.read(buf, off, buf.size - off)
            if (r <= 0) return false
            off += r
        }
        return true
    }

    private fun sleep(ms: Long) {
        try {
            Thread.sleep(ms)
        } catch (ignored: InterruptedException) {}
    }
}
