package org.matrix.teesim

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.InputStream
import java.io.OutputStream
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

    private val lock = Object()
    @Volatile private var latest: String? = null
    private var seq = 0L
    @Volatile private var running = false

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
            "ack" ->
                SystemLogger.info(
                    "control: ack epoch=${msg.optLong("epoch")} ok=${msg.optBoolean("ok")} " +
                        "applied=${msg.optInt("profilesApplied")} failed=${msg.optInt("profilesFailed")}"
                )
            "pong" -> SystemLogger.verbose("control: pong ${msg.optLong("epoch")}")
        }
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
