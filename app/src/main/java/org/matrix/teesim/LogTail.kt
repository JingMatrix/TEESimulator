package org.matrix.teesim

import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Tails logcat into a bounded ring buffer so the WebUI can poll recent lines cheaply (no logcat
 * spawn per request). It keeps three things: every `TEESimulator` line (the daemon, the TA, and both
 * native interceptors all log under that tag), every `avc` line (SELinux denials — the usual
 * injection blocker), and, once the interceptor is injected, every line from the target keystore
 * process, so the Logs panel shows what happens inside the process we hook rather than only our own
 * output. The WebUI filters this stream by tag, level, and substring.
 *
 * logcat cannot select by pid in its filterspec, so we capture broadly (`TEESimulator:V *:I`) and
 * keep only the matching lines here; [targetPid] is supplied by the [Injector].
 */
object LogTail {

    private const val CAP = 4000

    data class Line(val seq: Long, val level: Char, val tag: String, val text: String)

    /** The injected keystore/keystore2 pid, set by [Injector]; -1 when none is live. */
    @Volatile var targetPid: Int = -1

    private val lock = Any()
    private val buf = ArrayDeque<Line>(CAP)
    private var seq = 0L

    @Volatile private var started = false

    // threadtime: "MM-DD HH:MM:SS.mmm  PID  TID L TAG: message" — capture pid, level, tag.
    private val HEADER =
        Regex("^\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}\\s+(\\d+)\\s+\\d+\\s+([VDIWEF])\\s+(.*?):\\s")

    // Carried across a continuation line (no header) so a kept multi-line message — a
    // stack trace — keeps all of its lines. Touched only from the single pump thread.
    private var lastKept = false
    private var lastLevel = 'I'
    private var lastTag = ""

    fun start() {
        if (started) return
        started = true
        Thread({ pump() }, "teesim-logtail").apply {
            isDaemon = true
            start()
        }
    }

    private fun pump() {
        while (true) {
            try {
                // TEESimulator at verbose; everything else at info+ so the target
                // process's lines are emitted for add() to select.
                val p =
                    ProcessBuilder("logcat", "-v", "threadtime", "TEESimulator:V", "*:I")
                        .redirectErrorStream(true)
                        .start()
                BufferedReader(InputStreamReader(p.inputStream, Charsets.UTF_8)).useLines { lines ->
                    lines.forEach { add(it) }
                }
                p.waitFor()
            } catch (e: Exception) {
                SystemLogger.warning("LogTail: logcat pump failed; retrying", e)
            }
            // logcat exited (buffer reset, or it was killed) — pause briefly and reattach.
            try {
                Thread.sleep(1000)
            } catch (_: InterruptedException) {
                return
            }
        }
    }

    private fun add(raw: String) {
        val m = HEADER.find(raw)
        val keep: Boolean
        val level: Char
        val tag: String
        if (m != null) {
            val pid = m.groupValues[1].toIntOrNull() ?: -1
            level = m.groupValues[2].firstOrNull() ?: 'I'
            tag = m.groupValues[3].trim()
            val pidNow = targetPid
            keep = tag == "TEESimulator" || tag == "avc" || (pidNow > 0 && pid == pidNow)
            lastKept = keep
            lastLevel = level
            lastTag = tag
        } else {
            // Continuation line (stack trace, "beginning of main" separator): follow the
            // previous entry so a kept multi-line message stays whole.
            keep = lastKept
            level = lastLevel
            tag = lastTag
        }
        if (!keep) return
        synchronized(lock) {
            if (buf.size >= CAP) buf.removeFirst()
            buf.addLast(Line(++seq, level, tag, raw))
        }
    }

    /** Lines with seq greater than [after], up to [max], plus the cursor to poll with next. */
    fun snapshot(after: Long, max: Int): Pair<List<Line>, Long> {
        synchronized(lock) {
            val out = buf.asSequence().filter { it.seq > after }.take(max).toList()
            val next = if (out.isNotEmpty()) out.last().seq else maxOf(after, seq)
            return out to next
        }
    }
}
