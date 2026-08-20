package org.matrix.teesim

import java.io.File

/**
 * The daemon's view onto the device log, for the WebUI's Logs panel. It no longer spawns a `logcat`
 * child: an in-process native reader ([nativeRun], in libteesim_logcat.so) reads logd directly through
 * liblog's reader API, filters in C to the lines we keep — every `TEESimulator` line (the daemon, the
 * TA and both native interceptors log under that tag), `AndroidRuntime` and fatal-level lines
 * (Java/native crash reports), and, once the interceptor is injected, every line from the target
 * keystore process ([targetPid]) — and serves
 * them two ways: a bounded ring the WebUI polls incrementally ([snapshot]), and rotating files under
 * [Const.logDir] so a crash's context survives a restart.
 *
 * The old `logcat`-subprocess reader pulled the WHOLE device stream through a pipe and regex-filtered
 * it in the JVM, so any flood (e.g. the KeyAdmin accept loop in #265) was carried at full volume into
 * the daemon and amplified by the very reader meant to observe it. The native reader filters at the
 * source and captures nothing under its own identity, so there is no feedback path to spin on.
 */
object LogTail {

    // Field separator the native side packs each polled line with: "seq<SEP>level<SEP>tag<SEP>text".
    // Neither a tag nor a log message contains U+0001, so the four-way split is unambiguous.
    private const val SEP = '\u0001'

    data class Line(val seq: Long, val level: Char, val tag: String, val text: String)

    @Volatile private var loaded = false

    /** The injected keystore/keystore2 pid, set by [Injector]; -1 when none is live. Forwarded to the
     *  native reader so its lines are kept even though they carry neither our tag nor a fatal level. */
    @Volatile
    var targetPid: Int = -1
        set(value) {
            field = value
            if (loaded) runCatching { nativeSetTargetPid(value) }
        }

    private external fun nativeRun(dir: String)

    private external fun nativeSetTargetPid(pid: Int)

    private external fun nativeMaxSeq(): Long

    private external fun nativePoll(after: Long, max: Int): Array<String>

    /**
     * Load libteesim_logcat.so from [nativeLib] and start the reader on its own daemon thread. Called
     * once, from [App], with the module's per-ABI library path. If the library is missing or fails to
     * load the Logs panel simply stays empty; the daemon is otherwise unaffected.
     */
    fun start(nativeLib: File) {
        if (loaded) return
        try {
            System.load(nativeLib.absolutePath)
            loaded = true
        } catch (e: Throwable) {
            SystemLogger.error("LogTail: cannot load ${nativeLib.absolutePath}; Logs panel disabled", e)
            return
        }
        // The reader thread needs a place to write before it opens its files.
        runCatching { Const.logDir.mkdirs() }
        // Push the current target pid across in case the Injector set it before the library loaded.
        runCatching { nativeSetTargetPid(targetPid) }
        // The log reader is a debugging aid; it must NEVER take the daemon down. nativeRun can still
        // throw at call time even after a successful load (e.g. an UnsatisfiedLinkError if a JNI name
        // was renamed) — an uncaught throwable on this thread would kill the whole process, so it is
        // contained here and merely disables the Logs panel.
        Thread({
            try {
                nativeRun(Const.logDir.absolutePath)
            } catch (e: Throwable) {
                SystemLogger.error("LogTail: native log reader thread died; Logs panel disabled", e)
            }
        }, "teesim-logtail").apply {
            isDaemon = true
            start()
        }
        SystemLogger.info("LogTail: native log reader started (dir=${Const.logDir.absolutePath})")
    }

    /** Lines with seq greater than [after], up to [max], plus the cursor to poll with next. Empty (and
     *  the cursor unchanged) until the native reader is loaded. */
    fun snapshot(after: Long, max: Int): Pair<List<Line>, Long> {
        if (!loaded) return emptyList<Line>() to after
        val packed =
            try {
                nativePoll(after, max)
            } catch (e: Throwable) {
                SystemLogger.warning("LogTail: nativePoll failed", e)
                return emptyList<Line>() to after
            }
        val out = ArrayList<Line>(packed.size)
        for (s in packed) {
            // A four-way split keeps a multi-line message (a stack trace) whole in the last field.
            val parts = s.split(SEP, limit = 4)
            if (parts.size < 4) continue
            val seq = parts[0].toLongOrNull() ?: continue
            val level = parts[1].firstOrNull() ?: 'I'
            out.add(Line(seq, level, parts[2], parts[3]))
        }
        val next =
            if (out.isNotEmpty()) out.last().seq
            else maxOf(after, runCatching { nativeMaxSeq() }.getOrDefault(after))
        return out to next
    }
}
