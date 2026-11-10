package org.matrix.teesim

import android.os.Build
import java.io.File

/**
 * Finds the keystore daemon and drives the packaged `inject` binary to load the right interceptor
 * into it: `inject <pid> <lib.so> entry`. On Android 12+ the target is keystore2 with
 * libteesim_keymint.so; on 10/11 it is keystore with libteesim_keystore.so. Re-injects whenever the
 * daemon restarts (new pid).
 *
 * A keystore process can already be carrying an interceptor when this daemon starts — after a
 * daemon crash and respawn, after a hot install, or when late-load.sh arms a system that was armed
 * before. Injecting again would dlopen a second copy and chain the PLT hook onto our own, so each
 * pid is first classified: [Verdict.Adopt] when it carries THIS build (the record written at the
 * last injection still describes the live process), [Verdict.Restart] when it carries something
 * else, since a library is never unloaded or injected over and only a fresh process clears it, and
 * [Verdict.Inject] when it carries nothing of ours.
 */
class Injector(private val moduleDir: File) {

    private val api = Build.VERSION.SDK_INT
    private val procName = if (api >= 31) "keystore2" else "keystore"
    private val libName = if (api >= 31) "libteesim_keymint.so" else "libteesim_keystore.so"

    private val abi: String =
        Build.SUPPORTED_ABIS?.firstOrNull() ?: DeviceProps.prop("ro.product.cpu.abi", "arm64-v8a")

    private companion object {
        /** Keystore restarts this daemon may order to clear an interceptor it cannot drive. */
        const val MAX_RESTARTS = 2
    }

    private val injectBin = File(moduleDir, "$abi/inject")
    private val libFile = File(moduleDir, "$abi/$libName")

    @Volatile private var running = false
    @Volatile private var lastPid = -1
    // The pid whose interceptor we gave up on (see [standDown]): evaluated once, then left alone.
    @Volatile private var stoodDownPid = -1
    // The pid we last asked init to restart, and how many restarts this daemon has ordered. A
    // restart that does not take (same pid still there) must not become a loop, and neither must a
    // keystore that keeps coming back with something we cannot account for.
    // Written from the loop thread and from [adoptAsync]'s watcher, so both are volatile.
    @Volatile private var restartedPid = -1
    @Volatile private var restarts = 0

    /** What to do with a keystore process we have not injected yet. */
    private enum class Verdict {
        Inject,
        Adopt,
        Restart,
    }

    /**
     * What the last successful injection put into which process, so a LATER daemon can tell its own
     * build from an older one. Keyed on the live process (boot id + pid + start time, which no
     * other process can repeat within a boot) and on the interceptor file's inode, which changes
     * the moment the module directory is replaced — so a hot install's record never matches.
     */
    private data class Record(val boot: String, val pid: Int, val startTime: Long, val libIno: Long)

    private val recordFile = File(Const.DATA_DIR, "injected.json")

    fun start() {
        if (running) return
        running = true
        if (!injectBin.exists() || !libFile.exists()) {
            SystemLogger.error(
                "Injector: missing artifacts (inject=${injectBin.exists()} lib=${libFile.exists()}) " +
                    "under ${moduleDir.absolutePath}/$abi"
            )
        }
        injectBin.setExecutable(true, false)
        Thread({ loop() }, "teesim-injector").apply {
            isDaemon = true
            start()
        }
    }

    private fun loop() {
        SystemLogger.info("Injector: watching $procName (abi=$abi lib=$libName)")
        var failures = 0
        while (running) {
            // The full /proc walk in findPid touches every process's cmdline (~1000 reads on a
            // busy device); skip it while the pid we last injected is still alive, since it never
            // changes between keystore restarts. Fall back to the walk only once it's gone. The
            // fallback fires at most once per keystore restart (or per retry while injection keeps
            // failing), so log it; the common alive-pid path stays silent to keep the loop cheap.
            val pid =
                if (lastPid > 0 && isNamedProcess(lastPid, procName)) {
                    lastPid
                } else {
                    if (lastPid > 0) {
                        SystemLogger.debug(
                            "Injector: pid=$lastPid is no longer $procName; re-scanning /proc"
                        )
                    }
                    findPid(procName)
                }
            // Tell the log tail which process to capture, so the Logs panel shows the target
            // keystore's own output — even before we manage to inject it.
            LogTail.targetPid = if (pid > 0) pid else -1
            if (pid > 0 && pid != lastPid && pid != stoodDownPid && serviceReady()) {
                when (verdict(pid)) {
                    Verdict.Inject ->
                        if (inject(pid)) {
                            lastPid = pid
                            failures = 0
                            SystemLogger.info("Injector: injected into $procName pid=$pid")
                            writeRecord(pid)
                            confirmAsync(pid)
                        } else {
                            failures++
                            SystemLogger.warning(
                                "Injector: injection into pid=$pid failed; will retry"
                            )
                        }
                    Verdict.Adopt -> {
                        lastPid = pid
                        failures = 0
                        SystemLogger.info(
                            "Injector: $procName pid=$pid already carries this build's interceptor; " +
                                "adopting it instead of injecting a second copy"
                        )
                        adoptAsync(pid)
                    }
                    Verdict.Restart -> {
                        SystemLogger.warning(
                            "Injector: $procName pid=$pid carries an interceptor this daemon did not " +
                                "put there (a previous build, or one left by a crashed daemon); it can " +
                                "only be replaced by a fresh process"
                        )
                        restartTarget(pid)
                    }
                }
            } else if (pid <= 0) {
                lastPid = -1 // process gone; force re-inject when it returns
            }
            // Back off when injection keeps failing so we don't hammer a wedged keystore.
            sleep(if (failures > 3) 10000 else 2000)
        }
    }

    // --- What a running keystore is already carrying --------------------------------------

    /**
     * Classifies a keystore process we have not injected on this daemon's watch. The record is
     * believed over the memory map: it identifies the live process exactly, and it is the only
     * thing that can tell OUR interceptor from an older build's, whose file name is the same.
     */
    private fun verdict(pid: Int): Verdict {
        val rec = readRecord()
        if (
            rec != null &&
                rec.boot == bootId() &&
                rec.pid == pid &&
                rec.startTime == startTime(pid) &&
                rec.libIno == libInode()
        ) {
            return Verdict.Adopt
        }
        // No record for this process. A mapped interceptor is then something we cannot drive —
        // unless the maps are unreadable, where the old behaviour (inject) is the safer guess: a
        // keystore that has nothing in it would otherwise never be armed at all.
        return when (hasInterceptor(pid)) {
            true -> Verdict.Restart
            false -> Verdict.Inject
            null -> {
                SystemLogger.warning(
                    "Injector: cannot read /proc/$pid/maps, so whether $procName already carries an " +
                        "interceptor is unknown; injecting"
                )
                Verdict.Inject
            }
        }
    }

    /**
     * Whether [pid] has an interceptor mapped, or null when the maps cannot be read. Two shapes
     * count: the module's own libteesim_*.so, mapped straight from /data/adb, and the injector's
     * staging fallback, which copies it to /data/local/tmp/lib<random>.so, dlopens that and unlinks
     * it — so the map keeps that path with a "(deleted)" suffix.
     */
    private fun hasInterceptor(pid: Int): Boolean? {
        return try {
            File("/proc/$pid/maps").useLines { lines ->
                lines.any { it.contains("libteesim_") || it.contains("/data/local/tmp/lib") }
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Ask init to restart the keystore service, so the next pid comes up clean and injectable. The
     * caller has already decided the current one cannot be used; the cap is what keeps a keystore
     * that keeps coming back wrong from being restarted forever.
     */
    private fun restartTarget(pid: Int) {
        if (pid == restartedPid) {
            standDown(pid, "the restart did not take")
            return
        }
        if (restarts >= MAX_RESTARTS) {
            standDown(pid, "already restarted $procName $restarts time(s) on this daemon")
            return
        }
        restarts++
        restartedPid = pid
        try {
            val p =
                ProcessBuilder("setprop", "ctl.restart", procName).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            SystemLogger.info(
                "Injector: asked init to restart $procName (exit ${p.exitValue()}" +
                    "${if (out.isEmpty()) "" else ", $out"}); the new process will be injected"
            )
        } catch (e: Throwable) {
            standDown(pid, "could not run setprop ctl.restart $procName: ${e.message}")
        }
    }

    /**
     * Gives up on one pid, loudly: the keystore daemon keeps whatever it is carrying, which for a
     * previous build means the old interceptor stays live until something restarts the service.
     * Said out loud because nothing else tells the two builds apart, and a reader otherwise cannot
     * know which interceptor the apps on screen are talking to.
     */
    private fun standDown(pid: Int, why: String) {
        stoodDownPid = pid
        lastPid = pid // stop the /proc walk; this pid is settled either way
        SystemLogger.error(
            "Injector: leaving $procName pid=$pid as it is ($why). Its current interceptor keeps " +
                "serving; a reboot, or killing $procName, starts a clean one"
        )
    }

    /**
     * An adopted interceptor was serving when it was recorded, but nothing proves it still is — the
     * daemon that recorded it may have died mid-handshake, or the control socket may now be denied.
     * Wait for the hello, and treat silence the same as a foreign interceptor: only a fresh process
     * can replace it.
     */
    private fun adoptAsync(pid: Int) {
        Thread(
                {
                    for (i in 0 until 40) { // ~20s
                        if (Control.libApi != 0) return@Thread
                        sleep(500)
                    }
                    // The keystore may have restarted for its own reasons while we waited, and
                    // the loop will have injected the new process already: nothing to answer for.
                    if (!isNamedProcess(pid, procName) || lastPid != pid) return@Thread
                    SystemLogger.warning(
                        "Injector: the interceptor adopted in pid=$pid never checked in over " +
                            "${Const.CONTROL_SOCKET_PATH}, so it is serving nothing; restarting $procName"
                    )
                    restartTarget(pid)
                },
                "teesim-inject-adopt",
            )
            .apply {
                isDaemon = true
                start()
            }
    }

    // --- The injection record -------------------------------------------------------------

    /** This boot's id, which makes a pid from a previous boot unmistakable. */
    private fun bootId(): String =
        try {
            File("/proc/sys/kernel/random/boot_id").readText().trim()
        } catch (e: Exception) {
            ""
        }

    /**
     * [pid]'s start time in clock ticks since boot (/proc/pid/stat field 22), which together with
     * the pid identifies one process within a boot. Read from after the last ')' so a comm holding
     * spaces or parentheses cannot shift the fields.
     */
    private fun startTime(pid: Int): Long {
        return try {
            val stat = File("/proc/$pid/stat").readText()
            val fields = stat.substringAfterLast(')').trim().split(' ')
            // field 22 overall is the 20th after state, which is index 19 here.
            fields[19].toLong()
        } catch (e: Exception) {
            -1L
        }
    }

    /** The interceptor file's inode, which a replaced module directory changes. */
    private fun libInode(): Long =
        try {
            android.system.Os.stat(libFile.absolutePath).st_ino
        } catch (e: Throwable) {
            -1L
        }

    private fun writeRecord(pid: Int) {
        try {
            val json =
                org.json
                    .JSONObject()
                    .put("boot", bootId())
                    .put("pid", pid)
                    .put("startTime", startTime(pid))
                    .put("libIno", libInode())
            recordFile.writeText(json.toString())
        } catch (e: Exception) {
            // Only costs a later daemon the adopt path, which then restarts keystore instead.
            SystemLogger.warning(
                "Injector: could not record the injection in ${recordFile.absolutePath}: ${e.message}"
            )
        }
    }

    private fun readRecord(): Record? {
        return try {
            val o = org.json.JSONObject(recordFile.readText())
            Record(
                o.optString("boot"),
                o.optInt("pid", -1),
                o.optLong("startTime", -1L),
                o.optLong("libIno", -1L),
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * keystore forks before it registers its binder; wait for the service so we don't inject into a
     * half-initialised process.
     */
    private fun serviceReady(): Boolean {
        val name =
            if (api >= 31) "android.system.keystore2.IKeystoreService/default"
            else "android.security.keystore"
        return try {
            android.os.ServiceManager.getService(name) != null
        } catch (e: Throwable) {
            true // can't check (stub / older API): don't block injection
        }
    }

    /**
     * The control-channel hello is the real proof the lib loaded and bound the control socket. Warn
     * (don't re-inject — that risks double-hooking) if it never arrives.
     */
    private fun confirmAsync(pid: Int) {
        Thread(
                {
                    for (i in 0 until 24) { // ~12s
                        if (Control.libApi != 0) return@Thread
                        sleep(500)
                    }
                    SystemLogger.warning(
                        "Injector: injected pid=$pid but the lib never checked in over ${Const.CONTROL_SOCKET_PATH} " +
                            "(SELinux on the control socket? look for 'avc: denied' in logcat)"
                    )
                },
                "teesim-inject-confirm",
            )
            .apply {
                isDaemon = true
                start()
            }
    }

    private fun inject(pid: Int): Boolean {
        return try {
            val proc =
                ProcessBuilder(
                        injectBin.absolutePath,
                        pid.toString(),
                        libFile.absolutePath,
                        "entry",
                    )
                    .redirectErrorStream(true)
                    .start()
            val output = proc.inputStream.bufferedReader().readText()
            val code = proc.waitFor()
            if (code != 0) SystemLogger.warning("Injector: inject exit=$code output=$output")
            code == 0
        } catch (e: Exception) {
            SystemLogger.error("Injector: failed to run inject binary", e)
            false
        }
    }

    /** True if /proc/[pid]/cmdline's basename still matches [name], else false. */
    private fun isNamedProcess(pid: Int, name: String): Boolean {
        val cmd =
            try {
                File("/proc/$pid/cmdline").readBytes()
            } catch (e: Exception) {
                return false
            }
        if (cmd.isEmpty()) return false
        val end = cmd.indexOf(0.toByte()).let { if (it < 0) cmd.size else it }
        return String(cmd, 0, end).substringAfterLast('/') == name
    }

    /** Return the pid whose /proc/<pid>/cmdline basename matches [name], else -1. */
    private fun findPid(name: String): Int {
        val proc = File("/proc")
        val entries =
            proc.listFiles { f -> f.isDirectory && f.name.all { it.isDigit() } } ?: return -1
        for (dir in entries) {
            val cmdlineFile = File(dir, "cmdline")
            val cmd =
                try {
                    cmdlineFile.readBytes()
                } catch (e: Exception) {
                    continue
                }
            if (cmd.isEmpty()) continue
            val end = cmd.indexOf(0.toByte()).let { if (it < 0) cmd.size else it }
            val arg0 = String(cmd, 0, end)
            val base = arg0.substringAfterLast('/')
            if (base == name) return dir.name.toIntOrNull() ?: continue
        }
        return -1
    }

    private fun sleep(ms: Long) {
        try {
            Thread.sleep(ms)
        } catch (ignored: InterruptedException) {}
    }
}
