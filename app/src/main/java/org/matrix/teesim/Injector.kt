package org.matrix.teesim

import android.os.Build
import java.io.File

/**
 * Finds the keystore daemon and drives the packaged `inject` binary to load the right interceptor
 * into it: `inject <pid> <lib.so> entry`. On Android 12+ the target is keystore2 with
 * libteesim_keymint.so; on 10/11 it is keystore with libteesim_keystore.so. Re-injects whenever the
 * daemon restarts (new pid).
 */
class Injector(private val moduleDir: File) {

    private val api = Build.VERSION.SDK_INT
    private val procName = if (api >= 31) "keystore2" else "keystore"
    private val libName = if (api >= 31) "libteesim_keymint.so" else "libteesim_keystore.so"

    private val abi: String =
        Build.SUPPORTED_ABIS?.firstOrNull() ?: DeviceProps.prop("ro.product.cpu.abi", "arm64-v8a")

    private val injectBin = File(moduleDir, "$abi/inject")
    private val libFile = File(moduleDir, "$abi/$libName")

    @Volatile private var running = false
    @Volatile private var lastPid = -1

    fun start() {
        if (running) return
        running = true
        if (!injectBin.exists() || !libFile.exists()) {
            SystemLogger.error(
                "injector: missing artifacts (inject=${injectBin.exists()} lib=${libFile.exists()}) " +
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
        SystemLogger.info("injector: watching $procName (abi=$abi lib=$libName)")
        var failures = 0
        while (running) {
            val pid = findPid(procName)
            // Tell the log tail which process to capture, so the Logs panel shows the
            // target keystore's own output — even before we manage to inject it.
            LogTail.targetPid = if (pid > 0) pid else -1
            if (pid > 0 && pid != lastPid && serviceReady()) {
                if (inject(pid)) {
                    lastPid = pid
                    failures = 0
                    SystemLogger.info("injector: injected into $procName pid=$pid")
                    confirmAsync(pid)
                } else {
                    failures++
                    SystemLogger.warning("injector: injection into pid=$pid failed; will retry")
                }
            } else if (pid <= 0) {
                lastPid = -1 // process gone; force re-inject when it returns
            }
            // Back off when injection keeps failing so we don't hammer a wedged keystore.
            sleep(if (failures > 3) 10000 else 2000)
        }
    }

    /** keystore forks before it registers its binder; wait for the service so we don't
     * inject into a half-initialised process. */
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

    /** The control-channel hello is the real proof the lib loaded and bound @teesim. Warn
     * (don't re-inject — that risks double-hooking) if it never arrives. */
    private fun confirmAsync(pid: Int) {
        Thread({
                for (i in 0 until 24) { // ~12s
                    if (Control.libApi != 0) return@Thread
                    sleep(500)
                }
                SystemLogger.warning(
                    "injector: injected pid=$pid but the lib never checked in over @teesim " +
                        "(SELinux on the abstract socket? look for 'avc: denied' in logcat)"
                )
            }, "teesim-inject-confirm")
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
            if (code != 0) SystemLogger.warning("injector: inject exit=$code output=$output")
            code == 0
        } catch (e: Exception) {
            SystemLogger.error("injector: failed to run inject binary", e)
            false
        }
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
