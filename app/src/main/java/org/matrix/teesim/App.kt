package org.matrix.teesim

import android.app.ActivityThread
import android.app.Application
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.Looper
import android.os.SystemClock
import java.io.File
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.JSONObject

/**
 * Privileged control daemon, launched via app_process. Bootstraps just enough of the Android
 * framework for AndroidKeyStore + PackageManager to work in this bare process (following the proven
 * main-branch sequence), harvests real attestation parameters, injects the native interceptor, and
 * pushes resolved config over @teesim.
 *
 * Launch (from the module's service.sh): app_process -Djava.class.path=$MODDIR/classes.dex $MODDIR
 * \ --nice-name=teesim org.matrix.teesim.App $MODDIR The trailing $MODDIR tells the Injector where
 * the inject binary + libraries live.
 */
object App {

    @Volatile private lateinit var appContext: Context
    // The frozen captured harvest (raw device state + computed default overrides). Never re-merged.
    @Volatile private lateinit var capturedBase: Harvester.Record
    // capturedBase with the user's overrides.json layered on — what we present and push. Recomputed on
    // every resolveAndPush, so an edit to overrides.json (which trips the DATA_DIR watcher) takes effect.
    @Volatile private lateinit var harvest: Harvester.Record
    @Volatile private var lastGoodConfig: ConfigStore.Config? = null
    // Cleared after the first committed push, so the startup-only attest-key purge runs exactly once.
    private val firstCommit = java.util.concurrent.atomic.AtomicBoolean(true)

    // How often the usage poll asks the lib for its per-uid key-request tallies.
    private const val USAGE_POLL_MS = 15_000L
    // Serializes the WHOLE fetch→delta→apply cycle of [pollUsageOnce]. Two callers race — the 15s poll
    // thread and KeyAdmin's /packages handler (its own thread) — and although Control.fetchUsage is
    // itself serialized, applying two snapshots out of order would drive a stale (smaller) count into
    // UsageStore's "count shrank ⇒ lib restarted" branch and fold a whole cumulative as a phantom delta.
    // A DEDICATED lock (never the App monitor, which resolveAndPush holds) keeps polls single-file
    // without blocking the config path across the multi-second fetch.
    private val usagePollLock = Any()

    // The delete-helper child body (see main): keystore2 only lets a key's OWNER delete it, and only the
    // owner's delete evicts keystore2's in-memory cache (a direct database delete does not). binder tells
    // keystore2 the sender's EFFECTIVE uid, so we seteuid to the owner and then delete — our real uid
    // stays root, and this is a throwaway process anyway. Exit code: 0 deleted, 1 keystore2 refused,
    // 2 could-not-seteuid (so the parent falls back to a direct database delete + keystore2 restart).
    @Suppress("DEPRECATION") // Os.seteuid is deprecated but is the only way to set the binder-reported euid
    private fun runDeleteHelper(uid: Int, keyId: Long): Int {
        if (uid < 0) return 2
        try {
            android.system.Os.seteuid(uid)
        } catch (e: Throwable) {
            SystemLogger.warning("delete-helper: seteuid($uid) failed: ${e.javaClass.simpleName}: ${e.message}")
            return 2
        }
        return try {
            if (Keystore2Service.deleteKeyById(keyId)) 0 else 1
        } catch (e: Throwable) {
            SystemLogger.warning("delete-helper: deleteKeyById($keyId) as euid=$uid failed", e)
            1
        }
    }

    @JvmStatic
    fun main(args: Array<String>) {
        // Delete-helper mode (a child the daemon spawns to delete one key as its owning app — see
        // runDeleteHelper). Runs before any daemon setup and exits with the outcome as its code.
        if (args.size == 3 && args[0] == "del") {
            kotlin.system.exitProcess(runDeleteHelper(args[1].toIntOrNull() ?: -1, args[2].toLongOrNull() ?: 0L))
        }
        SystemLogger.info("TEESimulator control daemon starting")
        try {
            waitForSystemReady()
            appContext = prepareEnvironment()

            // AndroidKeyStore provider for this process (harvest needs it).
            if (Build.VERSION.SDK_INT in Build.VERSION_CODES.Q..Build.VERSION_CODES.R) {
                android.security.keystore.AndroidKeyStoreProvider.install()
            } else {
                android.security.keystore2.AndroidKeyStoreProvider.install()
            }

            // Swap Android's stripped "BC" for the bundled full BouncyCastle (ASN.1 parsing).
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.addProvider(BouncyCastleProvider())

            Packages.init(appContext)

            // Real-key harvest (frozen verifiedBoot*), persisted to harvested.json. Then layer the user's
            // overrides.json over it for the record we actually present.
            capturedBase = Harvester.run(appContext)
            harvest = Harvester.applyUserOverrides(capturedBase, OverrideStore.load())

            // Key-management endpoint for the WebUI.
            KeyAdmin.start(harvest)

            // Pull Google's attestation revocation list in the background so the keybox inspector's
            // revoked/Google-signed verdicts are ready before the first inspect.
            RevocationList.warm()

            // Inject the interceptor and keep it injected across keystore restarts.
            Injector(resolveModuleDir(args)).start()

            // Control channel + initial push, then watch config and packages. After each committed
            // push the lib acks; that is when pre-existing target keys are re-attested to the keybox.
            Control.onCommitted = {
            lastGoodConfig?.let { cfg ->
                // On the first committed push (daemon start) clear each target's stale attestation key
                // so it is regenerated through the TA — an attest key must be ours to patch the leaves
                // it later signs. If that purge restarts keystore2, skip re-attestation this round: the
                // restart re-injects and re-pushes, and re-attestation runs then against a live keystore.
                val restarting = firstCommit.getAndSet(false) && ReAttest.purgeTargetAttestKeys(cfg)
                if (!restarting) ReAttest.run(cfg)
            }
        }
            Control.start()
            // Freeze the auto-include baseline (known_packages.json) at a known moment, before the first
            // resolve reads it — so "future installs only" is measured from daemon-start, not lazily.
            Scope.baselineKnownPackages()
            resolveAndPush()
            ConfigStore.watch { resolveAndPush() }
            // The third and last re-resolve trigger: the WebUI's pull-to-refresh on the Profiles
            // screen. Discovery of newly installed apps is LAZY by design — there is no package
            // observer, because a broadcast receiver registered from this process is silently
            // dropped by AMS (no ProcessRecord for a bare app_process; it throws on API 32/33 and
            // no-ops from 34 on). So the set of installed apps is only ever re-read here, on a
            // config change, and at daemon start.
            KeyAdmin.onRescan = { resolveAndPush() }
            startUsagePoll()

            SystemLogger.info("Daemon initialised; entering main loop")
            Looper.loop()
        } catch (e: Throwable) {
            SystemLogger.error("Fatal error in daemon main", e)
            throw e
        }
    }

    /**
     * The first app_process at boot can start before system_server, and then
     * ActivityThread.systemMain()/getSystemContext() NPE deep in the framework —
     * only the service.sh respawn recovers. main fixed this (#99) by waiting for a
     * core system service first. "package" is one of the last services system_server
     * registers, so once it answers the framework is fully up.
     */
    private fun waitForSystemReady() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                android.os.ServiceManager.waitForService("package")
                return
            }
        } catch (_: Throwable) {}
        for (i in 0 until 140) { // ~70s total (140 × 500ms)
            try {
                if (android.os.ServiceManager.getService("package") != null) return
            } catch (_: Throwable) {}
            try {
                Thread.sleep(500)
            } catch (_: InterruptedException) {
                return
            }
        }
        SystemLogger.warning("system_server not ready after 70s; bootstrapping anyway")
    }

    /** Minimal ActivityThread bootstrap so KeyStore.getApplicationContext() works. */
    private fun prepareEnvironment(): Context {
        if (Looper.getMainLooper() == null) {
            @Suppress("DEPRECATION") Looper.prepareMainLooper()
        }
        val activityThread = ActivityThread.systemMain()
        // getSystemContext() can still NPE on the very first launch; the readiness
        // gate above usually makes the first attempt succeed, but retry to be safe.
        var systemContext: Any? = null // stub getSystemContext() returns ContextImpl, passed reflectively
        for (attempt in 0 until 5) {
            try {
                systemContext = activityThread.getSystemContext()
                if (systemContext != null) break
            } catch (e: Throwable) {
                SystemLogger.warning("getSystemContext attempt ${attempt + 1} failed: ${e.message}")
            }
            try {
                Thread.sleep(1000)
            } catch (_: InterruptedException) {}
        }
        val sysCtx =
            systemContext ?: throw IllegalStateException("system context unavailable after retries")

        val app = Application()
        val attach =
            ContextWrapper::class.java.getDeclaredMethod("attachBaseContext", Context::class.java)
        attach.isAccessible = true
        attach.invoke(app, sysCtx)

        val field = ActivityThread::class.java.getDeclaredField("mInitialApplication")
        field.isAccessible = true
        field.set(activityThread, app)

        neutralizeSqliteSettingsReads()
        return app
    }

    /**
     * Stop SQLiteDatabase from reading device settings on its first open in this process. Planting
     * mInitialApplication above (so KeyStore/PackageManager see a context) makes
     * ActivityThread.currentApplication() non-null, and SQLiteDatabase's constructor then reaches into
     * settings the way a normal app would. Our process is not an AMS-registered app, so on some ROMs
     * resolving a provider throws ("Unable to find app for caller"), and every openDatabase() — hence
     * every KeystoreDb read — fails, leaving the WebUI key list empty. We pre-seed the framework's
     * cached settings so those lookups never run. Two independent reads have to be defused:
     *
     * - OnePlus builds have SQLiteGlobal consult a package list (getPkgs/BenchAppList) to pick a sync
     *   mode. Seeding sDefaultSyncMode to NORMAL short-circuits that before it touches PackageManager.
     * - Stock SQLiteCompatibilityWalFlags.initIfNeeded() reads Settings.Global.getString() under only a
     *   try/finally. Marking the class initialised returns early before it touches settings; its
     *   defaults (no compat-WAL overrides) are exactly what our read-only snapshot reads want.
     *
     * Each step is best effort: a framework that lays the class out differently just keeps the old
     * behaviour.
     */
    private fun neutralizeSqliteSettingsReads() {
        // OnePlus compares the current package against a BenchAppList to decide the sync mode; seeding
        // sDefaultSyncMode keeps SQLiteGlobal from calling getPkgs() through PackageManager.
        try {
            val syncMode =
                Class.forName("android.database.sqlite.SQLiteGlobal")
                    .getDeclaredField("sDefaultSyncMode")
                    .apply { isAccessible = true }
            if (syncMode.get(null) == null) {
                syncMode.set(null, "NORMAL")
                SystemLogger.info("SQLiteGlobal.sDefaultSyncMode seeded NORMAL (skip getPkgs on DB open)")
            }
        } catch (e: Throwable) {
            SystemLogger.verbose("SQLiteGlobal sync-mode guard not applied: ${e.message}")
        }

        // Stock AOSP settings dependency: present since API 28, absent on some newer builds.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                val walFlags = Class.forName("android.database.sqlite.SQLiteCompatibilityWalFlags")
                // Mark initialised so initIfNeeded() returns before reading Settings.Global.
                walFlags.getDeclaredField("sInitialized").apply { isAccessible = true }.setBoolean(null, true)
                // Secondary recursion guard, in case a build reorders the initIfNeeded() short-circuit.
                walFlags
                    .getDeclaredField("sCallingGlobalSettings")
                    .apply { isAccessible = true }
                    .setBoolean(null, true)
                SystemLogger.info("SQLiteCompatibilityWalFlags neutralised (skip Settings.Global on DB open)")
            } catch (e: Throwable) {
                SystemLogger.warning("Could not neutralise SQLiteCompatibilityWalFlags", e)
            }
        }
    }

    /**
     * Re-read + validate config, resolve against the frozen harvest and the live device, and push.
     * On config validation failure the last-good config is kept.
     */
    @Synchronized
    private fun resolveAndPush(): Int {
        // Re-layer the user's overrides.json over the frozen capture — an override edit trips the same
        // DATA_DIR watcher that calls us, so this is where a changed override becomes live. Refresh the
        // record the WebUI reads, and reflect any boot key/hash override into ro.boot.vbmeta.*.
        harvest = Harvester.applyUserOverrides(capturedBase, OverrideStore.load())
        KeyAdmin.updateHarvest(harvest)
        applyBootProps(harvest)
        try {
            lastGoodConfig = ConfigStore.load()
        } catch (e: ConfigStore.ConfigException) {
            SystemLogger.error("config.json invalid; keeping last-good: ${e.message}")
        } catch (e: Exception) {
            SystemLogger.error("config.json read failed; keeping last-good", e)
        }
        val cfg =
            lastGoodConfig
                ?: run {
                    SystemLogger.warning("No valid config yet; nothing to push")
                    return -1
                }
        return try {
            val msg = Resolver.resolve(cfg, harvest)
            Control.push(msg.toString())
            countTargetUids(msg)
        } catch (e: Exception) {
            SystemLogger.error("Failed to resolve/push config", e)
            -1
        }
    }

    /**
     * How many distinct caller uids the freshly pushed config targets, read back off the wire message
     * rather than re-resolving — [Scope.resolve] enumerates every installed app when a profile
     * auto-includes, and doing that twice per rescan just to count would double the cost of the
     * WebUI's pull-to-refresh. Deduplicated across profiles, since the same uid never legally appears
     * in two of them but a count that silently double-reported would be a confusing thing to show.
     */
    private fun countTargetUids(msg: JSONObject): Int {
        val profiles = msg.optJSONArray("profiles") ?: return 0
        val all = HashSet<Int>()
        for (i in 0 until profiles.length()) {
            val uids = profiles.optJSONObject(i)?.optJSONArray("uids") ?: continue
            for (j in 0 until uids.length()) all.add(uids.getInt(j))
        }
        return all.size
    }

    /**
     * The background loop that keeps [UsageStore] current: every [USAGE_POLL_MS] it polls the lib for
     * its per-uid key-request tallies and folds the deltas in ([pollUsageOnce]). Runs off the control
     * reader thread (Control delivers the reply there), so it lives on its own daemon thread. A slow or
     * absent lib just means an empty poll; the loop keeps going.
     */
    private fun startUsagePoll() {
        Thread({ usagePollLoop() }, "teesim-usage-poll").apply {
            isDaemon = true
            start()
        }
        SystemLogger.info("Usage poll thread started (every ${USAGE_POLL_MS}ms)")
    }

    private fun usagePollLoop() {
        while (true) {
            try {
                Thread.sleep(USAGE_POLL_MS)
            } catch (_: InterruptedException) {
                return
            }
            try {
                pollUsageOnce()
            } catch (e: Throwable) {
                SystemLogger.warning("usage poll: iteration failed: ${e.message}")
            }
        }
    }

    /**
     * Ask the lib for its usage snapshot and fold it into [UsageStore]. For each reported uid: resolve a
     * representative package (PackageManager reverse map, or the lib's pkg hint as a fallback), convert
     * the CLOCK_BOOTTIME lastBootMs to a wall-clock epoch via the current boot/wall offset, and hand it
     * to [UsageStore.applyLibSample], which owns the per-uid cursor and the delta math under its own
     * lock. This method therefore holds NO lock — in particular it must never block the config path:
     * [Control.fetchUsage] can wait seconds for the lib, and an earlier version @Synchronized on the App
     * monitor (shared with [resolveAndPush]) stalled config pushes for that whole window.
     */
    fun pollUsageOnce() = synchronized(usagePollLock) {
        val apps = Control.fetchUsage() ?: return@synchronized
        val bootNowMs = SystemClock.elapsedRealtime()
        val wallNow = System.currentTimeMillis()
        var recorded = 0
        for (i in 0 until apps.length()) {
            val e = apps.optJSONObject(i) ?: continue
            val uid = e.optInt("uid", -1)
            if (uid < 0) continue
            val current = e.optLong("count", 0L)
            val lastBootMs = e.optLong("lastBootMs", 0L)
            val hint = e.optString("pkg", "")

            val pkg = Packages.packagesForUid(uid).firstOrNull()?.takeIf { it.isNotEmpty() }
                ?: hint.takeIf { it.isNotEmpty() }
                ?: continue // no resolvable package: leave the cursor untouched so the count isn't lost
            // Remembered under the app token, not the bare package: a work profile's copy of an app is
            // a different caller and deserves its own count, and the token is also what the Scope
            // picker and config.json spell it as.
            val token = Scope.entryToken(pkg, Packages.userIdOf(uid))
            // lastBootMs is on CLOCK_BOOTTIME; the same offset (wallNow - bootNowMs) maps it to wall time.
            val lastUsedEpoch = if (lastBootMs > 0) wallNow - (bootNowMs - lastBootMs) else wallNow
            UsageStore.applyLibSample(uid, token, current, lastUsedEpoch)
            recorded++
        }
        SystemLogger.info("usage poll: ${apps.length()} uid(s) reported, $recorded merged")
    }

    /**
     * Force the matching ro.boot.vbmeta.* property to the boot key/hash we actually PRESENT (the override
     * when one is active, else the real captured value), so anything reading those props directly sees
     * exactly what attestation reports. We compare against the LIVE property and overwrite it on any
     * mismatch — the value we attest wins unconditionally, whether the property was empty (some bootloaders
     * never populate ro.boot.vbmeta.digest — unlocked / verification-disabled / OEM AVB, #228), stale, or
     * changed by another module. A match is left untouched, so a steady state does no work.
     */
    private fun applyBootProps(h: Harvester.Record) {
        for ((prop, value) in Harvester.bootPropValues(h)) {
            val live = DeviceProps.prop(prop, "")
            if (live != value) {
                SysProp.set(prop, value)
                SystemLogger.info("boot prop: forced $prop to the attested value (was '${live.ifEmpty { "unset" }}')")
            }
        }
    }

    /** Where the inject binary + native libs live: args[0], else the dex dir, else default. */
    private fun resolveModuleDir(args: Array<String>): File {
        args.firstOrNull()?.let {
            val d = File(it)
            if (d.isDirectory) return d
        }
        System.getProperty("java.class.path")?.let { cp ->
            val first = cp.split(File.pathSeparatorChar).firstOrNull()
            if (first != null && (first.endsWith(".dex") || first.endsWith(".apk"))) {
                File(first).parentFile?.let {
                    return it
                }
            }
        }
        return File("/data/adb/modules/teesim")
    }
}
