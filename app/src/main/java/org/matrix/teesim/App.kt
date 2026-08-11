package org.matrix.teesim

import android.app.ActivityThread
import android.app.Application
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.Looper
import java.io.File
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

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
    @Volatile private lateinit var harvest: Harvester.Record
    @Volatile private var lastGoodConfig: ConfigStore.Config? = null
    // Cleared after the first committed push, so the startup-only attest-key purge runs exactly once.
    private val firstCommit = java.util.concurrent.atomic.AtomicBoolean(true)

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

            // Real-key harvest (frozen verifiedBoot*), persisted to harvested.json.
            harvest = Harvester.run(appContext)

            // Key-management endpoint for the WebUI.
            KeyAdmin.start(harvest)

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
            resolveAndPush()
            ConfigStore.watch { resolveAndPush() }
            PackageWatch.start(appContext) { resolveAndPush() }

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
    private fun resolveAndPush() {
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
                    return
                }
        try {
            val msg = Resolver.resolve(cfg, harvest)
            Control.push(msg.toString())
        } catch (e: Exception) {
            SystemLogger.error("Failed to resolve/push config", e)
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
