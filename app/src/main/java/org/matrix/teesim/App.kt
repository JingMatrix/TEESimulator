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

    @JvmStatic
    fun main(args: Array<String>) {
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

            // Control channel + initial push, then watch config and packages.
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
        return app
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
