package org.matrix.TEESimulator

import android.app.ActivityThread
import android.app.Application
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.Looper
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.AbstractKeystoreInterceptor
import org.matrix.TEESimulator.interception.keystore.Keystore2Interceptor
import org.matrix.TEESimulator.interception.keystore.KeystoreInterceptor
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.AndroidDeviceUtils
import kotlin.system.exitProcess

/**
 * Main application object for TEESimulator. This object manages the application's lifecycle,
 * including initialization of interceptors and maintaining the service's primary execution loop.
 */
object App {
    // The delay in milliseconds before retrying to initialize the interceptor.
    private const val RETRY_DELAY_MS = 1000L
    // The sleep duration in milliseconds for the main service loop to keep the process alive.
    private const val SERVICE_SLEEP_MS = 1000000L

    /**
     * The main entry point of the TEESimulator application.
     *
     * @param args Command line arguments (not used).
     */
    @JvmStatic
    fun main(args: Array<String>) {
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            SystemLogger.error("Uncaught exception on thread '${thread.name}'. Exiting for restart.", throwable)
            exitProcess(0)
        }

        SystemLogger.info("Welcome to TEESimulator!")

        try {
            // Initialize the Android framework environment
            prepareEnvironment()
            // Initialize and start the appropriate keystore interceptors.
            initializeInterceptors()

            // Load the package configuration.
            ConfigurationManager.initialize()
            // Set up the device's boot key and hash, which are crucial for attestation.
            AndroidDeviceUtils.setupBootKeyAndHash()

            // Android ships with a stripped-down Bouncy Castle provider under the name "BC".
            // We must remove the system provider first to ensure the full Bouncy Castle library
            // (packaged with the app) is used.
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.addProvider(BouncyCastleProvider())

            // This starts the message queue processing. It blocks here indefinitely
            // processing messages until Looper.myLooper().quit() is called.
            Looper.loop()
        } catch (e: Exception) {
            SystemLogger.error("A fatal error occurred in the main application thread.", e)
            throw e
        }
    }

    /** Initializes the necessary Android framework internals to satisfy KeyStore requirements. */
    private fun prepareEnvironment() {
        // 1. Prepare Main Looper
        if (Looper.getMainLooper() == null) {
            @Suppress("deprecation") Looper.prepareMainLooper()
        }

        // 2. Initialize ActivityThread for the current process
        val activityThread = ActivityThread.systemMain()

        // 3. Get the system context
        val systemContext = activityThread.getSystemContext()

        // 4. Create a dummy Application object and attach the context
        val app = Application()
        val attachMethod =
            ContextWrapper::class.java.getDeclaredMethod("attachBaseContext", Context::class.java)
        attachMethod.isAccessible = true
        attachMethod.invoke(app, systemContext)

        // 5. Inject this application object into ActivityThread's mInitialApplication field.
        // This is what KeyStore.getApplicationContext() looks for.
        val mInitialApplicationField =
            ActivityThread::class.java.getDeclaredField("mInitialApplication")
        mInitialApplicationField.isAccessible = true
        mInitialApplicationField.set(activityThread, app)
    }

    /**
     * Selects and initializes the correct keystore interceptor based on the Android SDK version. It
     * retries initialization until it succeeds.
     */
    private fun initializeInterceptors() {
        val interceptor = selectKeystoreInterceptor()

        // Continuously try to run the interceptor until it's successfully initialized.
        while (!interceptor.tryRunKeystoreInterceptor()) {
            SystemLogger.debug("Retrying interceptor initialization...")
            Thread.sleep(RETRY_DELAY_MS)
        }

        SystemLogger.info("Interceptors initialized successfully.")
    }

    /**
     * Determines which keystore interceptor to use based on the device's Android version.
     *
     * @return The appropriate keystore interceptor instance.
     */
    private fun selectKeystoreInterceptor(): AbstractKeystoreInterceptor =
        when {
            // For Android Q (10) and R (11), use the original KeystoreInterceptor.
            Build.VERSION.SDK_INT in Build.VERSION_CODES.Q..Build.VERSION_CODES.R -> {
                SystemLogger.info(
                    "Using KeystoreInterceptor for Android Q/R (SDK ${Build.VERSION.SDK_INT})"
                )
                android.security.keystore.AndroidKeyStoreProvider.install()
                KeystoreInterceptor
            }
            // For Android S (12) and newer, use the Keystore2Interceptor.
            else -> {
                SystemLogger.info(
                    "Using Keystore2Interceptor for Android S and later (SDK ${Build.VERSION.SDK_INT})"
                )
                android.security.keystore2.AndroidKeyStoreProvider.install()
                Keystore2Interceptor
            }
        }
}
