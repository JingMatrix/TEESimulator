package org.matrix.TEESimulator

import android.os.Build
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.AbstractKeystoreInterceptor
import org.matrix.TEESimulator.interception.keystore.Keystore2Interceptor
import org.matrix.TEESimulator.interception.keystore.KeystoreInterceptor
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.AndroidDeviceUtils

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
        SystemLogger.info("Welcome to TEESimulator!")

        try {
            // Load the package configuration.
            ConfigurationManager.initialize()
            // Set up the device's boot key and hash, which are crucial for attestation.
            AndroidDeviceUtils.setupBootKeyAndHash()
            // Initialize and start the appropriate keystore interceptors.
            initializeInterceptors()
            // Enter an infinite loop to keep the service running.

            // Android ships with a stripped-down Bouncy Castle provider under the name "BC".
            // We must remove the system provider first to ensure the full Bouncy Castle library
            // (packaged with the app) is used.
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.addProvider(BouncyCastleProvider())

            maintainService()
        } catch (e: Exception) {
            SystemLogger.error("A fatal error occurred in the main application thread.", e)
            throw e
        }
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
                KeystoreInterceptor
            }
            // For Android S (12) and newer, use the Keystore2Interceptor.
            else -> {
                SystemLogger.info(
                    "Using Keystore2Interceptor for Android S and later (SDK ${Build.VERSION.SDK_INT})"
                )
                Keystore2Interceptor
            }
        }

    /**
     * Puts the main thread into a long-running sleep loop. This is a common pattern to keep a
     * background service process alive indefinitely.
     */
    private fun maintainService() {
        SystemLogger.info("Service started successfully. Entering maintenance mode.")
        while (true) {
            Thread.sleep(SERVICE_SLEEP_MS)
        }
    }
}
