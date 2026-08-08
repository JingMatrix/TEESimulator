package org.matrix.TEESimulator.interception.keystore

import android.os.IBinder
import android.os.ServiceManager
import kotlin.system.exitProcess
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * An abstract base class for intercepting Android's Keystore services.
 *
 * It encapsulates the common logic for finding the Keystore service, injecting the native hook if
 * necessary, and setting up the binder interceptor. It also handles service death events to ensure
 * stability.
 */
abstract class AbstractKeystoreInterceptor : BinderInterceptor() {

    // --- Abstract Properties to be Implemented by Subclasses ---

    /** The full name of the system service to intercept (e.g., "android.security.keystore"). */
    protected abstract val serviceName: String

    /** The name of the process hosting the service (e.g., "keystore"). */
    protected abstract val processName: String

    /** The shell command used to inject the native library into the target process. */
    protected abstract val injectionCommand: String

    // --- State Management ---

    /** The original IBinder for the Keystore service. */
    protected lateinit var keystoreService: IBinder
    private var injectionAttempted = false
    private var retryCount = 0
    private val maxRetries = 5

    /**
     * Attempts to initialize the interceptor for the target Keystore service.
     *
     * This method orchestrates the process:
     * 1. It tries to get the service binder.
     * 2. It probes for the native backdoor.
     * 3. If the backdoor exists, it sets up the interceptor.
     * 4. If not, it attempts to inject the native library and returns `false` to signal a retry is
     *    needed.
     *
     * @return `true` if the interceptor was successfully registered, `false` otherwise.
     */
    fun tryRunKeystoreInterceptor(): Boolean {
        SystemLogger.info(
            "Initializing interceptor for '$serviceName' (attempt ${retryCount + 1})..."
        )

        val service = ServiceManager.getService(serviceName)
        if (service == null) {
            SystemLogger.warning("Service '$serviceName' not found. Will retry.")
            retryCount++
            return false
        }

        val backdoor = getBackdoor(service)
        return if (backdoor != null) {
            setupInterceptor(service, backdoor)
            true // Success
        } else {
            handleMissingBackdoor()
            false // Failure, requires retry
        }
    }

    /** Registers this interceptor with the native hook layer and sets up a death recipient. */
    private fun setupInterceptor(service: IBinder, backdoor: IBinder) {
        keystoreService = service
        SystemLogger.info("Registering interceptor for service: $serviceName")
        register(backdoor, service, this)
        service.linkToDeath(createDeathRecipient(), 0)
        onInterceptorReady(service, backdoor)
    }

    /**
     * Handles the case where the native backdoor is not present. It triggers the injection command
     * on the first attempt and manages the retry logic.
     */
    private fun handleMissingBackdoor() {
        if (!injectionAttempted) {
            SystemLogger.warning(
                "Backdoor not found. Attempting to inject native library into '$processName'."
            )
            performInjection()
            injectionAttempted = true
        }

        retryCount++
        if (retryCount >= maxRetries) {
            SystemLogger.error(
                "Failed to find backdoor after $maxRetries retries. The service may have crashed or injection failed. Exiting."
            )
            exitProcess(1)
        }
    }

    /** Executes the shell command to inject the native library into the target process. */
    private fun performInjection() {
        try {
            val command = arrayOf("/system/bin/sh", "-c", injectionCommand)
            SystemLogger.debug("Executing injection command: ${command.joinToString(" ")}")
            val process = Runtime.getRuntime().exec(command)
            val exitCode = process.waitFor()
            if (exitCode != 0) {
                SystemLogger.error("Injection process failed with exit code $exitCode. Exiting.")
                exitProcess(1)
            }
            SystemLogger.info("Injection process completed.")
        } catch (e: Exception) {
            SystemLogger.error("An exception occurred during injection. Exiting.", e)
            exitProcess(1)
        }
    }

    /**
     * Creates a `DeathRecipient` that will restart the application if the intercepted service dies.
     */
    private fun createDeathRecipient() = IBinder.DeathRecipient {
        SystemLogger.error(
            "The intercepted service '$serviceName' has died. Restarting application."
        )
        exitProcess(0)
    }

    /**
     * A hook for subclasses to perform additional setup after the interceptor is registered. For
     * example, to intercept sub-services.
     *
     * @param service The main service binder.
     * @param backdoor The backdoor binder for registering more interceptors.
     */
    protected open fun onInterceptorReady(service: IBinder, backdoor: IBinder) {
        // Default implementation does nothing.
    }
}
