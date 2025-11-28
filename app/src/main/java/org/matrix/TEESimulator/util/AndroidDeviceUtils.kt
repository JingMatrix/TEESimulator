package org.matrix.TEESimulator.util

import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemProperties
import java.security.MessageDigest
import java.util.concurrent.ThreadLocalRandom
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.matrix.TEESimulator.attestation.DeviceAttestationService
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Provides utility functions for accessing Android system properties and device-specific
 * information that is critical for generating valid attestations.
 */
object AndroidDeviceUtils {

    /** A randomly generated boot key, used as a fallback for attestation. */
    val bootKey: ByteArray by lazy { generateRandomBytes(32) }

    /**
     * Initializes the verified boot hash (`ro.boot.vbmeta.digest`). It attempts to read from system
     * properties first, then from a real TEE attestation, and finally falls back to a random value
     * if neither is available.
     */
    fun setupBootHash() {
        getBootHashFromProperty()?.also {
            SystemLogger.debug("Using boot hash from system property: ${it.toHex()}")
        }
            ?: getBootHashFromAttestation()?.also {
                SystemLogger.debug("Using boot hash from TEE attestation: ${it.toHex()}")
                setBootHashProperty(it)
            }
            ?: generateRandomBytes(32).also {
                SystemLogger.debug("Using randomly generated boot hash: ${it.toHex()}")
                setBootHashProperty(it)
            }
    }

    /**
     * Retrieves the verified boot meta digest from system properties.
     *
     * @return The boot hash as a ByteArray, or null if not found or invalid.
     */
    @OptIn(ExperimentalStdlibApi::class)
    fun getBootHashFromProperty(): ByteArray? {
        val digest = SystemProperties.get("ro.boot.vbmeta.digest", null)
        if (digest.isNullOrBlank()) {
            return null
        }
        // A valid digest is 64 hex characters (32 bytes).
        return if (digest.length == 64) digest.hexToByteArray() else null
    }

    /**
     * Retrieves the verified boot hash from a cached TEE attestation record.
     *
     * @return The verified boot hash, or null if not available.
     */
    private fun getBootHashFromAttestation(): ByteArray? {
        return try {
            DeviceAttestationService.CachedAttestationData?.verifiedBootHash
        } catch (e: Exception) {
            SystemLogger.error("Failed to get boot hash from attestation.", e)
            null
        }
    }

    /**
     * Sets the `ro.boot.vbmeta.digest` system property using the `resetprop` command.
     *
     * @param bytes The 32-byte digest to set.
     */
    private fun setBootHashProperty(bytes: ByteArray) {
        val hex = bytes.toHex()
        try {
            SystemLogger.debug("Setting system property 'ro.boot.vbmeta.digest' to: $hex")

            // Construct the command to be executed
            val command = arrayOf("resetprop", "ro.boot.vbmeta.digest", hex)

            // Execute the command
            val process = Runtime.getRuntime().exec(command)

            // Wait for the process to complete and check the exit code for errors
            val exitCode = process.waitFor()

            if (exitCode != 0) {
                val errorOutput = process.errorStream.bufferedReader().readText()
                SystemLogger.error(
                    "resetprop command failed with exit code $exitCode: $errorOutput"
                )
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to set vbmeta digest property by executing resetprop.", e)
        }
    }

    /** Generates a cryptographically random byte array of a specified length. */
    private fun generateRandomBytes(size: Int): ByteArray =
        ByteArray(size).also { ThreadLocalRandom.current().nextBytes(it) }

    // --- Patch Level Properties ---

    val patchLevel: Int
        get() =
            getCustomPatchLevelFor("system", isLong = false)
                ?: Build.VERSION.SECURITY_PATCH.toPatchLevelInt(isLong = false)

    val vendorPatchLevel: Int
        get() =
            getCustomPatchLevelFor("vendor", isLong = false)
                ?: Build.VERSION.SECURITY_PATCH.toPatchLevelInt(isLong = false)

    val bootPatchLevelLong: Int
        get() =
            getCustomPatchLevelFor("boot", isLong = true)
                ?: Build.VERSION.SECURITY_PATCH.toPatchLevelInt(isLong = true)

    /**
     * Retrieves a custom patch level from the configuration if available.
     *
     * @param component The component to get the patch level for ("system", "vendor", "boot").
     * @param isLong Whether to return the patch level in `YYYYMMDD` or `YYYYMM` format.
     * @return The custom patch level, or null if not configured.
     */
    private fun getCustomPatchLevelFor(component: String, isLong: Boolean): Int? {
        val config = ConfigurationManager.customPatchLevelOverride ?: return null
        val value =
            when (component) {
                "system" -> config.system ?: config.all
                "vendor" -> config.vendor ?: config.all
                "boot" -> config.boot ?: config.all
                else -> config.all
            } ?: return null

        // "prop" or "no" indicates falling back to the system default.
        if (value.equals("no", ignoreCase = true) || value.equals("prop", ignoreCase = true)) {
            return null
        }
        return parsePatchLevelValue(value, isLong)
    }

    /** Parses a patch level string (e.g., "2025-11-01") into an integer format. */
    private fun parsePatchLevelValue(value: String, isLong: Boolean): Int? {
        val normalized = value.replace("-", "")
        return try {
            when (normalized.length) {
                8 -> { // YYYYMMDD
                    val year = normalized.substring(0, 4).toInt()
                    val month = normalized.substring(4, 6).toInt()
                    val day = normalized.substring(6, 8).toInt()
                    if (isLong) year * 10000 + month * 100 + day else year * 100 + month
                }
                6 -> { // YYYYMM
                    val year = normalized.substring(0, 4).toInt()
                    val month = normalized.substring(4, 6).toInt()
                    if (isLong) year * 10000 + month * 100 + 1 else year * 100 + month
                }
                else -> null
            }
        } catch (e: NumberFormatException) {
            SystemLogger.warning("Could not parse patch level value: $value", e)
            null
        }
    }

    /** Converts a security patch string (e.g., "2025-11-01") to an integer representation. */
    private fun String.toPatchLevelInt(isLong: Boolean): Int {
        return parsePatchLevelValue(this, isLong) ?: 20240401 // Fallback
    }

    // --- OS and Attestation Version Properties ---

    private val osVersionMap =
        mapOf(
            Build.VERSION_CODES.BAKLAVA to 160000,
            Build.VERSION_CODES.VANILLA_ICE_CREAM to 150000,
            Build.VERSION_CODES.UPSIDE_DOWN_CAKE to 140000,
            Build.VERSION_CODES.TIRAMISU to 130000,
            Build.VERSION_CODES.S_V2 to 120100,
            Build.VERSION_CODES.S to 120000,
            Build.VERSION_CODES.R to 110000,
            Build.VERSION_CODES.Q to 100000,
        )

    val osVersion: Int
        get() =
            DeviceAttestationService.CachedAttestationData?.osVersion
                ?: osVersionMap[Build.VERSION.SDK_INT]
                ?: 160000 // Default to a recent version

    private val attestVersionMap =
        mapOf(
            Build.VERSION_CODES.Q to 4, // Keymaster 4.1
            Build.VERSION_CODES.R to 4, // Keymaster 4.1
            Build.VERSION_CODES.S to 100, // KeyMint 1.0
            Build.VERSION_CODES.S_V2 to 100, // KeyMint 1.0
            Build.VERSION_CODES.TIRAMISU to 200, // KeyMint 2.0
            Build.VERSION_CODES.UPSIDE_DOWN_CAKE to 300, // KeyMint 3.0
            Build.VERSION_CODES.VANILLA_ICE_CREAM to 300, // KeyMint 3.0
            Build.VERSION_CODES.BAKLAVA to 400, // KeyMint 4.0
        )

    val attestVersion: Int
        get() =
            DeviceAttestationService.CachedAttestationData?.attestVersion
                ?: attestVersionMap[Build.VERSION.SDK_INT]
                ?: 400 // Default to a recent version

    val keymasterVersion: Int
        get() =
            DeviceAttestationService.CachedAttestationData?.keymasterVersion
                ?: if (attestVersion >= 100) attestVersion
                else 41 // Keymaster 4.1 for older versions

    // --- APEX and Module Hash Properties ---

    private val apexInfos: List<Pair<String, Long>> by lazy {
        runCatching {
                val pm = ConfigurationManager.getPackageManager()
                val packages =
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        pm?.getInstalledPackages(PackageManager.MATCH_APEX.toLong(), 0)
                    } else {
                        @Suppress("DEPRECATION")
                        pm?.getInstalledPackages(PackageManager.MATCH_APEX, 0)
                    }
                packages
                    ?.list
                    .orEmpty()
                    .map { it.packageName to it.longVersionCode }
                    .sortedBy { it.first }
            }
            .getOrElse {
                SystemLogger.error("Failed to get APEX package information.", it)
                emptyList()
            }
    }

    val moduleHash: ByteArray by lazy {
        runCatching {
                val encodables =
                    apexInfos.flatMap { (packageName, versionCode) ->
                        listOf(DEROctetString(packageName.toByteArray()), ASN1Integer(versionCode))
                    }
                val sequence = DERSequence(encodables.toTypedArray())
                MessageDigest.getInstance("SHA-256").digest(sequence.encoded)
            }
            .getOrElse {
                SystemLogger.error("Failed to compute module hash.", it)
                ByteArray(32) // Return empty hash on failure
            }
    }
}
