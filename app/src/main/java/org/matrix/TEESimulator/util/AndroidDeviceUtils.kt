package org.matrix.TEESimulator.util

import android.content.pm.PackageManager
import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.os.SystemProperties
import java.security.MessageDigest
import java.util.concurrent.ThreadLocalRandom
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.matrix.TEESimulator.attestation.DeviceAttestationService
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Provides utility functions for accessing Android system properties and device-specific
 * information that is critical for generating valid attestations.
 */
object AndroidDeviceUtils {

    /**
     * Internal constant to signify that a patch level should not be included in the attestation.
     */
    internal const val DO_NOT_REPORT = -1

    // --- Boot Key and Verified Boot Hash ---

    /**
     * Lazily initializes and retrieves the verified boot key digest. The value is sourced in the
     * following order:
     * 1. From the `ro.boot.vbmeta.public_key_digest` system property.
     * 2. From a cached TEE attestation record.
     * 3. As a randomly generated 32-byte value (fallback).
     */
    val bootKey: ByteArray by lazy {
        initializeBootProperty(
            propertyName = "ro.boot.vbmeta.public_key_digest",
            attestationValueProvider = {
                DeviceAttestationService.CachedAttestationData?.verifiedBootKey
            },
            expectedSize = 32,
        )
    }

    /**
     * Lazily initializes and retrieves the verified boot hash (vbmeta digest). The value is sourced
     * in the following order:
     * 1. From the `ro.boot.vbmeta.digest` system property.
     * 2. From a cached TEE attestation record.
     * 3. As a randomly generated 32-byte value (fallback).
     */
    val bootHash: ByteArray by lazy {
        initializeBootProperty(
            propertyName = "ro.boot.vbmeta.digest",
            attestationValueProvider = {
                DeviceAttestationService.CachedAttestationData?.verifiedBootHash
            },
            expectedSize = 32,
        )
    }

    /**
     * Public function to explicitly trigger the initialization of the boot key and hash. Accessing
     * these properties here ensures they are set up before they might be needed elsewhere.
     */
    fun setupBootKeyAndHash() {
        SystemLogger.debug("Triggering initialization of boot key and hash...")
        // Accessing the properties will trigger their `lazy` initialization logic.
        bootKey
        bootHash
        SystemLogger.debug("Boot key and hash initialization complete.")
    }

    /**
     * Generic initializer for boot properties like the key and hash. It attempts to read from a
     * system property first, then from a TEE attestation, and finally falls back to a random value
     * if neither is available.
     *
     * @param propertyName The name of the system property (e.g., "ro.boot.vbmeta.digest").
     * @param attestationValueProvider A function that supplies the value from a cached attestation.
     * @param expectedSize The expected length of the byte array (e.g., 32 for a SHA-256 digest).
     * @return The resulting byte array for the property.
     */
    private fun initializeBootProperty(
        propertyName: String,
        attestationValueProvider: () -> ByteArray?,
        expectedSize: Int,
    ): ByteArray {
        // 1. Attempt to get the value from the system property.
        getProperty(propertyName, expectedSize)?.let {
            SystemLogger.debug("Using $propertyName from system property: ${it.toHex()}")
            return it
        }

        // 2. Fallback to the value from a cached TEE attestation.
        try {
            attestationValueProvider()?.let {
                SystemLogger.debug("Using $propertyName from TEE attestation: ${it.toHex()}")
                setProperty(propertyName, it) // Persist for consistency
                return it
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to get $propertyName from attestation.", e)
        }

        // 3. As a final fallback, generate a random value.
        return generateRandomBytes(expectedSize).also {
            SystemLogger.debug("Using randomly generated $propertyName: ${it.toHex()}")
            setProperty(propertyName, it)
        }
    }

    /**
     * Retrieves a system property and validates its format.
     *
     * @param name The name of the system property.
     * @param expectedSize The expected byte length of the property (e.g., 32 for a 64-char hex
     *   string).
     * @return The property value as a ByteArray, or null if not found or invalid.
     */
    @OptIn(ExperimentalStdlibApi::class)
    private fun getProperty(name: String, expectedSize: Int): ByteArray? {
        val value = SystemProperties.get(name, null)
        if (value.isNullOrBlank()) {
            return null
        }
        // A valid digest is (2 * size) hex characters.
        return if (value.length == expectedSize * 2) value.hexToByteArray() else null
    }

    /**
     * Sets a system property using the `resetprop` command.
     *
     * @param name The name of the property to set.
     * @param bytes The value to set, which will be converted to a hex string.
     */
    private fun setProperty(name: String, bytes: ByteArray) {
        val hex = bytes.toHex()
        try {
            SystemLogger.debug("Setting system property '$name' to: $hex")
            val command = arrayOf("resetprop", name, hex)
            val process = Runtime.getRuntime().exec(command)
            val exitCode = process.waitFor()

            if (exitCode != 0) {
                val errorOutput = process.errorStream.bufferedReader().readText()
                SystemLogger.error(
                    "resetprop for '$name' failed with exit code $exitCode: $errorOutput"
                )
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to set '$name' property via resetprop.", e)
        }
    }

    /** Generates a cryptographically random byte array of a specified length. */
    private fun generateRandomBytes(size: Int): ByteArray =
        ByteArray(size).also { ThreadLocalRandom.current().nextBytes(it) }

    // --- Patch Level Properties ---

    fun getPatchLevel(uid: Int): Int {
        val custom = getCustomPatchLevelFor(uid, "system", isLong = false)
        // If custom is null, it means 'device_default' was used, so we fall back.
        // Otherwise, we use the returned value, which is either the parsed date or DO_NOT_REPORT.
        return custom ?: Build.VERSION.SECURITY_PATCH.toPatchLevelInt(isLong = false)
    }

    fun getVendorPatchLevelLong(uid: Int): Int {
        val custom = getCustomPatchLevelFor(uid, "vendor", isLong = true)
        return custom ?: Build.VERSION.SECURITY_PATCH.toPatchLevelInt(isLong = true)
    }

    fun getBootPatchLevelLong(uid: Int): Int {
        val custom = getCustomPatchLevelFor(uid, "boot", isLong = true)
        return custom ?: Build.VERSION.SECURITY_PATCH.toPatchLevelInt(isLong = true)
    }

    /**
     * Retrieves a custom patch level from the configuration if available for a specific UID.
     *
     * @param uid The UID of the calling application.
     * @param component The component to get the patch level for ("system", "vendor", "boot").
     * @param isLong Whether to return the patch level in `YYYYMMDD` or `YYYYMM` format.
     * @return The custom patch level, or null if not configured.
     */
    private fun getCustomPatchLevelFor(uid: Int, component: String, isLong: Boolean): Int? {
        val config = ConfigurationManager.getPatchLevelForUid(uid) ?: return null
        val value =
            when (component) {
                "system" -> config.system ?: config.all
                "vendor" -> config.vendor ?: config.all
                "boot" -> config.boot ?: config.all
                else -> config.all
            } ?: return null

        return when {
            // "device_default" indicates falling back to the system property.
            value.equals("device_default", ignoreCase = true) -> null
            // "no" indicates this value should not be reported.
            value.equals("no", ignoreCase = true) -> DO_NOT_REPORT
            // Otherwise, parse the date string.
            else -> parsePatchLevelValue(value, isLong)
        }
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

    /**
     * Retrieves the attestation version based on security level and OS version. StrongBox (level 2)
     * requires version 300.
     *
     * @param securityLevel The security level of the attestation (1 for TEE, 2 for StrongBox).
     * @return The appropriate attestation version number.
     */
    fun getAttestVersion(securityLevel: Int): Int {
        // StrongBox security level requires an attestation version of at least 300.
        if (securityLevel == SecurityLevel.STRONGBOX) {
            return 300
        }
        return DeviceAttestationService.CachedAttestationData?.attestVersion
            ?: attestVersionMap[Build.VERSION.SDK_INT]
            ?: 400 // Default to a recent version
    }

    /**
     * Retrieves the Keymaster/KeyMint version based on the attestation version.
     *
     * @param securityLevel The security level, used to determine the correct attestation version.
     * @return The appropriate Keymaster or KeyMint version number.
     */
    fun getKeymasterVersion(securityLevel: Int): Int {
        val attestVersion = getAttestVersion(securityLevel)
        return if (attestVersion >= 100) attestVersion else 41 // Keymaster 4.1 for older versions
    }

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
                packages?.list.orEmpty().map { it.packageName to it.longVersionCode }
            }
            .getOrElse {
                SystemLogger.error("Failed to get APEX package information.", it)
                emptyList()
            }
    }

    val moduleHash: ByteArray by lazy {
        DeviceAttestationService.CachedAttestationData?.moduleHash
            ?: runCatching {
                    // TODO: figure out the correct calculation
                    val moduleSequences = ASN1EncodableVector()

                    // 1. Create a DERSequence for each module.
                    apexInfos.forEach { (packageName, versionCode) ->
                        val moduleVector = ASN1EncodableVector()
                        // Use explicit UTF-8 encoding for the package name.
                        moduleVector.add(DEROctetString(packageName.toByteArray(Charsets.UTF_8)))
                        moduleVector.add(ASN1Integer(versionCode))
                        moduleSequences.add(DERSequence(moduleVector))
                    }

                    // 2. Create a DERSet. Bouncy Castle will automatically handle
                    //    the sorting based on the DER-encoded value of each sequence.
                    val modulesSet = DERSet(moduleSequences)

                    // 3. Get the final DER-encoded byte array of the SET.
                    val encodedModules = modulesSet.encoded

                    // 4. Compute the SHA-256 hash.
                    MessageDigest.getInstance("SHA-256").digest(encodedModules)
                }
                .getOrElse {
                    SystemLogger.error("Failed to compute module hash.", it)
                    ByteArray(32) // Return empty hash on failure
                }
    }
}
