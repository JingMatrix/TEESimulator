package org.matrix.TEESimulator.util

import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.os.SystemProperties
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.time.LocalDate
import java.util.concurrent.ThreadLocalRandom
import org.bouncycastle.asn1.ASN1EncodableVector
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
        return custom ?: getRealDevicePatchLevelInt("system", isLong = false)
    }

    fun getVendorPatchLevelLong(uid: Int): Int {
        val custom = getCustomPatchLevelFor(uid, "vendor", isLong = true)
        return custom ?: getRealDevicePatchLevelInt("vendor", isLong = true)
    }

    fun getBootPatchLevelLong(uid: Int): Int {
        val custom = getCustomPatchLevelFor(uid, "boot", isLong = true)
        return custom ?: getRealDevicePatchLevelInt("boot", isLong = true)
    }

    /**
     * Retrieves the definitive device patch level integer for a given component. This function
     * encapsulates the entire fallback chain and guarantees a non-null return.
     *
     * Fallback Priority:
     * 1. Cached TEE attestation data.
     * 2. Specific system property (e.g., ro.vendor.build.security_patch).
     * 3. Default system patch level from Build.VERSION.SECURITY_PATCH.
     *
     * @param component The component ("system", "vendor", "boot").
     * @param isLong Whether the final integer should be in YYYYMMDD format.
     * @return The patch level as a guaranteed non-null Integer.
     */
    private fun getRealDevicePatchLevelInt(component: String, isLong: Boolean): Int {
        // Get value from cached TEE attestation data
        DeviceAttestationService.CachedAttestationData?.let { data ->
            val value =
                when (component) {
                    "system" -> data.osPatchLevel
                    "vendor" -> data.vendorPatchLevel
                    "boot" -> data.bootPatchLevel
                    else -> null
                }
            if (value != null) return value
        }

        // We only check the specific vendor property, as the boot one is non-existent.
        if (component == "vendor") {
            val propValue = SystemProperties.get("ro.vendor.build.security_patch", "")
            if (!propValue.isNullOrBlank()) {
                parsePatchLevelValue(propValue, isLong)?.let { parsedValue ->
                    return parsedValue
                }
            }
        }

        return Build.VERSION.SECURITY_PATCH.toPatchLevelInt(isLong)
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

        // First, resolve dynamic keywords and templates into a concrete date string.
        val resolvedValue = resolveDateKeywords(value)

        return when {
            // "device_default" indicates falling back to the system property.
            resolvedValue.equals("device_default", ignoreCase = true) -> null
            // "no" indicates this value should not be reported.
            resolvedValue.equals("no", ignoreCase = true) -> DO_NOT_REPORT
            // Otherwise, parse the resolved date string.
            else -> parsePatchLevelValue(resolvedValue, isLong)
        }
    }

    /**
     * Resolves special date keywords and templates into a concrete "YYYY-MM-DD" date string.
     *
     * @param value The configuration value string (e.g., "today", "YYYY-MM-01").
     * @return A concrete date string, or the original value if it's not a dynamic date keyword.
     */
    private fun resolveDateKeywords(value: String): String {
        // Handle the "today" keyword.
        if (value.equals("today", ignoreCase = true)) {
            return LocalDate.now().toString() // Returns "YYYY-MM-DD" format
        }

        // Handle date templates like "YYYY-MM-01" or "2025-MM-DD".
        if (
            value.contains("YYYY", ignoreCase = true) ||
                value.contains("MM", ignoreCase = true) ||
                value.contains("DD", ignoreCase = true)
        ) {

            val now = LocalDate.now()
            // Chain replacements for YYYY, MM, and DD placeholders.
            return value
                .replace("YYYY", now.year.toString(), ignoreCase = true)
                .replace("MM", String.format("%02d", now.monthValue), ignoreCase = true)
                .replace("DD", String.format("%02d", now.dayOfMonth), ignoreCase = true)
        }

        // If it's not a dynamic keyword or template, return the original value.
        return value
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

    // https://cs.android.com/android/platform/superproject/+/android-latest-release:system/apex/proto/apex_manifest.proto
    // --- Minimal Protobuf Parser for ApexManifest ---
    // Field 1: name (string)
    // Field 2: version (int64)
    private class MinimalApexManifestParser(private val data: ByteArray) {
        var pos = 0

        fun parse(): Pair<String, Long>? {
            var name: String? = null
            var version: Long? = null

            while (pos < data.size) {
                val tag = readVarint()
                val fieldNum = tag ushr 3
                val wireType = (tag and 0x07).toInt()

                when (fieldNum) {
                    1L -> { // name
                        val length = readVarint().toInt()
                        if (pos + length > data.size) return null
                        name = String(data, pos, length, Charsets.UTF_8)
                        pos += length
                    }
                    2L -> { // version
                        version = readVarint()
                    }
                    else -> skipField(wireType)
                }
            }

            return if (name != null && version != null) {
                name to version
            } else {
                null
            }
        }

        private fun readVarint(): Long {
            var value = 0L
            var shift = 0
            while (pos < data.size) {
                val b = data[pos++].toInt()
                value = value or ((b and 0x7F).toLong() shl shift)
                if ((b and 0x80) == 0) return value
                shift += 7
            }
            return value
        }

        private fun skipField(wireType: Int) {
            when (wireType) {
                0 -> readVarint() // Varint
                1 -> pos += 8 // 64-bit
                2 -> { // Length-delimited
                    val len = readVarint().toInt()
                    pos += len
                }
                5 -> pos += 4 // 32-bit
                else -> throw IllegalStateException("Unknown wire type $wireType")
            }
        }
    }

    // https://cs.android.com/android/platform/superproject/main/+/main:system/apex/libs/libapexutil/apexutil.cpp
    private val apexInfos: List<Pair<String, Long>> by lazy {
        val results = mutableListOf<Pair<String, Long>>()
        val apexRoot = File("/apex")

        if (!apexRoot.exists() || !apexRoot.isDirectory) {
            return@lazy emptyList()
        }

        // Logic from: GetActivePackages in apexutil.cpp
        apexRoot.listFiles()?.forEach { file ->
            if (!file.isDirectory) return@forEach
            val name = file.name

            // 1. Ignore "." (and implicitly "..")
            if (name.startsWith(".")) return@forEach

            // 2. Ignore directories containing '@' (active mounts usually don't have version in
            // path)
            if (name.contains("@")) return@forEach

            // 3. Ignore "sharedlibs"
            if (name == "sharedlibs") return@forEach

            // 4. Parse apex_manifest.pb
            val manifestFile = File(file, "apex_manifest.pb")
            if (manifestFile.exists()) {
                runCatching {
                    val bytes = FileInputStream(manifestFile).use { it.readBytes() }
                    val parser = MinimalApexManifestParser(bytes)
                    parser.parse()?.let { (pkgName, version) -> results.add(pkgName to version) }
                }
            }
        }

        // Ensure uniqueness (though filesystem scan usually prevents exact dupes,
        // strictly speaking we want to behave like a Map keyed by package name)
        results.distinctBy { it.first }
    }

    // https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/maintenance.rs
    val moduleHash: ByteArray by lazy {
        DeviceAttestationService.CachedAttestationData?.moduleHash
            ?: runCatching {
                    // 1. Create a container to hold the sort key (name encoded) and the full data
                    // (sequence encoded)
                    data class ModuleEntry(
                        val nameEncoded: ByteArray, // The sort key
                        val fullEncoded: ByteArray, // The data to hash
                    )

                    val modules =
                        apexInfos.map { (packageName, versionCode) ->
                            // Create the components
                            val nameOctet = DEROctetString(packageName.toByteArray(Charsets.UTF_8))
                            val versionInt = ASN1Integer(versionCode)

                            // Create the Sequence: SEQUENCE { packageName, version }
                            val vec = ASN1EncodableVector()
                            vec.add(nameOctet)
                            vec.add(versionInt)
                            val sequence = DERSequence(vec)

                            // We store the encoded name separately because Rust sorts ONLY by this
                            ModuleEntry(
                                nameEncoded = nameOctet.encoded,
                                fullEncoded = sequence.encoded,
                            )
                        }

                    // 2. Sort manually based on the encoded Package Name (lexicographically)
                    // This mimics the Rust 'impl DerOrd for ModuleInfo' which delegates to
                    // 'self.name'
                    val sortedModules =
                        modules.sortedWith { m1, m2 ->
                            compareByteArrays(m1.nameEncoded, m2.nameEncoded)
                        }

                    // 3. Concatenate the full sequences in the specific sorted order
                    val payloadStream = ByteArrayOutputStream()
                    sortedModules.forEach { payloadStream.write(it.fullEncoded) }
                    val payload = payloadStream.toByteArray()

                    // 4. Wrap manually in a DER SET tag (0x31)
                    // We cannot use DERSet(vector) because it would re-sort incorrectly.
                    val finalDerSet = encodeAsDerSet(payload)

                    // 5. Compute SHA-256
                    MessageDigest.getInstance("SHA-256").digest(finalDerSet)
                }
                .getOrElse {
                    SystemLogger.error("Failed to compute module hash.", it)
                    ByteArray(32)
                }
    }

    /** Compares two byte arrays lexicographically (unsigned). */
    private fun compareByteArrays(a: ByteArray, b: ByteArray): Int {
        val length = minOf(a.size, b.size)
        for (i in 0 until length) {
            val byteA = a[i].toInt() and 0xFF
            val byteB = b[i].toInt() and 0xFF
            if (byteA != byteB) {
                return byteA - byteB
            }
        }
        return a.size - b.size
    }

    /** Manually wraps the payload in an ASN.1 SET (0x31) tag with correct length encoding. */
    private fun encodeAsDerSet(payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x31) // ASN.1 Tag for SET
        writeDerLength(out, payload.size)
        out.write(payload)
        return out.toByteArray()
    }

    /** Writes the ASN.1 length field to the stream. */
    private fun writeDerLength(out: ByteArrayOutputStream, length: Int) {
        if (length < 128) {
            // Short form
            out.write(length)
        } else {
            // Long form
            var size = length
            val bytes = ArrayList<Byte>()
            while (size > 0) {
                bytes.add((size and 0xFF).toByte())
                size = size ushr 8
            }
            // First byte: 0x80 | number of length bytes
            out.write(0x80 or bytes.size)
            // Write length bytes in big-endian (reverse of how we extracted them)
            for (i in bytes.indices.reversed()) {
                out.write(bytes[i].toInt())
            }
        }
    }
}
