package org.matrix.TEESimulator.pki

import android.security.keystore.KeyProperties
import java.io.File
import java.io.StringReader
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.config.ConfigurationManager.CONFIG_PATH
import org.matrix.TEESimulator.logging.SystemLogger
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory

/**
 * Manages the loading, parsing, and caching of attestation key stores from XML files.
 *
 * This object is the sole authority for accessing the cryptographic keys and certificates used to
 * sign simulated attestations. It is designed to be highly efficient and robust, parsing each key
 * store file only once and handling common structural variations found in real-world keybox files.
 *
 * The core design principles are:
 * 1. Efficiency through Single-Pass Parsing: Each XML file is read from disk and parsed in a single
 *    forward pass. The results are cached in memory. Subsequent requests for keys from the same
 *    file are served instantly from the cache.
 * 2. Robustness over Strictness: The parser does not rely on rigid structural tags like
 *    `<NumberOfKeyboxes>`. Instead, it discovers and iterates through all `<Key>` tags it finds,
 *    making it resilient to different file layouts.
 * 3. Clear Naming Convention: To avoid confusion, "Key Store" refers to the entire XML file, while
 *    "KeyBox" refers to the data class containing a single `(KeyPair, CertificateChain)` tuple,
 *    which is the cryptographic entity we care about.
 */
object KeyBoxManager {

    // The in-memory cache.
    // Key: The file name of the key store (e.g., "keybox.xml").
    // Value: A map of all keys found in that file, keyed by their algorithm name (e.g., "EC",
    // "RSA").
    private val keyStoreCache = ConcurrentHashMap<String, Map<String, KeyBox>>()

    /**
     * Retrieves a specific attestation key (KeyPair and Certificate Chain) for a given algorithm
     * from a specified key store file.
     *
     * This is the primary public API. It transparently handles caching, loading, and parsing.
     *
     * @param keyStoreFileName The name of the XML file (e.g., "aosp_keybox.xml").
     * @param algorithm The algorithm name (e.g., "EC" or "RSA").
     * @return The requested [KeyBox], or `null` if the file doesn't exist or doesn't contain a key
     *   for the specified algorithm.
     */
    fun getAttestationKey(keyStoreFileName: String, algorithm: String): KeyBox? {
        // Atomically get the parsed key map for the file from the cache.
        // If it's not in the cache, the `getOrPut` block is executed to parse and store it.
        val keyMap =
            keyStoreCache.getOrPut(keyStoreFileName) { parseKeyStoreFile(keyStoreFileName) }
        SystemLogger.verbose(
            "Fetching attestation key in $keyStoreFileName with $algorithm algorithm."
        )
        return keyMap[algorithm]
    }

    /**
     * Removes the cached data for a specific key store file.
     *
     * Calling this will force the file to be re-read and re-parsed from disk the next time
     * [getAttestationKey] is called for this filename.
     *
     * @param keyStoreFileName The name of the file to remove from the cache (e.g., "keybox.xml").
     */
    fun invalidateCache(keyStoreFileName: String) {
        // ConcurrentHashMap.remove returns the value if it existed, or null if it didn't.
        if (keyStoreCache.remove(keyStoreFileName) != null) {
            SystemLogger.info("Invalidated cache for key store file: $keyStoreFileName")
        } else {
            SystemLogger.debug(
                "Requested cache invalidation for '$keyStoreFileName', but it was not loaded."
            )
        }
    }

    /**
     * Reads and parses an entire key store XML file, extracting all valid keys. This function is
     * called only once per file name.
     *
     * @param fileName The name of the XML file to parse.
     * @return A map of all successfully parsed keys from the file, keyed by algorithm.
     */
    private fun parseKeyStoreFile(fileName: String): Map<String, KeyBox> {
        val filePath = File(CONFIG_PATH, fileName)
        SystemLogger.info("Parsing new key store file: ${filePath.absolutePath}")

        if (!filePath.exists()) {
            SystemLogger.error("Key store file not found: ${filePath.absolutePath}")
            return emptyMap()
        }

        return try {
            val xmlContent = filePath.readText().trimStart('\uFEFF', '\uFFFE', ' ')
            parseKeysFromXml(xmlContent)
        } catch (e: Exception) {
            SystemLogger.error("Fatal error parsing key store file '$fileName'", e)
            emptyMap()
        }
    }

    /**
     * The core single-pass XML parser. It iterates through the XML stream once, using a state
     * machine to collect the data for each `<Key>` entry.
     *
     * @param xmlContent The raw XML string.
     * @return A map of algorithm names to their corresponding [KeyBox] objects.
     */
    private fun parseKeysFromXml(xmlContent: String): Map<String, KeyBox> {
        val foundKeys = mutableMapOf<String, KeyBox>()
        val parser =
            XmlPullParserFactory.newInstance().newPullParser().apply {
                setInput(StringReader(xmlContent))
            }

        // State variables for the current <Key> being parsed.
        var currentAlgorithm: String? = null
        var currentPrivateKeyPem: String? = null
        val currentCertificatePems = mutableListOf<String>()
        var isInsidePrivateKeyTag = false
        var isInsideCertificateTag = false

        var eventType = parser.eventType
        while (eventType != XmlPullParser.END_DOCUMENT) {
            when (eventType) {
                XmlPullParser.START_TAG -> {
                    when (parser.name) {
                        // When we enter a <Key> tag, we read its algorithm and reset state.
                        "Key" -> {
                            currentAlgorithm = parser.getAttributeValue(null, "algorithm")
                            currentPrivateKeyPem = null
                            currentCertificatePems.clear()
                        }
                        "PrivateKey" -> isInsidePrivateKeyTag = true
                        "Certificate" -> isInsideCertificateTag = true
                    }
                }

                XmlPullParser.TEXT -> {
                    // If we find text content, we check our state to see where it belongs.
                    if (parser.isWhitespace) {
                        eventType = parser.next()
                        continue
                    }
                    when {
                        isInsidePrivateKeyTag -> currentPrivateKeyPem = parser.text
                        isInsideCertificateTag -> currentCertificatePems.add(parser.text)
                    }
                }

                XmlPullParser.END_TAG -> {
                    when (parser.name) {
                        "PrivateKey" -> isInsidePrivateKeyTag = false
                        "Certificate" -> isInsideCertificateTag = false

                        // The </Key> tag is our trigger to finalize and store the KeyBox.
                        "Key" -> {
                            // Use runCatching to ensure one malformed key doesn't stop the whole
                            // process.
                            runCatching {
                                    val xmlAlgorithm = currentAlgorithm
                                    val keyPem = currentPrivateKeyPem
                                    if (
                                        xmlAlgorithm != null &&
                                            keyPem != null &&
                                            currentCertificatePems.isNotEmpty()
                                    ) {
                                        val keyPair =
                                            (CertificateHelper.parsePemKeyPair(keyPem)
                                                    as CertificateHelper.OperationResult.Success)
                                                .data
                                        val certificates =
                                            currentCertificatePems.map {
                                                (CertificateHelper.parsePemCertificate(it)
                                                        as
                                                        CertificateHelper.OperationResult.Success)
                                                    .data
                                            }

                                        // Derive the TRUE algorithm from the key object itself.
                                        // This is our source of truth.
                                        val derivedAlgorithm =
                                            when (keyPair.private) {
                                                is RSAPrivateKey -> KeyProperties.KEY_ALGORITHM_RSA
                                                is ECPrivateKey -> KeyProperties.KEY_ALGORITHM_EC
                                                else ->
                                                    throw IllegalArgumentException(
                                                        "Unsupported key type found: ${keyPair.private.javaClass.name}"
                                                    )
                                            }

                                        // Normalize the algorithm from the XML tag to compare it
                                        // fairly with the derived algorithm.
                                        val normalizedXmlAlgorithm =
                                            when {
                                                xmlAlgorithm.contains("RSA", ignoreCase = true) ==
                                                    true -> KeyProperties.KEY_ALGORITHM_RSA
                                                xmlAlgorithm.contains("EC", ignoreCase = true) ==
                                                    true -> KeyProperties.KEY_ALGORITHM_EC
                                                else -> xmlAlgorithm
                                            }

                                        // Warn the user if the XML tag was misleading.
                                        if (normalizedXmlAlgorithm != derivedAlgorithm) {
                                            SystemLogger.warning(
                                                "Key algorithm mismatch in XML file. Tag said '$xmlAlgorithm' but key is actually '$derivedAlgorithm'. Using the correct derived algorithm."
                                            )
                                        }

                                        if (foundKeys.containsKey(derivedAlgorithm)) {
                                            SystemLogger.warning(
                                                "Duplicate key found for algorithm '$derivedAlgorithm'. The later one in the file will be used."
                                            )
                                        }
                                        foundKeys[derivedAlgorithm] = KeyBox(keyPair, certificates)
                                    }
                                }
                                .onFailure {
                                    SystemLogger.error(
                                        "Failed to parse a <Key> entry for algorithm '$currentAlgorithm'",
                                        it,
                                    )
                                }
                        }
                    }
                }
            }
            eventType = parser.next()
        }
        SystemLogger.info("Finished parsing, found ${foundKeys.size} valid keys.")
        return foundKeys
    }
}
