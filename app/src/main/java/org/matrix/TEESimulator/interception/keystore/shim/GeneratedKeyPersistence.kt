package org.matrix.TEESimulator.interception.keystore.shim

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyPair
import java.security.MessageDigest
import java.security.cert.Certificate
import org.matrix.TEESimulator.config.ConfigurationManager.CONFIG_PATH
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateHelper

data class PersistedKeyData(
    val uid: Int,
    val alias: String,
    val nspace: Long,
    val securityLevel: Int,
    val isAttestationKey: Boolean,
    val algorithm: Int,
    val keySize: Int,
    val ecCurve: Int,
    val purposes: List<Int>,
    val digests: List<Int>,
    val privateKeyBytes: ByteArray,
    val certChainBytes: List<ByteArray>,
)

object GeneratedKeyPersistence {

    private const val FORMAT_VERSION = 1
    private val PERSISTENCE_DIR = File(CONFIG_PATH, "persistent_keys")

    fun save(
        keyId: KeyIdentifier,
        keyPair: KeyPair,
        nspace: Long,
        securityLevel: Int,
        certChain: List<Certificate>,
        algorithm: Int,
        keySize: Int,
        ecCurve: Int,
        purposes: List<Int>,
        digests: List<Int>,
        isAttestationKey: Boolean,
    ) {
        runCatching {
            PERSISTENCE_DIR.mkdirs()
            val filename = keyFileName(keyId.uid, keyId.alias)
            val finalFile = File(PERSISTENCE_DIR, filename)
            val tmpFile = File(PERSISTENCE_DIR, "$filename.tmp")

            try {
                DataOutputStream(BufferedOutputStream(FileOutputStream(tmpFile))).use { out ->
                    out.writeInt(FORMAT_VERSION)
                    out.writeInt(securityLevel)
                    out.writeInt(keyId.uid)
                    out.writeUTF(keyId.alias)
                    out.writeLong(nspace)
                    out.writeBoolean(isAttestationKey)
                    out.writeInt(algorithm)
                    out.writeInt(keySize)
                    out.writeInt(ecCurve)

                    out.writeInt(purposes.size)
                    purposes.forEach { out.writeInt(it) }

                    out.writeInt(digests.size)
                    digests.forEach { out.writeInt(it) }

                    val pkBytes = keyPair.private.encoded
                    out.writeInt(pkBytes.size)
                    out.write(pkBytes)

                    out.writeInt(certChain.size)
                    certChain.forEach { cert ->
                        val encoded = cert.encoded
                        out.writeInt(encoded.size)
                        out.write(encoded)
                    }
                }
            } catch (e: Exception) {
                tmpFile.delete()
                throw e
            }

            // Atomic rename — if this fails the tmp is left behind and cleaned on next deleteAll
            if (!tmpFile.renameTo(finalFile)) {
                tmpFile.delete()
                throw IllegalStateException("Failed to atomically rename $tmpFile -> $finalFile")
            }

            SystemLogger.debug("Persisted key: $keyId")
        }.onFailure { e ->
            SystemLogger.error("Failed to persist key $keyId", e)
        }
    }

    fun delete(keyId: KeyIdentifier) {
        runCatching {
            val file = File(PERSISTENCE_DIR, keyFileName(keyId.uid, keyId.alias))
            if (file.exists()) {
                if (file.delete()) {
                    SystemLogger.debug("Deleted persisted key: $keyId")
                } else {
                    SystemLogger.warning("Failed to delete persisted key file: ${file.name}")
                }
            } else {
                SystemLogger.debug("No persisted file to delete for: $keyId")
            }
        }.onFailure { e ->
            SystemLogger.error("Failed to delete persisted key $keyId", e)
        }
    }

    fun deleteAll() {
        runCatching {
            if (!PERSISTENCE_DIR.exists()) {
                SystemLogger.debug("No persistent_keys directory, nothing to delete")
                return
            }
            val files = PERSISTENCE_DIR.listFiles()
            if (files == null) {
                SystemLogger.warning("Cannot list persistent_keys directory")
                return
            }
            var count = 0
            files.forEach { file ->
                if (file.name.endsWith(".bin") || file.name.endsWith(".tmp")) {
                    if (file.delete()) count++
                }
            }
            SystemLogger.info("Deleted $count persisted key files")
        }.onFailure { e ->
            SystemLogger.error("Failed to delete all persisted keys", e)
        }
    }

    fun loadAll(securityLevel: Int): List<PersistedKeyData> {
        if (!PERSISTENCE_DIR.exists()) {
            SystemLogger.debug("No persistent_keys directory, nothing to load")
            return emptyList()
        }
        val files = PERSISTENCE_DIR.listFiles { _, name -> name.endsWith(".bin") }
        if (files == null) {
            SystemLogger.warning("Cannot read persistent_keys directory")
            return emptyList()
        }
        if (files.isEmpty()) {
            SystemLogger.debug("No persisted key files found")
            return emptyList()
        }
        SystemLogger.info("Found ${files.size} persisted key files to process")

        val result = mutableListOf<PersistedKeyData>()

        for (file in files) {
            runCatching {
                DataInputStream(BufferedInputStream(FileInputStream(file))).use { input ->
                    val version = input.readInt()
                    if (version != FORMAT_VERSION) {
                        SystemLogger.warning(
                            "Skipping ${file.name}: unknown format version $version"
                        )
                        return@runCatching
                    }

                    val storedSecLevel = input.readInt()
                    val uid = input.readInt()
                    val alias = input.readUTF()
                    val nspace = input.readLong()
                    val isAttestKey = input.readBoolean()
                    val algo = input.readInt()
                    val kSize = input.readInt()
                    val curve = input.readInt()

                    val purposeCount = requireBounds(input.readInt(), 64, "purposeCount")
                    val purposes = (0 until purposeCount).map { input.readInt() }

                    val digestCount = requireBounds(input.readInt(), 64, "digestCount")
                    val digests = (0 until digestCount).map { input.readInt() }

                    val pkLen = requireBounds(input.readInt(), 8192, "pkLen")
                    val pkBytes = ByteArray(pkLen)
                    input.readFully(pkBytes)

                    val certCount = requireBounds(input.readInt(), 10, "certCount")
                    val certChainBytes = (0 until certCount).map {
                        val certLen = requireBounds(input.readInt(), 65536, "certLen")
                        val certBytes = ByteArray(certLen)
                        input.readFully(certBytes)
                        certBytes
                    }

                    if (storedSecLevel == securityLevel) {
                        result.add(
                            PersistedKeyData(
                                uid = uid,
                                alias = alias,
                                nspace = nspace,
                                securityLevel = storedSecLevel,
                                isAttestationKey = isAttestKey,
                                algorithm = algo,
                                keySize = kSize,
                                ecCurve = curve,
                                purposes = purposes,
                                digests = digests,
                                privateKeyBytes = pkBytes,
                                certChainBytes = certChainBytes,
                            )
                        )
                    }
                }
            }.onFailure { e ->
                SystemLogger.warning("Skipping corrupted persisted key file: ${file.name}", e)
            }
        }

        SystemLogger.info("Loaded ${result.size} persisted keys for security level $securityLevel")
        return result
    }

    // Re-persist updates the cert chain for an already-persisted key without
    // reconstructing authorization parameters from the response. This avoids
    // pulling keymint Tag dependencies into this file and is correct because
    // the only field that changes post-generation is the patched cert chain.
    fun rePersistIfNeeded(
        callingUid: Int,
        generatedKeyInfo: KeyMintSecurityLevelInterceptor.GeneratedKeyInfo,
    ) {
        val metadata = generatedKeyInfo.response.metadata
        if (metadata == null) {
            SystemLogger.debug("rePersist: no metadata, skipping")
            return
        }
        val secLevel = metadata.keySecurityLevel

        val entry = KeyMintSecurityLevelInterceptor.generatedKeys.entries.find { (id, info) ->
            id.uid == callingUid && info.nspace == generatedKeyInfo.nspace
        }
        if (entry == null) {
            SystemLogger.debug("rePersist: key not found in map for uid=$callingUid nspace=${generatedKeyInfo.nspace}")
            return
        }

        val keyId = entry.key
        val filename = keyFileName(keyId.uid, keyId.alias)
        val existing = File(PERSISTENCE_DIR, filename)

        if (!existing.exists()) {
            SystemLogger.debug("rePersist: no existing file for $keyId, skipping")
            return
        }

        val newChain = CertificateHelper.getCertificateChain(metadata)
        if (newChain == null) {
            SystemLogger.warning("rePersist: could not extract cert chain for $keyId")
            return
        }

        val persisted = runCatching {
            DataInputStream(BufferedInputStream(FileInputStream(existing))).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) {
                    SystemLogger.warning("rePersist: unknown format version $version for $keyId")
                    return
                }
                readPersistedKeyData(input)
            }
        }.getOrNull()
        if (persisted == null) {
            SystemLogger.warning("rePersist: failed to read existing data for $keyId")
            return
        }

        save(
            keyId = keyId,
            keyPair = generatedKeyInfo.keyPair,
            nspace = generatedKeyInfo.nspace,
            securityLevel = secLevel,
            certChain = newChain.toList(),
            algorithm = persisted.algorithm,
            keySize = persisted.keySize,
            ecCurve = persisted.ecCurve,
            purposes = persisted.purposes,
            digests = persisted.digests,
            isAttestationKey = persisted.isAttestationKey,
        )
        SystemLogger.debug("Re-persisted key $keyId with updated cert chain")
    }

    // Corrupted binary files can have arbitrary length fields — cap allocations
    private fun requireBounds(value: Int, max: Int, name: String): Int {
        require(value in 0..max) { "$name out of bounds: $value (max $max)" }
        return value
    }

    private fun keyFileName(uid: Int, alias: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("$uid:$alias".toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) } + ".bin"
    }

    // Reads all fields after version has already been consumed
    private fun readPersistedKeyData(input: DataInputStream): PersistedKeyData {
        val secLevel = input.readInt()
        val uid = input.readInt()
        val alias = input.readUTF()
        val nspace = input.readLong()
        val isAttestKey = input.readBoolean()
        val algo = input.readInt()
        val kSize = input.readInt()
        val curve = input.readInt()

        val purposeCount = requireBounds(input.readInt(), 64, "purposeCount")
        val purposes = (0 until purposeCount).map { input.readInt() }

        val digestCount = requireBounds(input.readInt(), 64, "digestCount")
        val digests = (0 until digestCount).map { input.readInt() }

        val pkLen = requireBounds(input.readInt(), 8192, "pkLen")
        val pkBytes = ByteArray(pkLen)
        input.readFully(pkBytes)

        val certCount = requireBounds(input.readInt(), 10, "certCount")
        val certChainBytes = (0 until certCount).map {
            val certLen = requireBounds(input.readInt(), 65536, "certLen")
            val certBytes = ByteArray(certLen)
            input.readFully(certBytes)
            certBytes
        }

        return PersistedKeyData(
            uid = uid,
            alias = alias,
            nspace = nspace,
            securityLevel = secLevel,
            isAttestationKey = isAttestKey,
            algorithm = algo,
            keySize = kSize,
            ecCurve = curve,
            purposes = purposes,
            digests = digests,
            privateKeyBytes = pkBytes,
            certChainBytes = certChainBytes,
        )
    }
}
