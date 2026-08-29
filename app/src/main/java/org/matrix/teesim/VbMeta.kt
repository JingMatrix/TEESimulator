package org.matrix.teesim

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileDescriptor
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/**
 * Computes the AVB "vbmeta digest" from the on-device vbmeta partitions, reproducing what libavb's
 * `avb_slot_verify_data_calculate_vbmeta_digest()` (and `avbtool calculate_vbmeta_digest`) produce
 * and what the bootloader exposes as `ro.boot.vbmeta.digest`.
 *
 * The digest is a plain hash over the concatenation of every vbmeta struct reached from the
 * top-level `vbmeta` partition — the main struct first, then each chained partition's struct in
 * descriptor order, depth-first — using the hash named by the top-level struct's algorithm (SHA-256
 * unless the algorithm is one of the SHA-512 variants; an unsigned/NONE image hashes with SHA-256).
 *
 * [computeDigest] is the value the harvester presents for verifiedBootHash / ro.boot.vbmeta.digest
 * when the TEE reported none: computing it ourselves is trustworthy in a way the (spoofable, often
 * absent) ro.boot.vbmeta.digest system property is not.
 */
object VbMeta {

    private const val VBMETA_MAGIC = "AVB0"
    private const val FOOTER_MAGIC = "AVBf"
    private const val HEADER_SIZE = 256
    private const val FOOTER_SIZE = 64
    private const val CHAIN_PARTITION_TAG =
        4L // AVB_DESCRIPTOR_TAG_CHAIN_PARTITION (0=prop 1=hashtree 2=hash 3=cmdline 4=chain)
    private const val MAX_PARTITIONS = 32 // cycle/runaway guard

    private val BY_NAME_DIRS = listOf("/dev/block/by-name", "/dev/block/bootdevice/by-name")

    data class Result(
        val algorithm: String, // "sha256" | "sha512" — the one the top-level struct selects
        val digest: ByteArray, // the digest under [algorithm]
        val partitions: List<String>, // vbmeta structs included, in hash order
        val totalBytes: Int,
    )

    /**
     * The AVB vbmeta digest computed from the on-device partitions, or null when they cannot be
     * read or parsed. Never throws — a read/parse failure is logged and returns null so the caller
     * can fall back.
     */
    fun computeDigest(): ByteArray? =
        try {
            compute()?.digest
        } catch (e: Throwable) {
            SystemLogger.warning("vbmeta digest: computation failed: ${e.message}")
            null
        }

    /**
     * The concatenated vbmeta structs, hashed, plus the structs covered. Null when the top-level
     * vbmeta partition is unreadable. Logs the result so it is visible in the harvest logs.
     */
    fun compute(): Result? {
        val slot = DeviceProps.prop("ro.boot.slot_suffix", "")
        val top = readVbmetaBlob("vbmeta$slot") ?: return null

        val order = ArrayList<String>()
        val blob = ByteArrayBuilder()
        val visited = HashSet<String>()
        // The TOP-LEVEL struct's algorithm selects the hash for the whole digest (SHA-256 for an
        // unsigned/NONE image, matching libavb's fall-through).
        val topAlg = ByteBuffer.wrap(top).order(ByteOrder.BIG_ENDIAN).getInt(28)
        val useSha512 = topAlg in 4..6

        walk("vbmeta", slot, top, order, blob, visited)

        val bytes = blob.toByteArray()
        val digest =
            MessageDigest.getInstance(if (useSha512) "SHA-512" else "SHA-256").digest(bytes)
        val label = if (useSha512) "sha512" else "sha256"
        SystemLogger.info(
            "vbmeta digest: computed ${digest.toHex()} ($label) over ${order.size} struct(s) " +
                "[${order.joinToString(",")}] ${bytes.size}B"
        )
        return Result(
            algorithm = label,
            digest = digest,
            partitions = order,
            totalBytes = bytes.size,
        )
    }

    /**
     * Append [blob] (the vbmeta struct of [baseName]) then recurse into its chain partitions in
     * order.
     */
    private fun walk(
        baseName: String,
        slot: String,
        blob: ByteArray,
        order: MutableList<String>,
        out: ByteArrayBuilder,
        visited: MutableSet<String>,
    ) {
        if (baseName in visited || visited.size >= MAX_PARTITIONS) return
        visited.add(baseName)
        order.add(baseName)
        out.append(blob)

        for (child in chainPartitions(blob)) {
            val childBlob = readVbmetaBlob("$child$slot") ?: continue
            walk(child, slot, childBlob, order, out, visited)
        }
    }

    /** The chain-partition names referenced by a vbmeta struct's descriptors, in order. */
    private fun chainPartitions(blob: ByteArray): List<String> {
        val bb = ByteBuffer.wrap(blob).order(ByteOrder.BIG_ENDIAN)
        val authSize = bb.getLong(12)
        val auxSize = bb.getLong(20)
        val descOffset = bb.getLong(96)
        val descSize = bb.getLong(104)
        val auxStart = HEADER_SIZE + authSize // aux block start within the struct
        var p = (auxStart + descOffset).toInt()
        val end = (auxStart + descOffset + descSize).toInt()
        val names = ArrayList<String>()
        if (auxSize <= 0 || descSize <= 0 || end > blob.size) return names
        while (p + 16 <= end) {
            val tag = bb.getLong(p)
            val numFollowing = bb.getLong(p + 8)
            val body = p + 16
            val next = body + numFollowing.toInt()
            if (next > end || numFollowing < 0) break
            if (tag == CHAIN_PARTITION_TAG) {
                // body: rollback_index_location u32, partition_name_len u32, public_key_len u32,
                //       reserved[64], partition_name[name_len], public_key[key_len]
                val nameLen = bb.getInt(body + 4)
                val nameAt = body + 4 + 4 + 4 + 64
                if (nameLen in 1..512 && nameAt + nameLen <= blob.size) {
                    names.add(String(blob, nameAt, nameLen, Charsets.UTF_8))
                }
            }
            p = next
        }
        return names
    }

    /**
     * The vbmeta struct bytes (header + auth block + aux block) of a partition: located via an
     * AvbFooter in the last 64 bytes for a data partition with an appended footer (boot, system,
     * ...), or at offset 0 for a dedicated vbmeta partition (vbmeta, vbmeta_system, ...). Null if
     * the partition is missing, unreadable, or carries no AVB0 struct.
     */
    private fun readVbmetaBlob(name: String): ByteArray? {
        val path = resolvePartition(name) ?: return null
        return try {
            val size = partitionSize(path)
            var vbOffset = 0L
            if (size >= FOOTER_SIZE) {
                val footer = readAt(path, size - FOOTER_SIZE, FOOTER_SIZE)
                if (footer.size == FOOTER_SIZE && ascii(footer, 0, 4) == FOOTER_MAGIC) {
                    val fb = ByteBuffer.wrap(footer).order(ByteOrder.BIG_ENDIAN)
                    vbOffset = fb.getLong(20) // vbmeta_offset
                }
            }
            val header = readAt(path, vbOffset, HEADER_SIZE)
            if (header.size < HEADER_SIZE || ascii(header, 0, 4) != VBMETA_MAGIC) {
                SystemLogger.info("vbmeta digest: $name has no AVB0 struct at offset $vbOffset")
                return null
            }
            val hb = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
            val authSize = hb.getLong(12)
            val auxSize = hb.getLong(20)
            val total = (HEADER_SIZE + authSize + auxSize).toInt()
            readAt(path, vbOffset, total)
        } catch (e: ErrnoException) {
            SystemLogger.info("vbmeta digest: cannot read $name ($path): ${e.message}")
            null
        } catch (e: Throwable) {
            SystemLogger.warning("vbmeta digest: parse of $name failed: ${e.message}")
            null
        }
    }

    private fun resolvePartition(name: String): String? {
        for (d in BY_NAME_DIRS) {
            val f = File(d, name)
            if (f.exists()) return f.absolutePath
        }
        // Some SoCs expose by-name only under /dev/block/platform/<controller>/by-name.
        File("/dev/block/platform").listFiles()?.forEach { plat ->
            val direct = File(plat, "by-name/$name")
            if (direct.exists()) return direct.absolutePath
            plat.listFiles()?.forEach { sub ->
                val nested = File(sub, "by-name/$name")
                if (nested.exists()) return nested.absolutePath
            }
        }
        return null
    }

    private fun partitionSize(path: String): Long {
        val fd = Os.open(path, OsConstants.O_RDONLY, 0)
        try {
            return Os.lseek(fd, 0, OsConstants.SEEK_END)
        } finally {
            closeQuietly(fd)
        }
    }

    private fun readAt(path: String, offset: Long, len: Int): ByteArray {
        val fd = Os.open(path, OsConstants.O_RDONLY, 0)
        try {
            Os.lseek(fd, offset, OsConstants.SEEK_SET)
            val buf = ByteArray(len)
            var got = 0
            while (got < len) {
                val n = Os.read(fd, buf, got, len - got)
                if (n <= 0) break
                got += n
            }
            return if (got == len) buf else buf.copyOf(got)
        } finally {
            closeQuietly(fd)
        }
    }

    private fun closeQuietly(fd: FileDescriptor) {
        try {
            Os.close(fd)
        } catch (_: ErrnoException) {}
    }

    private fun ascii(b: ByteArray, off: Int, len: Int): String =
        String(b, off, len, Charsets.US_ASCII)

    /**
     * Minimal growable byte sink, so we hash one concatenation without intermediate copies per
     * struct.
     */
    private class ByteArrayBuilder {
        private val out = java.io.ByteArrayOutputStream()

        fun append(b: ByteArray) = out.write(b)

        fun toByteArray(): ByteArray = out.toByteArray()
    }
}
