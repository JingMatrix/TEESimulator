package org.matrix.teesim

import android.util.Xml
import java.io.File
import org.xmlpull.v1.XmlPullParser

/**
 * Reads the KeyMint HAL AIDL interface version the device declares in its VINTF manifest — the `@N`
 * in `android.hardware.security.keymint.IKeyMintDevice/default@N`. An integrity checker (and
 * Android's own attestation contract, VtsAidlKeyMintTargetTest::check_attestation_version)
 * cross-checks the attested `attestationVersion` against this number: `attestationVersion / 100`
 * must not exceed it. It is baked into the vendor image and we cannot raise it, so it is the hard
 * ceiling for the version we may present.
 *
 * The value is parsed straight from the on-disk manifest fragments, which is exactly what the
 * platform assembles the declaration from; the module runs as root, so the vendor/odm paths are
 * readable. A result (including "not declared") is cached for the process — VINTF cannot change
 * without a reboot.
 */
object Vintf {

    // The KeyMint HAL package and the device interface within it we care about. A hal block may
    // also carry
    // ISharedSecret/ISecureClock under the same package version, so the interface name is matched
    // too.
    private const val KEYMINT_HAL = "android.hardware.security.keymint"
    private const val KEYMINT_IFACE = "IKeyMintDevice"
    private const val KEYMASTER_HAL = "android.hardware.keymaster"
    private const val KEYMASTER_IFACE = "IKeymasterDevice"

    // Standard AIDL VINTF manifest locations, vendor first (KeyMint is a vendor HAL). The
    // directories hold
    // per-HAL fragments; the flat files are the legacy single-manifest form. All are scanned and
    // the highest
    // matching version wins, so a fragment declaring the real HAL is found wherever the OEM placed
    // it.
    private val MANIFEST_PATHS =
        listOf(
            "/vendor/etc/vintf/manifest.xml",
            "/vendor/etc/vintf/manifest",
            "/odm/etc/vintf/manifest.xml",
            "/odm/etc/vintf/manifest",
            "/vendor/manifest.xml",
        )

    private val cache = HashMap<String, Int?>()
    data class AttestationConstraint(val version: Int, val exact: Boolean)

    private val attestationCache = HashMap<String, AttestationConstraint?>()

    /**
     * Highest attestation schema version consistent with the hardware-backed keystore HAL declared
     * for [instance]. Modern AIDL KeyMint versions map directly to their attestation encoding (3 ->
     * 300). Legacy HIDL Keymaster versions use the historical mapping from the Android attestation
     * specification: 3.0 -> 2, 4.0 -> 3, and 4.1 -> 4.
     */
    @Synchronized
    fun attestationVersionConstraint(instance: String = "default"): AttestationConstraint? {
        if (attestationCache.containsKey(instance)) return attestationCache[instance]
        val constraint =
            keyMintHalVersion(instance)?.let { AttestationConstraint(it * 100, exact = false) }
                ?: scanKeymaster(instance)?.let { AttestationConstraint(it, exact = true) }
        attestationCache[instance] = constraint
        SystemLogger.info(
            "Vintf: attestation version constraint for instance '$instance' = " +
                "${constraint?.version ?: "unknown"} (exact=${constraint?.exact ?: false})"
        )
        return constraint
    }

    /**
     * The declared KeyMint AIDL version for [instance] (e.g. 3 for `IKeyMintDevice/default@3`), or
     * null when no manifest declares it — a software-only device, or one whose manifest we could
     * not read. Cached per instance, so repeated harvests pay the scan once.
     */
    @Synchronized
    fun keyMintHalVersion(instance: String = "default"): Int? {
        if (cache.containsKey(instance)) return cache[instance]
        val v = runCatching {
            scan(instance)
        }
            .getOrElse {
                SystemLogger.info(
                    "Vintf: manifest scan failed: ${it.javaClass.simpleName}: ${it.message}"
                )
                null
            }
        cache[instance] = v
        SystemLogger.info(
            "Vintf: declared KeyMint HAL version for instance '$instance' = ${v ?: "unknown"}"
        )
        return v
    }

    /** The highest KeyMint version declared for [instance] across every candidate manifest file. */
    private fun scan(instance: String): Int? {
        var best: Int? = null
        for (path in MANIFEST_PATHS) {
            val f = File(path)
            val files =
                when {
                    !f.exists() -> emptyList()
                    f.isDirectory ->
                        f.listFiles { file -> file.isFile && file.name.endsWith(".xml") }?.toList()
                            ?: emptyList()
                    else -> listOf(f)
                }
            for (file in files) {
                versionIn(file, instance)?.let { v -> best = maxOf(best ?: v, v) }
            }
        }
        return best
    }

    /** Highest legacy HIDL Keymaster attestation version declared for [instance]. */
    private fun scanKeymaster(instance: String): Int? {
        var best: Int? = null
        for (path in MANIFEST_PATHS) {
            val f = File(path)
            val files =
                when {
                    !f.exists() -> emptyList()
                    f.isDirectory ->
                        f.listFiles { file -> file.isFile && file.name.endsWith(".xml") }?.toList()
                            ?: emptyList()
                    else -> listOf(f)
                }
            for (file in files) {
                keymasterVersionIn(file, instance)?.let { v -> best = maxOf(best ?: v, v) }
            }
        }
        return best
    }

    /** Parse a legacy HIDL Keymaster declaration and return its attestation schema version. */
    private fun keymasterVersionIn(file: File, instance: String): Int? {
        var best: Int? = null
        file.inputStream().use { input ->
            val parser = Xml.newPullParser()
            parser.setInput(input, null)

            var inHal = false
            var isHidl = false
            var halName: String? = null
            val versions = ArrayList<String>()
            var instanceMatched = false
            var ifaceName: String? = null

            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                if (event == XmlPullParser.START_TAG) {
                    val depth = parser.depth
                    when (parser.name) {
                        "hal" -> {
                            inHal = true
                            isHidl = "hidl".equals(parser.getAttributeValue(null, "format"), true)
                            halName = null
                            versions.clear()
                            instanceMatched = false
                            ifaceName = null
                        }
                        "interface" -> if (inHal) ifaceName = null
                        "name" ->
                            if (inHal) {
                                val text = readText(parser)
                                if (depth <= 3) halName = halName ?: text else ifaceName = text
                            }
                        "version" -> if (inHal && depth <= 3) versions.add(readText(parser))
                        "instance" ->
                            if (
                                inHal &&
                                    KEYMASTER_IFACE == ifaceName &&
                                    readText(parser) == instance
                            ) {
                                instanceMatched = true
                            }
                        "fqname" ->
                            if (inHal) {
                                // Format: "@3.0::IKeymasterDevice/default".
                                val fq = readText(parser)
                                val ifaceAndInstance = fq.substringAfter("::", fq)
                                if (
                                    ifaceAndInstance.substringBefore('/') == KEYMASTER_IFACE &&
                                        ifaceAndInstance.substringAfterLast('/') == instance
                                ) {
                                    instanceMatched = true
                                    fq.substringAfter('@', "")
                                        .substringBefore("::")
                                        .takeIf { it.isNotEmpty() }
                                        ?.let { versions.add(it) }
                                }
                            }
                    }
                } else if (event == XmlPullParser.END_TAG && parser.name == "hal") {
                    if (inHal && isHidl && halName == KEYMASTER_HAL && instanceMatched) {
                        versions.mapNotNull(::keymasterAttestationVersion).maxOrNull()?.let { v ->
                            best = maxOf(best ?: v, v)
                        }
                    }
                    inHal = false
                }
                event = parser.next()
            }
        }
        return best
    }

    private fun keymasterAttestationVersion(version: String): Int? =
        when (version.trim()) {
            "2.0" -> 1
            "3.0" -> 2
            "4.0" -> 3
            "4.1" -> 4
            else -> null
        }

    /**
     * The highest KeyMint `IKeyMintDevice/[instance]` AIDL version declared in one manifest file,
     * or null. Walks each `<hal format="aidl">` block, collecting its package name, its version(s),
     * and the instances it exposes — modern `<fqname>IKeyMintDevice/default</fqname>`, or the older
     * `<interface><name>IKeyMintDevice</name><instance>default</instance></interface>` — and keeps
     * the version of any block that both names KeyMint and exposes the requested instance.
     *
     * Element nesting is read from the parser depth (manifest=1, hal=2, a direct child of hal=3, a
     * child of <interface>=4), which is how a package `<name>`/`<version>` is told apart from an
     * interface `<name>` and its `<instance>`.
     */
    private fun versionIn(file: File, instance: String): Int? {
        var best: Int? = null
        file.inputStream().use { input ->
            val parser = Xml.newPullParser()
            parser.setInput(input, null)

            // Per-<hal> accumulation, reset at each <hal> start.
            var inHal = false
            var isAidl = false
            var halName: String? = null
            val versions = ArrayList<Int>()
            var instanceMatched = false
            var ifaceName: String? = null // name of the <interface> currently being read

            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                if (event == XmlPullParser.START_TAG) {
                    val depth = parser.depth
                    when (parser.name) {
                        "hal" -> {
                            inHal = true
                            isAidl = "aidl".equals(parser.getAttributeValue(null, "format"), true)
                            halName = null
                            versions.clear()
                            instanceMatched = false
                            ifaceName = null
                        }
                        "interface" -> if (inHal) ifaceName = null
                        "name" ->
                            if (inHal) {
                                val text = readText(parser)
                                // depth 3: the package name under <hal>; depth 4: the interface
                                // name.
                                if (depth <= 3) halName = halName ?: text else ifaceName = text
                            }
                        "version" ->
                            if (inHal && depth <= 3)
                                readText(parser).toIntOrNull()?.let { versions.add(it) }
                        "instance" ->
                            if (
                                inHal && KEYMINT_IFACE == ifaceName && readText(parser) == instance
                            ) {
                                instanceMatched = true
                            }
                        "fqname" ->
                            if (inHal) {
                                // Format: "IKeyMintDevice/default" (interface/instance).
                                val fq = readText(parser)
                                if (
                                    fq.substringBefore('/') == KEYMINT_IFACE &&
                                        fq.substringAfterLast('/') == instance
                                ) {
                                    instanceMatched = true
                                }
                            }
                    }
                } else if (event == XmlPullParser.END_TAG && parser.name == "hal") {
                    if (inHal && isAidl && halName == KEYMINT_HAL && instanceMatched) {
                        versions.maxOrNull()?.let { v -> best = maxOf(best ?: v, v) }
                    }
                    inHal = false
                }
                event = parser.next()
            }
        }
        return best
    }

    /**
     * Trimmed text of the element the parser is positioned on. Leaves the parser on the element's
     * END_TAG, so the caller's `parser.next()` advances past it — matching a plain
     * START_TAG/TEXT/END_TAG walk.
     */
    private fun readText(parser: XmlPullParser): String =
        if (parser.next() == XmlPullParser.TEXT) parser.text?.trim().orEmpty() else ""
}
