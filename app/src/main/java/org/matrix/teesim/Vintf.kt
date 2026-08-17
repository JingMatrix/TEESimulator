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

    // The legacy Keymaster HIDL HAL. A pre-KeyMint device (Keymaster 3.0/4.0/4.1), or a 12+ device whose
    // vendor still ships the Keymaster HAL behind keystore2's compat shim, declares this instead of the
    // AIDL KeyMint HAL, with a dotted HIDL version like 4.1. An integrity checker maps that version to the
    // attestation/keymaster versions a real device of that HAL reports (AOSP system/keymaster
    // version_to_attestation_version / version_to_keymaster_version) and cross-checks the attested pair.
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

    /**
     * The `attestationVersion` a real device of the legacy Keymaster HIDL HAL declared for [instance]
     * reports — 1 for `@2.0`, 2 for `@3.0`, 3 for `@4.0`, 4 for `@4.1` (AOSP system/keymaster
     * `version_to_attestation_version`) — or null when no manifest declares a Keymaster HAL for that
     * instance (a KeyMint device, or one whose manifest we could not read). Cached per instance, keyed
     * apart from [keyMintHalVersion]'s cache entries. This is the value the harvest aligns the presented
     * attestation to on a device that ships no KeyMint HAL.
     */
    @Synchronized
    fun keymasterHalAttestationVersion(instance: String = "default"): Int? {
        val key = "km-hidl:$instance"
        if (cache.containsKey(key)) return cache[key]
        val v = runCatching { scanKeymaster(instance) }
            .getOrElse {
                SystemLogger.info(
                    "Vintf: Keymaster manifest scan failed: ${it.javaClass.simpleName}: ${it.message}"
                )
                null
            }
        cache[key] = v
        SystemLogger.info(
            "Vintf: declared Keymaster HAL attestationVersion for instance '$instance' = ${v ?: "unknown"}"
        )
        return v
    }

    /** Every candidate VINTF manifest file: each flat manifest that exists, plus every .xml fragment in
     *  a manifest directory. Shared by the KeyMint and Keymaster scans. */
    private fun manifestFiles(): List<File> {
        val out = ArrayList<File>()
        for (path in MANIFEST_PATHS) {
            val f = File(path)
            when {
                !f.exists() -> {}
                f.isDirectory ->
                    f.listFiles { file -> file.isFile && file.name.endsWith(".xml") }?.let(out::addAll)
                else -> out.add(f)
            }
        }
        return out
    }

    /** The highest KeyMint version declared for [instance] across every candidate manifest file. */
    private fun scan(instance: String): Int? {
        var best: Int? = null
        for (file in manifestFiles()) {
            versionIn(file, instance)?.let { v -> best = maxOf(best ?: v, v) }
        }
        return best
    }

    /** The highest Keymaster HIDL attestation version declared for [instance] across every manifest. */
    private fun scanKeymaster(instance: String): Int? {
        var best: Int? = null
        for (file in manifestFiles()) {
            keymasterVersionIn(file, instance)?.let { v -> best = maxOf(best ?: v, v) }
        }
        return best
    }

    /** The `IKeymasterDevice@N` HIDL version, as its attestationVersion equivalent: 2.0->1, 3.0->2,
     *  4.0->3, 4.1->4 (AOSP system/keymaster). Null for an unknown/absent version string. */
    private fun keymasterAttestationVersion(dotted: String): Int? =
        when (dotted.trim()) {
            "2.0" -> 1
            "3.0" -> 2
            "4.0" -> 3
            "4.1" -> 4
            else -> null
        }

    /**
     * The highest Keymaster `IKeymasterDevice/[instance]` HIDL version declared in one manifest file, as
     * its attestationVersion equivalent, or null. Mirrors [versionIn] but for a `format="hidl"` block:
     * the `<version>` is a dotted HIDL version (mapped by [keymasterAttestationVersion]) and the instance
     * is named the classic way — `<interface><name>IKeymasterDevice</name><instance>default</instance>`.
     */
    private fun keymasterVersionIn(file: File, instance: String): Int? {
        var best: Int? = null
        file.inputStream().use { input ->
            val parser = Xml.newPullParser()
            parser.setInput(input, null)

            var inHal = false
            var isHidl = false
            var halName: String? = null
            val attestVersions = ArrayList<Int>()
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
                            attestVersions.clear()
                            instanceMatched = false
                            ifaceName = null
                        }
                        "interface" -> if (inHal) ifaceName = null
                        "name" ->
                            if (inHal) {
                                val text = readText(parser)
                                if (depth <= 3) halName = halName ?: text else ifaceName = text
                            }
                        "version" ->
                            if (inHal && depth <= 3)
                                keymasterAttestationVersion(readText(parser))?.let { attestVersions.add(it) }
                        "instance" ->
                            if (inHal && KEYMASTER_IFACE == ifaceName && readText(parser) == instance) {
                                instanceMatched = true
                            }
                    }
                } else if (event == XmlPullParser.END_TAG && parser.name == "hal") {
                    if (inHal && isHidl && halName == KEYMASTER_HAL && instanceMatched) {
                        attestVersions.maxOrNull()?.let { v -> best = maxOf(best ?: v, v) }
                    }
                    inHal = false
                }
                event = parser.next()
            }
        }
        return best
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
