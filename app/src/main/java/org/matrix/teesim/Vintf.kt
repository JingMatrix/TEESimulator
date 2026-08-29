package org.matrix.teesim

import android.util.Xml
import java.io.File
import org.xmlpull.v1.XmlPullParser

/**
 * Reads the keystore HAL version the device declares in its VINTF manifest, so the harvest can
 * present an attestation version consistent with it ([attestationVersionConstraint]). Two HAL
 * families appear: the AIDL KeyMint HAL
 * (`android.hardware.security.keymint.IKeyMintDevice/default@N`), where `attestationVersion / 100`
 * must not exceed `N` (VtsAidlKeyMintTargetTest::check_attestation_version), and the legacy HIDL
 * Keymaster HAL (`android.hardware.keymaster/IKeymasterDevice/default@X.Y`), whose version maps to
 * an attestation version (AOSP system/keymaster version_to_attestation_version).
 *
 * Values are parsed from the on-disk manifest fragments. The scanned locations and the parsing
 * (device vendor/odm AND framework system/system_ext/product manifests; the `<version>` +
 * `<interface>` form, the `<fqname>` form, and HIDL version ranges) follow the reference detector's
 * manifest reader (../Duck-Detector-Refactoring VintfKeyMintVersionProbe). The module runs as root,
 * so all paths are readable. Results (including "not declared") are cached for the process.
 */
object Vintf {

    // The KeyMint HAL package and the device interface within it we care about. A hal block may
    // also carry ISharedSecret/ISecureClock under the same package version, so the interface name
    // is matched too.
    private const val KEYMINT_HAL = "android.hardware.security.keymint"
    private const val KEYMINT_IFACE = "IKeyMintDevice"

    // The legacy Keymaster HIDL HAL, declared with a dotted HIDL version (e.g. 4.1). AOSP
    // system/keymaster version_to_attestation_version / version_to_keymaster_version map that
    // version to the attestation and keymaster versions.
    private const val KEYMASTER_HAL = "android.hardware.keymaster"
    private const val KEYMASTER_IFACE = "IKeymasterDevice"

    // VINTF manifest locations to scan: the device (vendor/odm) and framework
    // (system/system_ext/product) manifests, matching ../Duck-Detector-Refactoring
    // VintfKeyMintVersionProbe. Each entry is scanned as a directory of *.xml fragments or as a
    // flat file; the highest matching version across every file wins.
    private val MANIFEST_PATHS =
        listOf(
            "/vendor/etc/vintf/manifest.xml",
            "/vendor/etc/vintf/manifest",
            "/odm/etc/vintf/manifest.xml",
            "/odm/etc/vintf/manifest",
            "/system/etc/vintf/manifest.xml",
            "/system/etc/vintf/manifest",
            "/system_ext/etc/vintf/manifest.xml",
            "/system_ext/etc/vintf/manifest",
            "/product/etc/vintf/manifest.xml",
            "/product/etc/vintf/manifest",
            "/vendor/manifest.xml",
        )

    // A HIDL fqname, e.g. "@4.1::IKeymasterDevice/default" -> (version, interface, instance).
    private val HIDL_FQNAME = Regex("^@([0-9]+(?:\\.[0-9]+)?)::([^/]+)/(.+)$")
    // A HIDL version range, e.g. "4.0-1" -> major 4, minors 0..1.
    private val HIDL_RANGE = Regex("^([0-9]+)\\.([0-9]+)-([0-9]+)$")

    private val cache = HashMap<String, Int?>()

    /**
     * A VINTF-derived bound on the attestation version we may present for a security level: an
     * EXACT target (legacy HIDL Keymaster, whose HAL version maps 1:1 to an attestation version) or
     * a CEILING we must not exceed (AIDL KeyMint @N -> N*100).
     */
    data class AttestationConstraint(val version: Int, val exact: Boolean)

    private val constraintCache = HashMap<String, AttestationConstraint?>()

    /**
     * The attestation-version constraint the device's declared keystore HAL imposes for [instance]:
     * an AIDL KeyMint HAL @N gives a ceiling of N*100 (exact=false); a legacy HIDL Keymaster HAL
     * gives an exact target (@3.0 -> 2, @4.0 -> 3, @4.1 -> 4; AOSP system/keymaster). Prefers
     * KeyMint when both are declared. Null when neither is declared.
     * [Harvester.clampAttestationToVintf] reconciles the presented version against it. The
     * ceiling-vs-exact treatment follows ../Duck-Detector-Refactoring VintfKeyMintVersionProbe
     * (KeyMint compared as an upper bound, HIDL Keymaster as equality).
     */
    @Synchronized
    fun attestationVersionConstraint(instance: String = "default"): AttestationConstraint? {
        if (constraintCache.containsKey(instance)) return constraintCache[instance]
        val c =
            keyMintHalVersion(instance)?.let { AttestationConstraint(it * 100, exact = false) }
                ?: keymasterHalAttestationVersion(instance)?.let {
                    AttestationConstraint(it, exact = true)
                }
        constraintCache[instance] = c
        SystemLogger.info(
            "Vintf: attestation-version constraint for '$instance' = " +
                "${c?.version ?: "unknown"} (exact=${c?.exact ?: false})"
        )
        return c
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

    /**
     * The attestation version for the legacy Keymaster HIDL HAL version declared for [instance] — 1
     * for `@2.0`, 2 for `@3.0`, 3 for `@4.0`, 4 for `@4.1` (AOSP system/keymaster
     * `version_to_attestation_version`) — or null when no manifest declares a Keymaster HAL for
     * that instance. Cached per instance, keyed apart from [keyMintHalVersion]'s cache entries.
     */
    @Synchronized
    fun keymasterHalAttestationVersion(instance: String = "default"): Int? {
        val key = "km-hidl:$instance"
        if (cache.containsKey(key)) return cache[key]
        val v = runCatching {
            scanKeymaster(instance)
        }
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

    /**
     * Every candidate VINTF manifest file: each flat manifest that exists, plus every .xml fragment
     * in a manifest directory. Shared by the KeyMint and Keymaster scans.
     */
    private fun manifestFiles(): List<File> {
        val out = ArrayList<File>()
        for (path in MANIFEST_PATHS) {
            val f = File(path)
            when {
                !f.exists() -> {}
                f.isDirectory ->
                    f.listFiles { file -> file.isFile && file.name.endsWith(".xml") }
                        ?.let(out::addAll)
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

    /**
     * The highest Keymaster HIDL attestation version declared for [instance] across every manifest.
     */
    private fun scanKeymaster(instance: String): Int? {
        var best: Int? = null
        for (file in manifestFiles()) {
            keymasterVersionIn(file, instance)?.let { v -> best = maxOf(best ?: v, v) }
        }
        return best
    }

    /**
     * The `IKeymasterDevice@N` HIDL version, as its attestationVersion equivalent: 2.0->1, 3.0->2,
     * 4.0->3, 4.1->4 (AOSP system/keymaster). Null for an unknown/absent version string.
     */
    private fun keymasterAttestationVersion(dotted: String): Int? =
        when (dotted.trim()) {
            "2.0" -> 1
            "3.0" -> 2
            "4.0" -> 3
            "4.1" -> 4
            else -> null
        }

    /**
     * Expand a HIDL version token to concrete versions: "4.1" -> ["4.1"]; the range form "4.0-1"
     * (major.minorFirst-minorLast, as a manifest may abbreviate 4.0 and 4.1) -> ["4.0", "4.1"].
     */
    private fun expandHidlVersions(version: String): List<String> {
        val m = HIDL_RANGE.matchEntire(version.trim()) ?: return listOf(version.trim())
        val major = m.groupValues[1]
        return (m.groupValues[2].toInt()..m.groupValues[3].toInt()).map { "$major.$it" }
    }

    /**
     * The version from a Keymaster `<fqname>` like "@4.1::IKeymasterDevice/default" — but only when
     * it names [instance] on IKeymasterDevice; null otherwise. HIDL fqnames bind version and
     * instance together, so a strongbox fqname never contributes to the default instance.
     */
    private fun keymasterFqnameVersion(fqname: String, instance: String): String? {
        val m = HIDL_FQNAME.matchEntire(fqname.trim()) ?: return null
        val (version, iface, inst) = m.destructured
        return version.takeIf { iface == KEYMASTER_IFACE && inst == instance }
    }

    /**
     * The highest Keymaster `IKeymasterDevice/[instance]` HIDL version declared in one manifest
     * file, as its attestationVersion equivalent, or null. Handles both declaration styles VINTF
     * allows in a `format="hidl"` block: the classic `<version>` +
     * `<interface><name>IKeymasterDevice</name> <instance>default</instance>` form (versions apply
     * to every instance the interface lists), and the
     * `<fqname>@4.1::IKeymasterDevice/default</fqname>` form (version bound to one instance). HIDL
     * version ranges ("4.0-1") are expanded before mapping.
     */
    private fun keymasterVersionIn(file: File, instance: String): Int? {
        var best: Int? = null
        file.inputStream().use { input ->
            val parser = Xml.newPullParser()
            parser.setInput(input, null)

            var inHal = false
            var isHidl = false
            var halName: String? = null
            val versions = ArrayList<String>() // raw <version> tokens (may be ranges)
            val fqnames = ArrayList<String>()
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
                            fqnames.clear()
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
                                readText(parser).let { if (it.isNotEmpty()) versions.add(it) }
                        "instance" ->
                            if (
                                inHal &&
                                    KEYMASTER_IFACE == ifaceName &&
                                    readText(parser) == instance
                            ) {
                                instanceMatched = true
                            }
                        "fqname" ->
                            if (inHal) readText(parser).let { if (it.isNotEmpty()) fqnames.add(it) }
                    }
                } else if (event == XmlPullParser.END_TAG && parser.name == "hal") {
                    if (inHal && isHidl && halName == KEYMASTER_HAL) {
                        // Versions bound to the requested instance: the <version>+<interface> form
                        // when the interface exposed this instance, plus any <fqname> that names it
                        // directly.
                        val bound = ArrayList<String>()
                        if (instanceMatched) bound.addAll(versions)
                        for (fq in fqnames) keymasterFqnameVersion(fq, instance)?.let(bound::add)
                        bound
                            .flatMap(::expandHidlVersions)
                            .mapNotNull(::keymasterAttestationVersion)
                            .maxOrNull()
                            ?.let { v -> best = maxOf(best ?: v, v) }
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
