package org.matrix.teesim

import android.os.Build
import android.os.SystemProperties
import java.time.LocalDate

/**
 * Read-only access to system properties plus the integer encodings KeyMint expects: osVersion =
 * major*10000 + minor*100 + sub; osPatchLevel = YYYYMM; vendor/boot patch levels = YYYYMMDD.
 * Nothing here reaches the keystore hot path.
 */
object DeviceProps {

    fun prop(name: String, def: String = ""): String =
        try {
            SystemProperties.get(name, def) ?: def
        } catch (e: Throwable) {
            def
        }

    // --- osVersion --------------------------------------------------------------

    private val osVersionBySdk =
        mapOf(
            37 to 170000, // Android 17
            36 to 160000, // Baklava
            35 to 150000, // VanillaIceCream
            34 to 140000, // UpsideDownCake
            33 to 130000, // Tiramisu
            32 to 120100, // S_V2
            31 to 120000, // S
            30 to 110000, // R
            29 to 100000, // Q
        )

    /** A last-resort osVersion derived from the running platform SDK. */
    fun deviceOsVersion(): Int = osVersionBySdk[Build.VERSION.SDK_INT] ?: 170000

    /** Parse a config osVersion literal: "16", "16.0.0", or an already-encoded int string. */
    fun parseOsVersion(literal: String): Int? {
        val s = literal.trim()
        if (s.isEmpty()) return null
        // Already an integer encoding such as 160000.
        if (!s.contains('.') && s.toIntOrNull()?.let { it >= 10000 } == true) return s.toInt()
        val parts = s.split('.')
        return try {
            val major = parts.getOrNull(0)?.toInt() ?: return null
            val minor = parts.getOrNull(1)?.toIntOrNull() ?: 0
            val sub = parts.getOrNull(2)?.toIntOrNull() ?: 0
            major * 10000 + minor * 100 + sub
        } catch (e: NumberFormatException) {
            null
        }
    }

    // --- patch levels -----------------------------------------------------------

    /** "2025-11-01" (or "20251101") -> 202511. */
    fun toYyyymm(patch: String): Int? {
        val n = patch.replace("-", "")
        return when {
            n.length >= 6 && n.substring(0, 6).all { it.isDigit() } -> n.substring(0, 6).toInt()
            else -> null
        }
    }

    /** "2025-11-05" (or "2025-11") -> 20251105 (day defaults to 01 when absent). */
    fun toYyyymmdd(patch: String): Int? {
        val n = patch.replace("-", "")
        return try {
            when (n.length) {
                8 -> n.toInt()
                6 -> (n.toInt() * 100) + 1 // YYYYMM -> YYYYMM01
                else -> null
            }
        } catch (e: NumberFormatException) {
            null
        }
    }

    /** The system security patch string, e.g. "2025-11-01". */
    fun systemSecurityPatch(): String = Build.VERSION.SECURITY_PATCH ?: ""

    fun vendorSecurityPatch(): String =
        prop("ro.vendor.build.security_patch").ifBlank { systemSecurityPatch() }

    /** Boot has no dedicated build property; use the vendor security patch, the closest real value. */
    fun bootSecurityPatch(): String = vendorSecurityPatch()

    /** osVersion from getprop (ro.build.version.release), encoded, or null when unavailable. */
    fun propOsVersion(): Int? = parseOsVersion(prop("ro.build.version.release", Build.VERSION.RELEASE ?: ""))

    /**
     * Resolve one patch-level component from the config mini-language to its integer encoding, or
     * null to mean "omit / not reported".
     *
     * An empty value reuses the value captured from the real TEE at harvest ([harvested]). Keywords:
     * `system_property` (the matching build property from getprop, and nothing else), `today` (the
     * current month/day), `no` (report 0), or an explicit `YYYY-MM` / `YYYY-MM-DD` date. A date may
     * use the template tokens `YYYY` / `MM` / `DD`, resolved to today, so `YYYY-MM-05` tracks the
     * calendar.
     *
     * An empty harvested value or an absent build property reports nothing — the tag is omitted
     * rather than sent as a made-up default. component: "system" (YYYYMM), "vendor"/"boot" (YYYYMMDD).
     */
    fun resolvePatch(language: String, component: String, harvested: Int?): Int? {
        val isYmd = component != "system"
        val v = language.trim()
        return when {
            v.isEmpty() -> harvested
            v.equals("no", true) -> 0
            v.equals("system_property", true) -> {
                val prop =
                    when (component) {
                        "vendor" -> vendorSecurityPatch()
                        "boot" -> bootSecurityPatch()
                        else -> systemSecurityPatch()
                    }
                if (isYmd) toYyyymmdd(prop) else toYyyymm(prop)
            }
            v.equals("today", true) -> {
                val now = LocalDate.now()
                if (isYmd) now.year * 10000 + now.monthValue * 100 + now.dayOfMonth
                else now.year * 100 + now.monthValue
            }
            else -> {
                val resolved = substituteDateTemplates(v)
                if (isYmd) toYyyymmdd(resolved) else toYyyymm(resolved)
            }
        }
    }

    /** Replace YYYY / MM / DD tokens with today's zero-padded year / month / day. */
    private fun substituteDateTemplates(v: String): String {
        if (!v.contains("YYYY") && !v.contains("MM") && !v.contains("DD")) return v
        val now = LocalDate.now()
        return v.replace("YYYY", "%04d".format(now.year))
            .replace("MM", "%02d".format(now.monthValue))
            .replace("DD", "%02d".format(now.dayOfMonth))
    }
}
