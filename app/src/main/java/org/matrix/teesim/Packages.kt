package org.matrix.teesim

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.IPackageManager
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.os.Build
import android.os.Process
import android.os.ServiceManager
import android.util.LruCache
import java.io.ByteArrayOutputStream

/**
 * Package-name to uid resolution. Prefers the public [PackageManager] from the system context (it
 * hides the per-version aidl flag drift); keeps an [IPackageManager] handle for the reverse uid to
 * package-name mapping the legacy path needs.
 */
object Packages {

    private lateinit var pm: PackageManager

    fun init(context: Context) {
        pm = context.packageManager
    }

    /** Resolve a package name to its app uid, or -1 when it is not installed. */
    fun uidForPackage(pkg: String): Int =
        try {
            @Suppress("DEPRECATION") pm.getPackageUid(pkg, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            -1
        } catch (e: Exception) {
            SystemLogger.warning("uidForPackage($pkg) failed", e)
            -1
        }

    /** The first uid the platform hands to a normal app; anything below is a system/shell uid. */
    fun firstAppUid(): Int = Process.FIRST_APPLICATION_UID

    /**
     * One installed app collapsed to its uid — the shape the Scope page and `GET /packages` render.
     * A shared-uid app contributes several [packages] under one entry; [label] is the best human
     * name; [system]/[launchable]/[enabled] are the aggregate flags described on [installedAppsByUid].
     */
    data class AppEntry(
        val uid: Int,
        val packages: List<String>,
        val label: String,
        val system: Boolean,
        val launchable: Boolean,
        val enabled: Boolean,
        // Epoch ms of first install, taken as the earliest firstInstallTime across the uid's members (a
        // shared-uid group's "age" is its oldest member); 0 when PackageManager yields nothing usable.
        val installTime: Long,
    )

    /**
     * Every installed application on the device, grouped by uid (the daemon runs as root, so its
     * PackageManager sees all apps as one uid namespace). Packages that share a uid collapse into a
     * single entry whose [AppEntry.packages] lists them sorted. [AppEntry.system] is true when ANY
     * member carries FLAG_SYSTEM; [AppEntry.launchable] when ANY member has a launcher entry;
     * [AppEntry.label]/[AppEntry.enabled] come from the group's representative (first sorted) package.
     * Failures are logged and swallowed per app so one bad entry never empties the whole list.
     */
    fun installedAppsByUid(): List<AppEntry> {
        val infos =
            try {
                @Suppress("DEPRECATION") pm.getInstalledApplications(0)
            } catch (e: Exception) {
                SystemLogger.warning("installedAppsByUid: getInstalledApplications failed", e)
                return emptyList()
            }
        val byUid = HashMap<Int, MutableList<ApplicationInfo>>()
        for (ai in infos) byUid.getOrPut(ai.uid) { ArrayList() }.add(ai)

        val out = ArrayList<AppEntry>(byUid.size)
        for ((uid, members) in byUid) {
            try {
                members.sortBy { it.packageName }
                val pkgNames = members.map { it.packageName }
                val rep = members.first()
                val label =
                    try {
                        pm.getApplicationLabel(rep).toString().takeIf { it.isNotBlank() }
                            ?: rep.packageName
                    } catch (e: Exception) {
                        rep.packageName
                    }
                val system = members.any { (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0 }
                // getLaunchIntentForPackage(pkg) is the simplest "has a launcher entry" probe — it is
                // exactly what a home screen would use to start the app.
                val launchable = pkgNames.any { pm.getLaunchIntentForPackage(it) != null }
                // Oldest member's first-install time is the group's install age; a per-package failure
                // contributes nothing (0) rather than aborting the whole entry.
                val installTime =
                    pkgNames.mapNotNull { p ->
                        try {
                            @Suppress("DEPRECATION") pm.getPackageInfo(p, 0).firstInstallTime
                        } catch (e: Exception) {
                            null
                        }
                    }.minOrNull() ?: 0L
                out.add(
                    AppEntry(
                        uid = uid,
                        packages = pkgNames,
                        label = label,
                        system = system,
                        launchable = launchable,
                        enabled = rep.enabled,
                        installTime = installTime,
                    )
                )
            } catch (e: Exception) {
                SystemLogger.warning("installedAppsByUid: skipping uid $uid", e)
            }
        }
        SystemLogger.info("Packages: enumerated ${infos.size} app(s) across ${out.size} uid(s)")
        return out
    }

    /** Every installed package name on the device, for the auto-include baseline seed. Empty on
     *  failure so a broken enumeration never seeds an empty baseline that later mislabels everything new. */
    fun allInstalledPackageNames(): Set<String> =
        try {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0).mapTo(HashSet()) { it.packageName }
        } catch (e: Exception) {
            SystemLogger.warning("allInstalledPackageNames: getInstalledApplications failed", e)
            emptySet()
        }

    // Rendered PNG icons keyed by package. A browser <img> re-hits /icon on every list scroll, so caching
    // the encoded bytes (small; ~a few KB each) keeps those repeats off PackageManager + the PNG encoder.
    private const val ICON_PX = 96
    private val iconCache = LruCache<String, ByteArray>(256)

    /**
     * The app icon for [pkg] rendered to a [ICON_PX]×[ICON_PX] PNG, or null when the package has no icon
     * or anything fails. Adaptive/vector icons have no intrinsic bitmap, so the drawable is always drawn
     * onto a fixed ARGB_8888 canvas rather than read as a bitmap. Results are memoized in [iconCache].
     */
    fun iconPng(pkg: String): ByteArray? {
        iconCache.get(pkg)?.let {
            return it
        }
        return try {
            val drawable: Drawable = pm.getApplicationIcon(pkg)
            val png = drawableToPng(drawable)
            if (png != null) iconCache.put(pkg, png)
            png
        } catch (e: Exception) {
            SystemLogger.warning("iconPng($pkg) failed", e)
            null
        }
    }

    private fun drawableToPng(drawable: Drawable): ByteArray? {
        // Honor an intrinsic bitmap's aspect where present, but never exceed ICON_PX — most launcher
        // icons are already square, and a fixed cap keeps the wire payload predictable.
        val w = ICON_PX
        val h = ICON_PX
        val bmp =
            if (drawable is BitmapDrawable && drawable.bitmap != null) {
                Bitmap.createScaledBitmap(drawable.bitmap, w, h, true)
            } else {
                val b = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
                val canvas = Canvas(b)
                drawable.setBounds(0, 0, w, h)
                drawable.draw(canvas)
                b
            }
        val bos = ByteArrayOutputStream()
        return if (bmp.compress(Bitmap.CompressFormat.PNG, 100, bos)) bos.toByteArray() else null
    }

    // --- IPackageManager (reverse mapping: uid -> package) -----------------------

    @Volatile private var ipm: IPackageManager? = null

    fun packageManagerService(): IPackageManager? {
        ipm?.let {
            return it
        }
        val binder =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                ServiceManager.waitForService("package")
            else ServiceManager.getService("package")
        if (binder == null) {
            SystemLogger.error("package service not available")
            return null
        }
        return IPackageManager.Stub.asInterface(binder).also { ipm = it }
    }

    fun packagesForUid(uid: Int): Array<String> =
        try {
            packageManagerService()?.getPackagesForUid(uid) ?: emptyArray()
        } catch (e: Exception) {
            SystemLogger.warning("getPackagesForUid($uid) failed", e)
            emptyArray()
        }
}
