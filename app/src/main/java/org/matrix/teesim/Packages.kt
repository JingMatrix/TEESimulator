package org.matrix.teesim

import android.content.Context
import android.content.pm.IPackageManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.ServiceManager

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
