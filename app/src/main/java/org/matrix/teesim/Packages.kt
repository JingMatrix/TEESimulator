package org.matrix.teesim

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.IPackageManager
import android.content.pm.PackageManager
import android.content.pm.ParceledListSlice
import android.content.pm.ResolveInfo
import android.content.pm.UserInfo
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.os.Build
import android.os.IUserManager
import android.os.Process
import android.os.ServiceManager
import android.util.LruCache
import java.io.ByteArrayOutputStream
import java.io.File
import java.lang.reflect.InvocationTargetException

/**
 * Package-name to uid resolution, across every Android user on the device. The public
 * [PackageManager] from the system context answers for user 0 (it hides the per-version aidl flag
 * drift); a work profile or a secondary user lives behind [IPackageManager]'s per-user overloads,
 * which the daemon may call because it runs as root — PackageManagerService waives its
 * cross-user permission check for uid 0.
 */
object Packages {

    private lateinit var pm: PackageManager

    fun init(context: Context) {
        pm = context.packageManager
    }

    // android.os.UserHandle.PER_USER_RANGE: the stride between two users' uids for the same app.
    // A uid is therefore userId * 100000 + appId — user 0's Play Store is 10123, the work
    // profile's clone of it is 1010123, and the two are different callers to keystore.
    const val PER_USER_RANGE = 100000

    /** The Android user a caller uid belongs to (0 for the primary/owner user). */
    fun userIdOf(uid: Int): Int = if (uid < 0) 0 else uid / PER_USER_RANGE

    /** The per-user uid of [appId] (a uid with its user stripped) inside user [userId]. */
    fun uidOf(userId: Int, appId: Int): Int = userId * PER_USER_RANGE + appId % PER_USER_RANGE

    /**
     * Resolve a package name to its app uid inside [userId], or -1 when it is not installed there.
     * User 0 goes through the public PackageManager (the path this has always taken); another user
     * is asked of the package service directly, which is the only way to see a work profile.
     */
    fun uidForPackage(pkg: String, userId: Int = 0): Int =
        if (userId == 0)
            try {
                @Suppress("DEPRECATION") pm.getPackageUid(pkg, 0)
            } catch (e: PackageManager.NameNotFoundException) {
                -1
            } catch (e: Exception) {
                SystemLogger.warning("uidForPackage($pkg) failed", e)
                -1
            }
        else applicationInfoAsUser(pkg, userId)?.uid ?: -1

    /** The first uid the platform hands to a normal app; anything below is a system/shell uid. */
    fun firstAppUid(): Int = Process.FIRST_APPLICATION_UID

    // --- users (work profiles and secondary users) -------------------------------

    /**
     * One Android user. [id] is what a uid carries (uid / [PER_USER_RANGE]), [name] is the label the
     * WebUI shows next to an app, and [managed] marks a work profile — the common case behind #237,
     * and the one worth naming as such when the ROM hands back an empty user name.
     */
    data class UserEntry(val id: Int, val name: String, val managed: Boolean)

    // android.content.pm.UserInfo.FLAG_MANAGED_PROFILE.
    private const val FLAG_MANAGED_PROFILE = 0x00000020

    // The last user set we logged, so a per-resolve enumeration doesn't reprint the same line
    // forever but a profile being created or removed still shows up in logcat when it happens.
    @Volatile private var lastUsersLogged: String? = null

    /**
     * Every user on the device, primary first. Tries the user service (the authoritative answer,
     * which root may ask), then falls back to the on-disk user directories, and finally to a
     * single user 0 — a device with no work profile then behaves exactly as it did before.
     */
    fun users(): List<UserEntry> {
        val found = usersFromService() ?: usersFromDisk() ?: listOf(UserEntry(0, "Owner", false))
        val users = found.sortedBy { it.id }
        val signature = users.joinToString(",") { "${it.id}:${it.name}" }
        if (signature != lastUsersLogged) {
            lastUsersLogged = signature
            SystemLogger.info(
                "Packages: ${users.size} user(s) on device — " +
                    users.joinToString(", ") { "${it.id} '${it.name}'${if (it.managed) " (work)" else ""}" }
            )
        } else {
            SystemLogger.verbose("Packages: ${users.size} user(s) on device (unchanged)")
        }
        return users
    }

    /**
     * The user list from IUserManager, or null when the service is unreachable or its aidl does not
     * match. getUsers is version-specific (see [getUsersForThisSdk]); a ROM that reshuffled or dropped
     * the interface leaves us with no compatible overload and we fall back to disk. Such a mismatch is
     * expected on OEM builds, so it is noted in a single line rather than a stack trace.
     */
    private fun usersFromService(): List<UserEntry>? {
        val binder =
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                    ServiceManager.waitForService("user")
                else ServiceManager.getService("user")
            } catch (e: Exception) {
                SystemLogger.warning("Packages: user service lookup failed", e)
                null
            }
        if (binder == null) {
            SystemLogger.warning("Packages: user service not available; falling back to /data/system/users")
            return null
        }
        val um =
            try {
                IUserManager.Stub.asInterface(binder)
            } catch (e: Throwable) {
                SystemLogger.warning("Packages: IUserManager.asInterface failed", e)
                return null
            }
        val infos =
            try {
                getUsersForThisSdk(um)
            } catch (e: Throwable) {
                // NoSuchMethodError on an aidl mismatch, SecurityException if a ROM tightened the check
                // beyond the platform's uid-0 waiver — both expected on OEM ROMs and both covered by the
                // on-disk fallback, so log one line (no backtrace) and read /data/system/users.
                val cause = (e as? InvocationTargetException)?.targetException ?: e
                SystemLogger.info(
                    "Packages: getUsers unavailable on this ROM (${cause.javaClass.simpleName}); reading /data/system/users"
                )
                return null
            }
        if (infos == null) {
            SystemLogger.info("Packages: no compatible getUsers overload; reading /data/system/users")
            return null
        }
        if (infos.isEmpty()) {
            SystemLogger.warning("Packages: getUsers returned nothing; falling back to /data/system/users")
            return null
        }
        return infos.mapNotNull { info ->
            try {
                val managed = (info.flags and FLAG_MANAGED_PROFILE) != 0
                UserEntry(info.id, userLabel(info.id, info.name, managed), managed)
            } catch (e: Throwable) {
                SystemLogger.warning("Packages: unreadable UserInfo entry", e)
                null
            }
        }
    }

    /**
     * Invoke IUserManager.getUsers with the overload the device actually declares. AOSP's signature is
     * SDK-specific — Android 10 has `getUsers(boolean excludeDying)`, Android 11+ has
     * `getUsers(boolean excludePartial, boolean excludeDying, boolean excludePreCreated)` (verified on
     * cs.android.com) — and OEM ROMs sometimes drop or reshuffle it. So instead of hard-coding one arity
     * and catching a NoSuchMethodError, we reflect over the live interface, pick the all-boolean getUsers
     * whose arity matches this SDK (any available one otherwise), and call it with every flag set (the
     * broadest enumeration, matching what both AOSP arities mean by all-true). Returns null when the ROM
     * declares no such overload, so the caller falls back to reading /data/system/users. Any exception the
     * call itself throws propagates to the caller, which logs it in one line.
     */
    private fun getUsersForThisSdk(um: IUserManager): List<UserInfo>? {
        val candidates =
            um.javaClass.methods.filter { m ->
                m.name == "getUsers" &&
                    List::class.java.isAssignableFrom(m.returnType) &&
                    m.parameterTypes.isNotEmpty() &&
                    m.parameterTypes.all { it == java.lang.Boolean.TYPE }
            }
        if (candidates.isEmpty()) return null
        val preferredArity = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) 3 else 1
        val method =
            candidates.firstOrNull { it.parameterTypes.size == preferredArity }
                ?: candidates.minByOrNull { it.parameterTypes.size }!!
        val allTrue = Array<Any>(method.parameterTypes.size) { true }
        @Suppress("UNCHECKED_CAST")
        return method.invoke(um, *allTrue) as? List<UserInfo>
    }

    // /data/system/users/<id>/ is one directory per user and <id>.xml its record; the daemon is root,
    // so reading them is a dependable last resort when the user service cannot be talked to. Only the
    // ids are taken from the directory names; the name and the managed-profile flag are lifted out of
    // the record with a narrow regex rather than a full XML parse, and both are optional.
    private val USER_NAME_RE = Regex("<name>([^<]*)</name>")
    private val USER_FLAGS_RE = Regex("flags=\"(-?\\d+)\"")

    private fun usersFromDisk(): List<UserEntry>? {
        val dir = File("/data/system/users")
        val ids =
            try {
                dir.listFiles()?.filter { it.isDirectory }?.mapNotNull { it.name.toIntOrNull() }
            } catch (e: Exception) {
                SystemLogger.warning("Packages: cannot list /data/system/users", e)
                null
            }
        if (ids.isNullOrEmpty()) return null
        return ids.map { id ->
            var name = ""
            var flags = 0
            try {
                val xml = File(dir, "$id.xml")
                if (xml.canRead()) {
                    val text = xml.readText()
                    name = USER_NAME_RE.find(text)?.groupValues?.get(1)?.trim().orEmpty()
                    flags = USER_FLAGS_RE.find(text)?.groupValues?.get(1)?.toIntOrNull() ?: 0
                }
            } catch (e: Exception) {
                SystemLogger.warning("Packages: cannot read /data/system/users/$id.xml", e)
            }
            val managed = (flags and FLAG_MANAGED_PROFILE) != 0
            UserEntry(id, userLabel(id, name, managed), managed)
        }
    }

    /** The display name for a user: what the platform recorded, else a role-shaped stand-in. */
    private fun userLabel(id: Int, name: String?, managed: Boolean): String {
        val given = name?.trim().orEmpty()
        if (given.isNotEmpty()) return given
        return when {
            id == 0 -> "Owner"
            managed -> "Work profile"
            else -> "User $id"
        }
    }

    /**
     * One installed app collapsed to its uid — the shape the Scope page and `GET /packages` render.
     * A shared-uid app contributes several [packages] under one entry; [label] is the best human
     * name; [system]/[launchable]/[enabled] are the aggregate flags described on [installedAppsByUid].
     *
     * [userId] is the Android user the entry was enumerated in, and [uid] already carries it (a work
     * profile's clone of an app has both a different uid and the same [packages] as user 0's copy),
     * so one app installed in two users is two entries here — which is exactly how a profile targets
     * one of them without the other.
     */
    data class AppEntry(
        val uid: Int,
        val userId: Int,
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
     * Every installed application on the device, in every user, grouped by uid. Packages that share a
     * uid collapse into a single entry whose [AppEntry.packages] lists them sorted. [AppEntry.system]
     * is true when ANY member carries FLAG_SYSTEM; [AppEntry.launchable] when ANY member has a
     * launcher entry; [AppEntry.label]/[AppEntry.enabled] come from the group's representative (first
     * sorted) package. Failures are logged and swallowed per app, and per user, so one bad entry — or
     * one unreadable work profile — never empties the whole list.
     */
    fun installedAppsByUid(): List<AppEntry> {
        val out = ArrayList<AppEntry>()
        var total = 0
        for (user in users()) {
            val infos = installedApplications(user.id)
            if (infos.isEmpty()) {
                SystemLogger.warning("installedAppsByUid: user ${user.id} enumerated no app")
                continue
            }
            total += infos.size
            val byUid = HashMap<Int, MutableList<ApplicationInfo>>()
            for (ai in infos) byUid.getOrPut(ai.uid) { ArrayList() }.add(ai)

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
                    val launchable = pkgNames.any { hasLauncherEntry(it, user.id) }
                    // Oldest member's first-install time is the group's install age; a per-package failure
                    // contributes nothing (0) rather than aborting the whole entry. It is read per user
                    // because a work profile installs its clone of an app at its own moment.
                    val installTime =
                        pkgNames.mapNotNull { p -> firstInstallTime(p, user.id) }.minOrNull() ?: 0L
                    out.add(
                        AppEntry(
                            uid = uid,
                            userId = user.id,
                            packages = pkgNames,
                            label = label,
                            system = system,
                            launchable = launchable,
                            enabled = rep.enabled,
                            installTime = installTime,
                        )
                    )
                } catch (e: Exception) {
                    SystemLogger.warning("installedAppsByUid: skipping uid $uid (user ${user.id})", e)
                }
            }
        }
        SystemLogger.info("Packages: enumerated $total app(s) across ${out.size} uid(s) in all users")
        return out
    }

    /**
     * Installed package names per Android user id, primary user first. One enumeration per user and
     * nothing else — no labels, icons, install times or launcher probes — because the baseline paths
     * that use it care only about which names exist, and would otherwise pay two binder calls per
     * package for answers they throw away.
     */
    fun installedPackageNamesByUser(): Map<Int, Set<String>> {
        val out = LinkedHashMap<Int, Set<String>>()
        for (user in users())
            out[user.id] = installedApplications(user.id).mapTo(HashSet()) { it.packageName }
        return out
    }

    /** Every installed package name on the device, in every user, for the auto-include baseline seed.
     *  Empty on failure so a broken enumeration never seeds an empty baseline that later mislabels
     *  everything new. The set is user-agnostic on purpose: the baseline answers "did this app exist
     *  when TEESimulator first ran", which is a question about the app, not about one user's copy. */
    fun allInstalledPackageNames(): Set<String> {
        val out = HashSet<String>()
        for (names in installedPackageNamesByUser().values) out.addAll(names)
        if (out.isEmpty()) SystemLogger.warning("allInstalledPackageNames: enumeration came back empty")
        return out
    }

    // --- per-user PackageManager calls -------------------------------------------

    /**
     * Every application installed for [userId]. User 0 keeps the public PackageManager path it has
     * always used; any other user goes through the package service, whose bulk call widened its
     * `flags` argument from int to long in Android 13 — hence [sliceOf], which tries the arity this
     * SDK expects and retries the other one when a ROM disagrees.
     */
    private fun installedApplications(userId: Int): List<ApplicationInfo> {
        if (userId == 0)
            return try {
                @Suppress("DEPRECATION") pm.getInstalledApplications(0)
            } catch (e: Exception) {
                SystemLogger.warning("installedApplications(user 0): getInstalledApplications failed", e)
                emptyList()
            }
        val ipm = packageManagerService() ?: return emptyList()
        return sliceOf("getInstalledApplications(user $userId)") { wide ->
            if (wide) ipm.getInstalledApplications(0L, userId) else ipm.getInstalledApplications(0, userId)
        } ?: emptyList()
    }

    /** [pkg]'s ApplicationInfo inside [userId], or null when it is not installed there. */
    private fun applicationInfoAsUser(pkg: String, userId: Int): ApplicationInfo? {
        val ipm = packageManagerService() ?: return null
        return callBothArities("getApplicationInfo($pkg, user $userId)") { wide ->
            if (wide) ipm.getApplicationInfo(pkg, 0L, userId) else ipm.getApplicationInfo(pkg, 0, userId)
        }
    }

    /** [pkg]'s first-install epoch inside [userId], or null when it cannot be read. */
    private fun firstInstallTime(pkg: String, userId: Int): Long? {
        if (userId == 0)
            return try {
                @Suppress("DEPRECATION") pm.getPackageInfo(pkg, 0).firstInstallTime
            } catch (e: Exception) {
                null
            }
        val ipm = packageManagerService() ?: return null
        return callBothArities("getPackageInfo($pkg, user $userId)") { wide ->
                if (wide) ipm.getPackageInfo(pkg, 0L, userId) else ipm.getPackageInfo(pkg, 0, userId)
            }
            ?.firstInstallTime
    }

    /**
     * Does [pkg] have a launcher entry in [userId] — the "is this a normal app the user can open"
     * probe the picker's User/System split rides on. User 0 asks the same getLaunchIntentForPackage a
     * home screen would; another user resolves the MAIN/LAUNCHER intent through the package service,
     * which is the only cross-user form of that query.
     */
    private fun hasLauncherEntry(pkg: String, userId: Int): Boolean {
        if (userId == 0) {
            return try {
                pm.getLaunchIntentForPackage(pkg) != null
            } catch (e: Exception) {
                false
            }
        }
        val ipm = packageManagerService() ?: return false
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).setPackage(pkg)
        val list =
            sliceOf("queryIntentActivities($pkg, user $userId)") { wide ->
                if (wide) ipm.queryIntentActivities(intent, null, 0L, userId)
                else ipm.queryIntentActivities(intent, null, 0, userId)
            }
        return !list.isNullOrEmpty()
    }

    /** [callBothArities] for the calls that answer with a chunked list. */
    private fun <T> sliceOf(what: String, call: (Boolean) -> ParceledListSlice<T>?): List<T>? =
        callBothArities(what, call)?.list

    /**
     * Run an IPackageManager call that exists in an int-`flags` and a long-`flags` form (the widening
     * landed in Android 13), starting with the one this SDK level expects. A ROM whose aidl sits on
     * the other side of that line answers with NoSuchMethodError, so the other arity is the retry
     * rather than a hard failure; anything else is logged and swallowed as "not available".
     */
    private fun <T> callBothArities(what: String, call: (Boolean) -> T?): T? {
        val wideFirst = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        return try {
            call(wideFirst)
        } catch (e: NoSuchMethodError) {
            SystemLogger.info("Packages: $what has the other flags arity on this ROM; retrying")
            try {
                call(!wideFirst)
            } catch (e2: Throwable) {
                SystemLogger.warning("Packages: $what failed on both arities", e2)
                null
            }
        } catch (e: Throwable) {
            SystemLogger.warning("Packages: $what failed", e)
            null
        }
    }

    // Rendered PNG icons keyed by package. A browser <img> re-hits /icon on every list scroll, so caching
    // the encoded bytes (small; ~a few KB each) keeps those repeats off PackageManager + the PNG encoder.
    private const val ICON_PX = 96
    private val iconCache = LruCache<String, ByteArray>(256)

    /**
     * The app icon for [pkg] rendered to a [ICON_PX]×[ICON_PX] PNG, or null when the package has no icon
     * or anything fails. Adaptive/vector icons have no intrinsic bitmap, so the drawable is always drawn
     * onto a fixed ARGB_8888 canvas rather than read as a bitmap. Results are memoized in [iconCache].
     *
     * [userId] only says where to LOOK the package up — an app installed in a work profile is missing
     * from user 0's PackageManager — not what to draw: every user runs the same apk off the same
     * sourceDir, so the rendered icon is identical and the cache stays keyed by package alone. The
     * managed-profile badge a launcher overlays is a launcher's doing, and is deliberately not drawn.
     */
    fun iconPng(pkg: String, userId: Int = 0): ByteArray? {
        iconCache.get(pkg)?.let {
            return it
        }
        val drawable = loadIconDrawable(pkg, userId) ?: return null
        return try {
            val png = drawableToPng(drawable)
            if (png != null) iconCache.put(pkg, png)
            png
        } catch (e: Exception) {
            SystemLogger.warning("iconPng($pkg): render failed", e)
            null
        }
    }

    /**
     * The icon drawable for [pkg], null when unavailable. Loads the app's own declared icon resource
     * straight from its [android.content.res.Resources], deliberately NOT via
     * [PackageManager.getApplicationIcon].
     *
     * On stock AOSP getApplicationIcon returns the real icon, but on some OEM ROMs (notably ColorOS)
     * it is intercepted by a themed UX-icon loader (OplusUXIconLoader) that reads Settings.Global to
     * pick its icon pack. This daemon is a bare app_process, not AMS-registered, so resolving the
     * settings content provider throws "Unable to find app for caller"; the OEM layer then swallows
     * that failure and hands back a generic placeholder for most apps (and outright throws for a few),
     * so every tile shows a default icon rather than the real one (issue #214). Reading the app's icon
     * resource directly sidesteps the OEM path entirely and yields the real icon on every device.
     * getApplicationIcon is kept only as a last resort for apps that declare no icon resource.
     */
    private fun loadIconDrawable(pkg: String, userId: Int): Drawable? {
        try {
            // User 0's record first even for another user's app: it is the cheap public call, and the
            // two describe the same apk. Only a package that user 0 does not have (a work-profile-only
            // install) needs the per-user lookup.
            val ai =
                try {
                    pm.getApplicationInfo(pkg, 0)
                } catch (e: PackageManager.NameNotFoundException) {
                    applicationInfoAsUser(pkg, userId)
                }
            if (ai != null && ai.icon != 0) {
                pm.getResourcesForApplication(ai).getDrawable(ai.icon, null)?.let {
                    return it
                }
            }
        } catch (e: Exception) {
            SystemLogger.warning("iconPng($pkg): resource icon load failed, trying getApplicationIcon", e)
        }
        return try {
            pm.getApplicationIcon(pkg)
        } catch (e: Exception) {
            SystemLogger.warning("iconPng($pkg, user $userId): getApplicationIcon failed", e)
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
