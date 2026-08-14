package org.matrix.teesim

import java.io.File
import org.json.JSONArray
import org.json.JSONObject

/**
 * The one place that turns a profile's `apps[]` list into the wire arrays the native router matches
 * against — `packages[]` with its per-entry `packageUsers[]` (attestation package-name match,
 * primary) and `uids[]` with `uidPackages[]` (caller-uid match, fallback) — plus the derived sets
 * the WebUI and re-attest paths need. Resolver, ReAttest and KeyAdmin all go through here so uid
 * resolution, the raw-`uid:N` syntax, the auto-include expansion and the low-uid warnings live once,
 * not copied three ways with drift between them.
 *
 * An `apps[]` entry is one of these shapes (see [parse]): a plain package name (the app as installed
 * for the primary user), a `pkg@N` token naming the same app inside Android user N — a work profile
 * or a secondary user, whose clone of an app is a different caller uid entirely — an advanced
 * `uid:N` token that targets a caller uid directly, or something malformed. A package name is kept
 * on the wire verbatim even when the app is not installed yet, because a later install still
 * name-matches; a uid is only ever pushed when it actually resolves (never -1).
 *
 * The user a package entry names is carried onto the wire beside it rather than folded away: the
 * attestation application id an app embeds says which package asked, never which user it ran as, so
 * only the pushed user id lets the router tell user 0's Play Store from the work profile's clone —
 * and hence lets two profiles hold two keyboxes for the same package in two users.
 */
object Scope {

    // android.os.Process.FIRST_APPLICATION_UID. A const avoids importing Process into every caller
    // (and works in unit reasoning), but it is the same 10000 the platform uses for the app range.
    const val FIRST_APP_UID = 10000

    enum class Kind {
        /** A package name that is currently installed in its entry's user; [Explicit.uid] is its
         *  resolved per-user app uid. */
        PACKAGE,
        /** An advanced `uid:N` token; [Explicit.uid] is N, [Explicit.pkg] is null. */
        RAW_UID,
        /** A package-shaped name that is not installed for its user (uid -1, but [Explicit.pkg] is
         *  kept), or a genuinely malformed entry (uid -1, [Explicit.pkg] null). */
        INVALID,
    }

    /**
     * One resolved `apps[]` entry, in the same order as written. [pkg] is non-null for anything
     * package-shaped (installed or not) and null for a `uid:N` token or a malformed entry — which is
     * exactly the "is this a wire package name?" test [ProfileScope.packageNames] uses. [userId] is
     * the Android user the entry names: 0 for a plain package name, N for `pkg@N`, and (for a raw uid
     * token) the user that uid already encodes.
     */
    data class Explicit(
        val entry: String,
        val kind: Kind,
        val uid: Int,
        val pkg: String?,
        val userId: Int,
    )

    /** The fully resolved scope of one profile against the live device. */
    data class ProfileScope(
        val profileId: String,
        // Whether the profile ASKED to auto-include, independent of whether anything qualified. The
        // WebUI needs the two apart: "auto-include on, nothing new yet" reads very differently from
        // "auto-include off", and an empty autoUids alone cannot tell them apart.
        val autoInclude: Boolean,
        val explicit: List<Explicit>, // one per apps[] entry, in order
        val autoUids: Set<Int>, // extra uids contributed by autoIncludeNewApps
        val packageNames: List<String>, // wire packages[]: every package-shaped entry, verbatim
        val packageUsers: List<Int>, // wire packageUsers[]: parallel to packageNames, one user each
        val uids: Set<Int>, // wire uids[]: effective caller uids, never containing -1
        val uidPackages: Map<Int, String>, // wire uidPackages[]: the package name behind a resolved uid
        val lowUids: Set<Int>, // effective uids whose app id is below FIRST_APP_UID, for the warning
    )

    /** The `apps[]` entry naming [pkg] inside [userId] — the plain name for the primary user, the
     *  `pkg@N` form for any other. The one place that spelling is decided. */
    fun entryToken(pkg: String, userId: Int): String = if (userId == 0) pkg else "$pkg@$userId"

    /** Is [uid] a privileged (system/shell) caller? Asked of its APP id, so the answer holds in a
     *  secondary user too — user 10's system_server is uid 1001000, far above [FIRST_APP_UID]. */
    fun isPrivilegedUid(uid: Int): Boolean = uid % Packages.PER_USER_RANGE < FIRST_APP_UID

    /** Classify a single `apps[]` entry. Never throws — a malformed entry becomes [Kind.INVALID]. */
    fun parse(entry: String): Explicit {
        val e = entry.trim()
        if (e.startsWith("uid:")) {
            val digits = e.substring(4)
            val n = if (digits.isNotEmpty() && digits.all { it.isDigit() }) digits.toIntOrNull() else null
            return if (n != null) Explicit(e, Kind.RAW_UID, n, null, Packages.userIdOf(n))
            else Explicit(e, Kind.INVALID, -1, null, 0)
        }
        // pkg@N splits into the package and the Android user it names; a bare package name is user 0.
        // Everything after the first '@' must be digits, so an '@' inside the package part (never
        // legal in a package name anyway) still falls through to INVALID below.
        val at = e.indexOf('@')
        val name = if (at < 0) e else e.substring(0, at)
        val userDigits = if (at < 0) "" else e.substring(at + 1)
        val userId =
            if (at < 0) 0
            else if (userDigits.isNotEmpty() && userDigits.all { it.isDigit() }) userDigits.toIntOrNull() ?: -1
            else -1
        if (userId >= 0 && name.isNotEmpty() && name.all { it.isLetterOrDigit() || it == '_' || it == '.' }) {
            val uid = Packages.uidForPackage(name, userId)
            // Package-shaped: PACKAGE when installed for that user, INVALID (but pkg kept) when not —
            // the name still rides the wire so a later install name-matches, yet contributes no uid
            // until it resolves.
            return if (uid >= 0) Explicit(e, Kind.PACKAGE, uid, name, userId)
            else Explicit(e, Kind.INVALID, -1, name, userId)
        }
        return Explicit(e, Kind.INVALID, -1, null, 0)
    }

    /**
     * Resolve one profile against the live device. [others] are the config's OTHER profiles; their
     * explicit package/uid claims are excluded from this profile's auto-include expansion so a
     * user-app deliberately assigned elsewhere is never silently re-captured here.
     *
     * [quiet] suppresses the per-entry / low-uid / summary logging. The authoritative, verbose
     * resolution log belongs to the ONE write path that actually pushes config (Resolver); the
     * read-only aggregators below ([allTargetUids], [uidToProfile], [uidToPackage]) — some driven by
     * a WebUI endpoint that may be polled — re-derive the same uids and would otherwise re-emit every
     * line (and re-warn about every privileged uid) on each call, so they resolve quietly.
     */
    fun resolve(
        profile: ConfigStore.ProfileConfig,
        others: List<ConfigStore.ProfileConfig>,
        quiet: Boolean = false,
    ): ProfileScope {
        val id = profile.id
        val explicit = profile.apps.map { parse(it) }

        val packageNames = ArrayList<String>()
        val packageUsers = ArrayList<Int>()
        val uids = LinkedHashSet<Int>()
        val uidPackages = LinkedHashMap<Int, String>()
        // The secondary users a primary-user entry might ALSO want to name. Resolved once, and only
        // on the logging (push) path — the point of it is the hint below, which the quiet aggregators
        // do not emit anyway.
        val otherUsers = if (quiet) emptyList() else Packages.users().filter { it.id != 0 }
        for (x in explicit) {
            if (x.pkg != null) {
                packageNames.add(x.pkg)
                packageUsers.add(x.userId)
            }
            when (x.kind) {
                Kind.PACKAGE -> {
                    uids.add(x.uid)
                    // The uid -> package pairing the legacy keystore1 path needs: downstream of that
                    // hook the caller's attestation application id is gone, so it rebuilds one from
                    // this name. It must be carried explicitly, never inferred from array position —
                    // packages[] and uids[] have long since stopped lining up 1:1.
                    x.pkg?.let { uidPackages[x.uid] = it }
                    if (!quiet) {
                        SystemLogger.info(
                            "Scope[$id]: '${x.entry}' -> uid ${x.uid} (user ${x.userId})"
                        )
                        // An entry names one user's copy of the app. Say when the same app also runs
                        // in another user, because that copy is a different caller and stays
                        // untargeted until it is named — a silence that would otherwise read as a bug.
                        if (x.userId == 0 && x.pkg != null) {
                            val also = otherUsers.filter { Packages.uidForPackage(x.pkg, it.id) >= 0 }
                            if (also.isNotEmpty())
                                SystemLogger.info(
                                    "Scope[$id]: '${x.entry}' is also installed for " +
                                        also.joinToString(", ") { "user ${it.id} ('${it.name}')" } +
                                        " — add '${x.pkg}@<user>' to target that copy too"
                                )
                        }
                    }
                }
                Kind.RAW_UID -> {
                    uids.add(x.uid)
                    if (!quiet)
                        SystemLogger.info("Scope[$id]: raw uid:${x.uid} (user ${x.userId})")
                }
                Kind.INVALID -> {
                    if (quiet) Unit
                    else if (x.pkg != null)
                        SystemLogger.info(
                            "Scope[$id]: '${x.entry}' -> NOT INSTALLED for user ${x.userId} (dropped)"
                        )
                    else SystemLogger.warning("Scope[$id]: '${x.entry}' is not a valid package name, pkg@user or uid:N token (dropped)")
                }
            }
        }

        // Auto-include (future-installs only): a user-app uid (an app id >= FIRST_APP_UID, in any
        // Android user) is folded in ONLY when NONE of its package names was present at the baseline —
        // i.e. the app was installed AFTER TEESimulator first ran — and no OTHER profile claims it and
        // this profile does not already name it. The baseline (known_packages.json, seeded once) is
        // what makes this "new apps only": every app that already existed is by definition in the
        // baseline and never auto-added. The baseline holds bare package names, so a work profile's
        // clone of an app that user 0 already had counts as pre-existing and is NOT auto-added — the
        // safe direction for a rule whose failure mode is applying a keybox where nobody asked.
        val autoUids = LinkedHashSet<Int>()
        if (profile.autoIncludeNewApps) {
            val baseline = baselineKnownPackages()
            // An EMPTY baseline (never seeded, or an empty/corrupt known_packages.json) must NOT be
            // trusted: with it, `app.packages.all { it in baseline }` is false for every app, so
            // auto-include would fold in the whole device and apply the keybox everywhere. Fail safe —
            // add nothing until a real baseline exists (the seed retries on a later resolve).
            if (baseline.isEmpty()) {
                if (!quiet)
                    SystemLogger.warning(
                        "Scope[$id]: auto-include skipped — no package baseline yet (nothing auto-added)"
                    )
            } else {
            val claimedElsewhere = explicitUidsOf(others)
            val mine = explicit.mapNotNull { if (it.uid >= 0) it.uid else null }.toHashSet()
            for (app in Packages.installedAppsByUid()) {
                if (isPrivilegedUid(app.uid)) continue
                if (app.uid in claimedElsewhere) continue
                if (app.uid in mine) continue
                // Every member package known at baseline => pre-existing app, skip. Any member absent from
                // the baseline => installed after it, so this uid is genuinely new and auto-includes.
                if (app.packages.all { it in baseline }) continue
                autoUids.add(app.uid)
            }
            uids.addAll(autoUids)
            if (!quiet)
                SystemLogger.info(
                    "Scope[$id]: auto-include added ${autoUids.size} post-baseline user uid(s)"
                )
            }
        }

        val lowUids = uids.filter { isPrivilegedUid(it) }.toSet()
        if (!quiet)
            for (u in lowUids)
                SystemLogger.warning(
                    "Scope[$id]: WARNING targeting privileged uid $u (app id ${u % Packages.PER_USER_RANGE} " +
                        "< first app uid $FIRST_APP_UID) — this is a system/shell uid (e.g. shell, " +
                        "system_server), not a normal app"
                )

        val invalidCount = explicit.count { it.kind == Kind.INVALID }
        if (!quiet)
            SystemLogger.info(
                "Scope[$id]: effective = ${packageNames.size} package-match name(s), ${uids.size} caller uid(s) " +
                    "${uids.sorted()}, $invalidCount invalid/uninstalled, ${autoUids.size} auto"
            )

        return ProfileScope(
            profileId = id,
            autoInclude = profile.autoIncludeNewApps,
            explicit = explicit,
            autoUids = autoUids,
            packageNames = packageNames,
            packageUsers = packageUsers,
            uids = uids,
            uidPackages = uidPackages,
            lowUids = lowUids,
        )
    }

    /**
     * The resolved truth of the last config push — what the native lib was actually handed. Published
     * once per push by [Resolver] and read by everything else, so a profile is resolved in exactly one
     * place. That matters for cost as much as for coherence: resolving a profile that auto-includes
     * enumerates every installed app through PackageManager, and the read-only aggregators below used
     * to pay that on every call, on whatever thread called them.
     */
    data class Resolved(
        val epoch: Long, // the wire epoch of the push this truth belongs to
        val atMs: Long, // wall clock of the resolve
        val baselineReady: Boolean, // known_packages.json is seeded, so auto-include is armed
        val scopes: List<ProfileScope>,
    )

    @Volatile private var resolved: Resolved? = null

    /** The last published snapshot, or null before the first push has resolved anything. */
    fun lastResolved(): Resolved? = resolved

    /**
     * Publish [scopes] as the resolved truth of the push carrying [epoch]. One immutable object built
     * and stored with a single volatile write, never mutated in place, so a reader on a KeyAdmin
     * connection thread sees either the whole old snapshot or the whole new one and never a torn mix.
     */
    fun publishResolved(epoch: Long, scopes: List<ProfileScope>) {
        val ready = baselineSeeded()
        resolved = Resolved(epoch = epoch, atMs = System.currentTimeMillis(), baselineReady = ready, scopes = scopes)
        val autoTotal = scopes.sumOf { it.autoUids.size }
        SystemLogger.info(
            "Scope: published resolved snapshot epoch=$epoch, ${scopes.size} profile(s), " +
                "$autoTotal auto uid(s) total, baselineReady=$ready"
        )
        for (s in scopes)
            SystemLogger.info(
                "Scope: snapshot[${s.profileId}] ${s.packageNames.size} package(s), ${s.uids.size} uid(s), " +
                    "${s.autoUids.size} auto, autoInclude=${s.autoInclude}"
            )
    }

    /**
     * Is the baseline seeded? Deliberately NON-seeding: it reads the cache only and must never fall
     * through to [baselineKnownPackages]. That function seeds and freezes the baseline on first call,
     * and freezing it from a request thread would fix "which apps count as new" at an arbitrary
     * moment — an HTTP GET would silently decide what auto-include means for the rest of the install.
     */
    private fun baselineSeeded(): Boolean = baselineCache?.isNotEmpty() == true

    /**
     * The scopes to answer read-only questions from. Normally the last published snapshot; a [force]
     * caller (a user-driven refresh) pays for a fresh live resolve instead, and so does anyone asking
     * before the first push has happened — KeyAdmin starts serving before the daemon's first resolve.
     */
    private fun scopesFor(config: ConfigStore.Config, force: Boolean): List<ProfileScope> {
        if (!force) lastResolved()?.let { return it.scopes }
        SystemLogger.info(
            "Scope: ${if (force) "forced" else "no published snapshot yet;"} live resolve of " +
                "${config.profiles.size} profile(s)"
        )
        return config.profiles.map { p -> resolve(p, config.profiles.filter { it.id != p.id }, quiet = true) }
    }

    // The baseline set, cached after the first read/seed. The file is written exactly once (when absent)
    // and never rewritten, so an in-memory cache is safe for the daemon's lifetime.
    @Volatile private var baselineCache: Set<String>? = null

    /**
     * The set of package names that existed when TEESimulator first ran, read from
     * [Const.knownPackagesFile]. Seeds the file — with every currently-installed package name — the first
     * time it is absent, then persists it, so the "future-installs only" auto-include has a fixed frame
     * of reference. Call once at daemon start (before the first resolve) to freeze the baseline at a
     * known moment; later calls reuse the cache / the persisted file.
     *
     * The baseline must be seeded from a REAL package enumeration exactly once. A transient
     * PackageManager failure (empty enumeration) is NEVER persisted or cached — freezing an empty
     * baseline would make `packages.all { it in baseline }` false for every app and auto-include the
     * entire device, the opposite of "future-installs only". An empty seed therefore returns empty for
     * this call WITHOUT writing the file, so the very next call retries and seeds properly once
     * PackageManager answers. A genuinely-present baseline file (even if it read back empty because the
     * device really had nothing) is honoured; only the seed path guards against the transient case.
     *
     * A version-1 file was written before the daemon could see past user 0, so it lists that user's
     * packages only. Left as it was, every app that lives solely in a work profile would read as
     * "installed after the baseline" and an auto-include profile would swallow the whole profile at
     * once on the first run after an update. Such a file is therefore topped up once — with the
     * packages of every user — and rewritten as version 2.
     */
    private const val BASELINE_VERSION = 2

    fun baselineKnownPackages(): Set<String> {
        baselineCache?.let {
            return it
        }
        val f = Const.knownPackagesFile
        if (f.exists()) {
            var version = BASELINE_VERSION
            val set =
                try {
                    val root = JSONObject(f.readText())
                    version = root.optInt("version", 1)
                    val arr = root.optJSONArray("packages") ?: JSONArray()
                    (0 until arr.length()).mapTo(HashSet()) { arr.getString(it) }
                } catch (e: Exception) {
                    // A corrupt baseline file is a hard problem retrying can't fix, but caching an empty
                    // set here would auto-include everything — so return empty WITHOUT caching and let a
                    // later call try again (a user can also delete the file to force a fresh seed).
                    SystemLogger.warning("Scope: known_packages.json unreadable; not caching empty baseline", e)
                    return emptySet()
                }
            // An EMPTY existing baseline (truncated write, hand-edit) is never cached and falls through
            // to a reseed below — auto-include is disabled (resolve() guards on empty) until a real set
            // is written, rather than freezing "everything is new".
            if (set.isNotEmpty() && version >= BASELINE_VERSION) {
                baselineCache = set
                return set
            }
            if (set.isNotEmpty()) {
                // Pre-multi-user baseline: fold today's every-user enumeration in. An enumeration that
                // comes back empty is the same transient failure the seed path guards against, so the
                // old set is returned UNCACHED and the top-up retries on the next call. Nothing is
                // auto-included meanwhile: resolve() walks the very enumeration that just failed.
                val live = Packages.allInstalledPackageNames()
                if (live.isEmpty()) {
                    SystemLogger.warning(
                        "Scope: package enumeration empty; deferring the known_packages.json v$version -> " +
                            "v$BASELINE_VERSION top-up (will retry)"
                    )
                    return set
                }
                val merged = HashSet(set).apply { addAll(live) }
                SystemLogger.info(
                    "Scope: topped up the v$version baseline with every user's packages — " +
                        "${set.size} -> ${merged.size} package(s)"
                )
                writeBaseline(f, merged)
                baselineCache = merged
                return merged
            }
            SystemLogger.warning("Scope: known_packages.json is empty; reseeding from a live enumeration")
        }
        // No baseline yet: seed from a live enumeration. If it comes back empty, treat it as a transient
        // failure — do not write or cache — so the baseline is only ever frozen from a real package set.
        val seeded = Packages.allInstalledPackageNames()
        if (seeded.isEmpty()) {
            SystemLogger.warning("Scope: package enumeration empty; deferring known_packages.json seed (will retry)")
            return emptySet()
        }
        SystemLogger.info("Scope: seeding known_packages.json baseline with ${seeded.size} package(s)")
        writeBaseline(f, seeded)
        baselineCache = seeded
        return seeded
    }

    /** Persist the baseline through a temp file and a rename, so a kill mid-write cannot truncate it
     *  into the "empty baseline" case above. A failure is logged, not thrown: the in-memory set still
     *  holds for this run, and the next start seeds again. */
    private fun writeBaseline(f: File, packages: Set<String>) {
        try {
            val root =
                JSONObject().put("version", BASELINE_VERSION).put("packages", JSONArray(packages.sorted()))
            f.parentFile?.mkdirs()
            val tmp = File(f.parentFile, "${f.name}.tmp")
            tmp.writeText(root.toString())
            if (!tmp.renameTo(f)) {
                f.writeText(root.toString())
                tmp.delete()
            }
            SystemLogger.info("Scope: wrote known_packages.json (v$BASELINE_VERSION, ${packages.size} package(s))")
        } catch (e: Exception) {
            SystemLogger.warning("Scope: failed to write known_packages.json", e)
        }
    }

    /** The set of explicit caller uids (installed packages + `uid:N` tokens) named across [profiles]. */
    private fun explicitUidsOf(profiles: List<ConfigStore.ProfileConfig>): Set<Int> {
        val s = HashSet<Int>()
        for (p in profiles) for (entry in p.apps) {
            val x = parse(entry)
            if (x.uid >= 0) s.add(x.uid)
        }
        return s
    }

    /** Every effective target uid across the whole config (union of each profile's wire uids[]). */
    fun allTargetUids(config: ConfigStore.Config, force: Boolean = false): Set<Int> {
        val all = LinkedHashSet<Int>()
        for (s in scopesFor(config, force)) all.addAll(s.uids)
        return all
    }

    /**
     * uid -> owning profile id across the config. The one-profile-per-package/uid rule makes real
     * collisions a validation error, so last-writer-wins here is only ever exercised by auto-include
     * overlap, which validation already forbids (at most one auto profile).
     */
    fun uidToProfile(config: ConfigStore.Config, force: Boolean = false): Map<Int, String> {
        val map = HashMap<Int, String>()
        for (s in scopesFor(config, force)) for (u in s.uids) map[u] = s.profileId
        return map
    }

    /**
     * uid -> a representative app name for the WebUI's stored-keys view. A resolved package entry maps
     * to the entry as written — so a secondary user's app keeps its `pkg@user` spelling and cannot be
     * mistaken for the primary user's copy; a raw or auto-included uid has no package, so it maps to
     * its `uid:N` token so the UI still shows something recognisable. Package entries win over tokens
     * on the same uid.
     */
    fun uidToPackage(config: ConfigStore.Config, force: Boolean = false): Map<Int, String> {
        val map = HashMap<Int, String>()
        for (scope in scopesFor(config, force)) {
            for (x in scope.explicit) if (x.kind == Kind.PACKAGE && x.pkg != null) map[x.uid] = x.entry
            for (u in scope.uids) if (u !in map) map[u] = "uid:$u"
        }
        return map
    }
}
