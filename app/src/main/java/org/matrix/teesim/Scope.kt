package org.matrix.teesim

import java.io.File
import org.json.JSONArray
import org.json.JSONObject

/**
 * The one place that turns a profile's `apps[]` list into the two wire arrays the native router
 * matches against — `packages[]` (attestation package-name match, primary) and `uids[]` (caller-uid
 * match, fallback) — plus the derived sets the WebUI and re-attest paths need. Resolver, ReAttest
 * and KeyAdmin all go through here so uid resolution, the raw-`uid:N` syntax, the auto-include
 * expansion and the low-uid warnings live once, not copied three ways with drift between them.
 *
 * An `apps[]` entry is one of three shapes (see [parse]): a plain package name, an advanced
 * `uid:N` token that targets a caller uid directly, or something malformed. A package name is kept
 * on the wire verbatim even when the app is not installed yet, because a later install still
 * name-matches; a uid is only ever pushed when it actually resolves (never -1).
 */
object Scope {

    // android.os.Process.FIRST_APPLICATION_UID. A const avoids importing Process into every caller
    // (and works in unit reasoning), but it is the same 10000 the platform uses for the app range.
    const val FIRST_APP_UID = 10000

    enum class Kind {
        /** A package name that is currently installed; [Explicit.uid] is its resolved app uid. */
        PACKAGE,
        /** An advanced `uid:N` token; [Explicit.uid] is N, [Explicit.pkg] is null. */
        RAW_UID,
        /** A package-shaped name that is not installed (uid -1, but [Explicit.pkg] is kept), or a
         *  genuinely malformed entry (uid -1, [Explicit.pkg] null). */
        INVALID,
    }

    /**
     * One resolved `apps[]` entry, in the same order as written. [pkg] is non-null for anything
     * package-shaped (installed or not) and null for a `uid:N` token or a malformed entry — which is
     * exactly the "is this a wire package name?" test [ProfileScope.packageNames] uses.
     */
    data class Explicit(val entry: String, val kind: Kind, val uid: Int, val pkg: String?)

    /** The fully resolved scope of one profile against the live device. */
    data class ProfileScope(
        val profileId: String,
        val explicit: List<Explicit>, // one per apps[] entry, in order
        val autoUids: Set<Int>, // extra uids contributed by autoIncludeNewApps
        val packageNames: List<String>, // wire packages[]: every package-shaped entry, verbatim
        val uids: Set<Int>, // wire uids[]: effective caller uids, never containing -1
        val lowUids: Set<Int>, // effective uids below FIRST_APP_UID, for the privileged-uid warning
    )

    /** Classify a single `apps[]` entry. Never throws — a malformed entry becomes [Kind.INVALID]. */
    fun parse(entry: String): Explicit {
        val e = entry.trim()
        if (e.startsWith("uid:")) {
            val digits = e.substring(4)
            val n = if (digits.isNotEmpty() && digits.all { it.isDigit() }) digits.toIntOrNull() else null
            return if (n != null) Explicit(e, Kind.RAW_UID, n, null)
            else Explicit(e, Kind.INVALID, -1, null)
        }
        if (e.isNotEmpty() && e.all { it.isLetterOrDigit() || it == '_' || it == '.' }) {
            val uid = Packages.uidForPackage(e)
            // Package-shaped: PACKAGE when installed, INVALID (but pkg kept) when not — the name still
            // rides the wire so a later install name-matches, yet contributes no uid until it resolves.
            return if (uid >= 0) Explicit(e, Kind.PACKAGE, uid, e)
            else Explicit(e, Kind.INVALID, -1, e)
        }
        return Explicit(e, Kind.INVALID, -1, null)
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
        val uids = LinkedHashSet<Int>()
        for (x in explicit) {
            if (x.pkg != null) packageNames.add(x.pkg)
            when (x.kind) {
                Kind.PACKAGE -> {
                    uids.add(x.uid)
                    if (!quiet) SystemLogger.info("Scope[$id]: '${x.entry}' -> uid ${x.uid}")
                }
                Kind.RAW_UID -> {
                    uids.add(x.uid)
                    if (!quiet) SystemLogger.info("Scope[$id]: raw uid:${x.uid}")
                }
                Kind.INVALID -> {
                    if (quiet) Unit
                    else if (x.pkg != null)
                        SystemLogger.info("Scope[$id]: '${x.entry}' -> NOT INSTALLED (dropped)")
                    else SystemLogger.warning("Scope[$id]: '${x.entry}' is not a valid package name or uid:N token (dropped)")
                }
            }
        }

        // Auto-include (v2, future-installs only): a user-app uid (>= FIRST_APP_UID) is folded in ONLY
        // when NONE of its package names was present at the baseline — i.e. the app was installed AFTER
        // TEESimulator first ran — and no OTHER profile claims it and this profile does not already name
        // it. The baseline (known_packages.json, seeded once) is what makes this "new apps only": every
        // app that already existed is by definition in the baseline and never auto-added.
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
                if (app.uid < FIRST_APP_UID) continue
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

        val lowUids = uids.filter { it < FIRST_APP_UID }.toSet()
        if (!quiet)
            for (u in lowUids)
                SystemLogger.warning(
                    "Scope[$id]: WARNING targeting privileged uid $u (< first app uid $FIRST_APP_UID) — " +
                        "this is a system/shell uid (e.g. shell, system_server), not a normal app"
                )

        val invalidCount = explicit.count { it.kind == Kind.INVALID }
        if (!quiet)
            SystemLogger.info(
                "Scope[$id]: effective = ${packageNames.size} package-match name(s), ${uids.size} caller uid(s) " +
                    "${uids.sorted()}, $invalidCount invalid/uninstalled, ${autoUids.size} auto"
            )

        return ProfileScope(
            profileId = id,
            explicit = explicit,
            autoUids = autoUids,
            packageNames = packageNames,
            uids = uids,
            lowUids = lowUids,
        )
    }

    // The baseline set, cached after the first read/seed. The file is written exactly once (when absent)
    // and never rewritten, so an in-memory cache is safe for the daemon's lifetime.
    @Volatile private var baselineCache: Set<String>? = null

    /**
     * The set of package names that existed when TEESimulator first ran (spec C6), read from
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
     */
    fun baselineKnownPackages(): Set<String> {
        baselineCache?.let {
            return it
        }
        val f = Const.knownPackagesFile
        if (f.exists()) {
            val set =
                try {
                    val arr = JSONObject(f.readText()).optJSONArray("packages") ?: JSONArray()
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
            if (set.isNotEmpty()) {
                baselineCache = set
                return set
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
        try {
            val root = JSONObject().put("version", 1).put("packages", JSONArray(seeded.sorted()))
            f.parentFile?.mkdirs()
            val tmp = File(f.parentFile, "${f.name}.tmp")
            tmp.writeText(root.toString())
            if (!tmp.renameTo(f)) {
                f.writeText(root.toString())
                tmp.delete()
            }
            SystemLogger.info("Scope: seeded known_packages.json baseline with ${seeded.size} package(s)")
        } catch (e: Exception) {
            SystemLogger.warning("Scope: failed to seed known_packages.json", e)
        }
        baselineCache = seeded
        return seeded
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
    fun allTargetUids(config: ConfigStore.Config): Set<Int> {
        val all = LinkedHashSet<Int>()
        for (p in config.profiles)
            all.addAll(resolve(p, config.profiles.filter { it.id != p.id }, quiet = true).uids)
        return all
    }

    /**
     * uid -> owning profile id across the config. The one-profile-per-package/uid rule makes real
     * collisions a validation error, so last-writer-wins here is only ever exercised by auto-include
     * overlap, which validation already forbids (at most one auto profile).
     */
    fun uidToProfile(config: ConfigStore.Config): Map<Int, String> {
        val map = HashMap<Int, String>()
        for (p in config.profiles)
            for (u in resolve(p, config.profiles.filter { it.id != p.id }, quiet = true).uids) map[u] = p.id
        return map
    }

    /**
     * uid -> a representative package name for the WebUI's stored-keys view. A resolved package entry
     * maps to its name; a raw or auto-included uid has no package, so it maps to its `uid:N` token so
     * the UI still shows something recognisable. Package names win over tokens on the same uid.
     */
    fun uidToPackage(config: ConfigStore.Config): Map<Int, String> {
        val map = HashMap<Int, String>()
        for (p in config.profiles) {
            val scope = resolve(p, config.profiles.filter { it.id != p.id }, quiet = true)
            for (x in scope.explicit) if (x.kind == Kind.PACKAGE && x.pkg != null) map[x.uid] = x.pkg
            for (u in scope.uids) if (u !in map) map[u] = "uid:$u"
        }
        return map
    }
}
