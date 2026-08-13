package org.matrix.teesim

/**
 * The one place that turns a profile's `apps[]` list into the two wire arrays the native router
 * matches against — `packages[]` (attestation package-name match, primary) and `uids[]` (caller-uid
 * match, fallback) — plus the derived sets the WebUI and re-attest paths need. Resolver, ReAttest
 * and KeyAdmin all go through here so uid resolution, the raw-`uid:N` syntax and the low-uid
 * warnings live once, not copied three ways with drift between them.
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
     * Resolve one profile against the live device.
     *
     * [quiet] suppresses the per-entry / low-uid / summary logging. The authoritative, verbose
     * resolution log belongs to the ONE write path that actually pushes config (Resolver); the
     * read-only aggregators below ([allTargetUids], [uidToProfile], [uidToPackage]) — some driven by
     * a WebUI endpoint that may be polled — re-derive the same uids and would otherwise re-emit every
     * line (and re-warn about every privileged uid) on each call, so they resolve quietly.
     */
    fun resolve(
        profile: ConfigStore.ProfileConfig,
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
                    "${uids.sorted()}, $invalidCount invalid/uninstalled"
            )

        return ProfileScope(
            profileId = id,
            explicit = explicit,
            packageNames = packageNames,
            uids = uids,
            lowUids = lowUids,
        )
    }

    /** Every effective target uid across the whole config (union of each profile's wire uids[]). */
    fun allTargetUids(config: ConfigStore.Config): Set<Int> {
        val all = LinkedHashSet<Int>()
        for (p in config.profiles) all.addAll(resolve(p, quiet = true).uids)
        return all
    }

    /**
     * uid -> owning profile id across the config. Validation rejects a package or uid claimed by two
     * profiles, so every uid here has exactly one owner and the last-writer-wins never actually fires.
     */
    fun uidToProfile(config: ConfigStore.Config): Map<Int, String> {
        val map = HashMap<Int, String>()
        for (p in config.profiles) for (u in resolve(p, quiet = true).uids) map[u] = p.id
        return map
    }

    /**
     * uid -> a representative package name for the WebUI's stored-keys view. A resolved package entry
     * maps to its name; a raw `uid:N` token has no package, so it maps to the token itself so the UI
     * still shows something recognisable. Package names win over tokens on the same uid.
     */
    fun uidToPackage(config: ConfigStore.Config): Map<Int, String> {
        val map = HashMap<Int, String>()
        for (p in config.profiles) {
            val scope = resolve(p, quiet = true)
            for (x in scope.explicit) if (x.kind == Kind.PACKAGE && x.pkg != null) map[x.uid] = x.pkg
            for (u in scope.uids) if (u !in map) map[u] = "uid:$u"
        }
        return map
    }
}
