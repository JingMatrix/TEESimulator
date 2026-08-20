package org.matrix.teesim

import java.io.File

/** Well-known paths and identifiers shared across the daemon. */
object Const {
    /** The daemon-owned configuration/state directory. */
    const val DATA_DIR = "/data/adb/teesim"

    val configFile = File(DATA_DIR, "config.json")
    val harvestedFile = File(DATA_DIR, "harvested.json")
    /** User edits to the harvest override layer (device ids, synthesized levels, an all-zero boot key).
     *  Written by the WebUI, merged over the frozen captured harvest on every push. */
    val overridesFile = File(DATA_DIR, "overrides.json")
    val adminTokenFile = File(DATA_DIR, "admin.token")

    /** Filesystem unix socket the WebUI reaches KeyAdmin on, in the root-only [DATA_DIR] (0700). Unlike a
     *  loopback TCP port — which any app uid can connect() to and thereby fingerprint — the kernel
     *  refuses a connect() here from any non-root caller, so the endpoint is invisible to other apps.
     *  The WebUI's WebView can't reach a unix socket directly; it goes through the root-exec bridge and
     *  the shipped `teesim-uds` client. */
    val adminSocketFile = File(DATA_DIR, "admin.sock")

    /** Persistent per-package key-request frequency memory (Scope picker usage stats). Keyed by package name
     *  because a uid can change across reinstalls; accumulated across boots from per-poll lib deltas. */
    val usageFile = File(DATA_DIR, "usage.json")

    /** The baseline set of package names present when TEESimulator first ran on this device. Seeded once
     *  (when absent) and never rewritten, so auto-include can add only packages installed AFTER it. */
    val knownPackagesFile = File(DATA_DIR, "known_packages.json")

    /** keystore's uid; the control socket only sends the keybox once the peer is it. Named after AOSP's
     *  own AID_KEYSTORE (android_filesystem_config.h) and mirrored here because the framework's
     *  Process.KEYSTORE_UID is @hide — the public SDK exposes only ROOT/SYSTEM/PHONE/SHELL and the
     *  application-uid bounds. */
    const val AID_KEYSTORE = 1017

    /** Filesystem control socket the interceptor library binds, inside keystore's own 0700 data dir
     *  (keystore_data_file). A path under a directory apps cannot traverse gives a uniform EACCES on
     *  connect() whether or not it exists — no existence oracle — unlike an abstract name, which any app
     *  can probe. The daemon (root) connects to it; keystore binds it because it owns the directory. */
    const val CONTROL_SOCKET_PATH = "/data/misc/keystore/.teesim-ctl"

    /** Security-level encodings shared with the native side and the wire protocol. */
    const val SECLEVEL_SOFTWARE = 0
    const val SECLEVEL_TEE = 1
    const val SECLEVEL_STRONGBOX = 2

    fun securityLevelName(level: Int): String =
        when (level) {
            SECLEVEL_SOFTWARE -> "Software"
            SECLEVEL_STRONGBOX -> "StrongBox"
            else -> "TrustedEnvironment"
        }
}
