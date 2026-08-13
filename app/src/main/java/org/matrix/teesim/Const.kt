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

    /** Persistent per-package key-request frequency memory (Scope picker usage stats). Keyed by package name
     *  because a uid can change across reinstalls; accumulated across boots from per-poll lib deltas. */
    val usageFile = File(DATA_DIR, "usage.json")

    /** keystore's uid; the control socket only sends the keybox once the peer is it. */
    const val AID_KEYSTORE = 1017

    /** Abstract control socket the interceptor library binds (`\0teesim`). */
    const val CONTROL_SOCKET = "teesim"

    /** Loopback port the WebUI reaches KeyAdmin on. */
    const val ADMIN_PORT = 8790

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
