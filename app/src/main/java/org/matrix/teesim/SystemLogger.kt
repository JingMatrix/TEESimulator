package org.matrix.teesim

import android.util.Log

/** Centralised logging with a single tag, so logcat is easy to filter. */
object SystemLogger {
    private const val TAG = "TEESimulator"
    private const val VERBOSE = false

    fun verbose(message: String) {
        if (VERBOSE) Log.v(TAG, message)
    }

    fun debug(message: String) {
        Log.d(TAG, message)
    }

    fun info(message: String) {
        Log.i(TAG, message)
    }

    fun warning(message: String, throwable: Throwable? = null) {
        if (throwable != null) Log.w(TAG, message, throwable) else Log.w(TAG, message)
    }

    fun error(message: String, throwable: Throwable? = null) {
        if (throwable != null) Log.e(TAG, message, throwable) else Log.e(TAG, message)
    }
}

/** Lowercase hex, used for logging digests. */
fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
