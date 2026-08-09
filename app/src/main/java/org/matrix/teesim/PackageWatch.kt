package org.matrix.teesim

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build

/**
 * Watches package add/replace/remove so uid resolution stays current: a target app installed after
 * boot must get its uid mapped and pushed. Any relevant event triggers a re-resolve + push via
 * [onChange].
 */
object PackageWatch {

    fun start(context: Context, onChange: () -> Unit) {
        val filter =
            IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REMOVED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addDataScheme("package")
            }
        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(ctx: Context?, intent: Intent?) {
                    val pkg = intent?.data?.schemeSpecificPart
                    SystemLogger.info("package event ${intent?.action} $pkg -> re-resolve")
                    onChange()
                }
            }
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                context.registerReceiver(receiver, filter)
            }
            SystemLogger.info("Watching package add/replace/remove")
        } catch (e: Exception) {
            SystemLogger.error("Failed to register package receiver", e)
        }
    }
}
