package org.matrix.TEESimulator.interception.keystore

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.os.Parcel
import android.os.Parcelable
import android.security.KeyStore
import android.security.keystore.KeystoreResponse
import android.system.keystore2.Authorization
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.AndroidDeviceUtils

data class KeyIdentifier(val uid: Int, val alias: String)

/** A collection of utility functions to support binder interception. */
object InterceptorUtils {

    /**
     * Uses reflection to get the integer transaction code for a given method name from a Stub
     * class. This is necessary for older Android versions where codes are not public constants.
     */
    fun getTransactCode(clazz: Class<*>, method: String): Int {
        return try {
            clazz.getDeclaredField("TRANSACTION_$method").apply { isAccessible = true }.getInt(null)
        } catch (e: Exception) {
            SystemLogger.error(
                "Failed to get transaction code for method '$method' in class '${clazz.simpleName}'.",
                e,
            )
            -1 // Return an invalid code
        }
    }

    fun createSuccessKeystoreResponse(): KeystoreResponse {
        val parcel = Parcel.obtain()
        try {
            parcel.writeInt(KeyStore.NO_ERROR)
            parcel.writeString("")
            parcel.setDataPosition(0)
            return KeystoreResponse.CREATOR.createFromParcel(parcel)
        } finally {
            parcel.recycle()
        }
    }

    fun patchAuthorizations(
        authorizations: Array<Authorization>?,
        callingUid: Int,
    ): Array<Authorization>? {
        if (authorizations == null) return null
        val osPatch = AndroidDeviceUtils.getPatchLevel(callingUid)
        val vendorPatch = AndroidDeviceUtils.getVendorPatchLevelLong(callingUid)
        val bootPatch = AndroidDeviceUtils.getBootPatchLevelLong(callingUid)

        return authorizations
            .mapNotNull { auth ->
                val replacement =
                    when (auth.keyParameter.tag) {
                        Tag.OS_PATCHLEVEL -> osPatch
                        Tag.VENDOR_PATCHLEVEL -> vendorPatch
                        Tag.BOOT_PATCHLEVEL -> bootPatch
                        else -> return@mapNotNull auth
                    }
                if (replacement == AndroidDeviceUtils.DO_NOT_REPORT) {
                    null
                } else {
                    Authorization().apply {
                        securityLevel = auth.securityLevel
                        keyParameter =
                            KeyParameter().apply {
                                tag = auth.keyParameter.tag
                                value = KeyParameterValue.integer(replacement)
                            }
                    }
                }
            }
            .toTypedArray()
    }

    /** Creates an `OverrideReply` parcel that indicates success with no data. */
    fun createSuccessReply(
        writeResultCode: Boolean = true
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                if (writeResultCode) {
                    writeInt(KeyStore.NO_ERROR)
                }
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /** Creates an `OverrideReply` parcel containing a raw byte array. */
    fun createByteArrayReply(data: ByteArray): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeByteArray(data)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /** Creates an `OverrideReply` parcel containing a typed array. */
    fun <T : Parcelable> createTypedArrayReply(
        array: Array<T>,
        flags: Int = 0,
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeTypedArray(array, flags)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /** Creates an `OverrideReply` parcel containing a Parcelable object. */
    fun <T : Parcelable?> createTypedObjectReply(
        obj: T,
        flags: Int = 0,
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeTypedObject(obj, flags)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /**
     * Creates an `OverrideReply` that writes a `ServiceSpecificException` with the given error
     * code. Uses the C++ binder::Status wire format which includes a remote stack trace header
     * between the message and the error code. Java's Parcel.writeException omits this header,
     * making it incompatible with native C++ AIDL clients on Android 12+.
     *
     * Wire format: [int32 exceptionCode] [String16 message] [int32 stackTraceSize=0] [int32
     * errorCode]
     */
    fun createServiceSpecificErrorReply(
        errorCode: Int
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeInt(-8) // EX_SERVICE_SPECIFIC
                writeString(null) // message (null → writeInt(-1) as String16 null marker)
                writeInt(0) // remote stack trace header size (empty)
                writeInt(errorCode) // service-specific error code
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /**
     * Extracts the base alias from a potentially prefixed alias string. For example, it converts
     * "USRCERT_my_key" to "my_key".
     */
    fun extractAlias(prefixedAlias: String): String {
        val underscoreIndex = prefixedAlias.indexOf('_')
        return if (underscoreIndex != -1) {
            // Return the part of the string after the first underscore.
            prefixedAlias.substring(underscoreIndex + 1)
        } else {
            // If there's no underscore, return the original string.
            prefixedAlias
        }
    }

    /** Checks if a reply parcel contains an exception without consuming it. */
    fun hasException(reply: Parcel): Boolean {
        val pos = reply.dataPosition()
        return try {
            reply.readException()
            false
        } catch (_: Exception) {
            reply.setDataPosition(pos)
            true
        }
    }
}
