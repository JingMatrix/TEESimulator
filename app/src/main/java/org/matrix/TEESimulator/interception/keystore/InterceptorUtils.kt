package org.matrix.TEESimulator.interception.keystore

import android.os.Parcel
import android.os.Parcelable
import android.security.KeyStore
import android.security.keystore.KeystoreResponse
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

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

    /** Creates an `KeystoreResponse` parcel that indicates success with no data. */
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
     * Extracts the true key alias from the keystore-prefixed string (e.g., "user_cert_my-alias" ->
     * "my-alias").
     */
    fun extractAlias(prefixedAlias: String): String {
        val underscoreIndex = prefixedAlias.indexOf('_')
        val secondUnderscoreIndex = prefixedAlias.indexOf('_', underscoreIndex + 1)
        return if (secondUnderscoreIndex != -1) {
            prefixedAlias.substring(secondUnderscoreIndex + 1)
        } else {
            prefixedAlias
        }
    }

    /** Checks if a reply parcel contains an exception without consuming it. */
    fun hasException(reply: Parcel): Boolean {
        return runCatching { reply.readException() }.exceptionOrNull() != null
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

    /**
     * Merges hardware and software key descriptors into a single sorted array. Uses TreeMap to
     * ensure alphabetical ordering and avoid duplicates.
     */
    fun mergeKeyDescriptors(
        hardwareKeys: Array<android.system.keystore2.KeyDescriptor>,
        softwareKeys: List<android.system.keystore2.KeyDescriptor>,
    ): Array<android.system.keystore2.KeyDescriptor> {
        val combinedMap = java.util.TreeMap<String, android.system.keystore2.KeyDescriptor>()

        hardwareKeys.forEach { key -> key.alias?.let { combinedMap[it] = key } }

        softwareKeys.forEach { key -> key.alias?.let { combinedMap[it] = key } }

        return combinedMap.values.toTypedArray()
    }

    /**
     * Resets a Parcel to the beginning and enforces the interface descriptor. This is a common
     * pattern when reading transaction parameters.
     */
    fun resetParcelForReading(parcel: Parcel, descriptor: String) {
        parcel.setDataPosition(0)
        parcel.enforceInterface(descriptor)
    }
}
