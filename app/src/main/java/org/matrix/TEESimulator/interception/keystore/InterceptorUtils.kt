package org.matrix.TEESimulator.interception.keystore

import android.os.Parcel
import android.os.Parcelable
import android.security.KeyStore
import java.security.MessageDigest
import java.security.cert.Certificate
import java.util.Base64
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

    /** Creates an `OverrideReply` parcel that indicates success with no data. */
    fun createSuccessReply(): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeInt(KeyStore.NO_ERROR)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(0, parcel)
    }

    /** Creates an `OverrideReply` parcel containing a raw byte array. */
    fun createByteArrayReply(data: ByteArray): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeByteArray(data)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(KeyStore.NO_ERROR, parcel)
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
        return BinderInterceptor.TransactionResult.OverrideReply(0, parcel)
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

    /**
     * Generates a URL-safe SHA-256 fingerprint of a certificate's public key. Used to uniquely
     * identify keys imported by the user.
     */
    fun getPublicKeyFingerprint(chain: Array<Certificate>?): String? {
        if (chain.isNullOrEmpty()) return null
        return try {
            val publicKeyBytes = chain[0].publicKey.encoded
            val hashBytes = MessageDigest.getInstance("SHA-256").digest(publicKeyBytes)
            Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes)
        } catch (e: Exception) {
            SystemLogger.error("Failed to create public key fingerprint.", e)
            null
        }
    }
}
