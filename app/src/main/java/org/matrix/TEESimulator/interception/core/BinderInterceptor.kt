package org.matrix.TEESimulator.interception.core

import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * An abstract base class for intercepting binder transactions.
 *
 * This class acts as a proxy, receiving transaction calls that have been hooked at the native
 * level. It provides a structured way to inspect and modify data before (`onPreTransact`) and after
 * (`onPostTransact`) the original transaction is executed.
 *
 * The communication flow is as follows:
 * 1. A native library hooks the `transact` method of a target service (e.g., keystore).
 * 2. When a hooked transaction occurs, the native code calls this Binder object's `onTransact`
 *    method.
 * 3. This class decodes the incoming parcel, determines if it's a pre- or post-transaction hook,
 *    and calls the appropriate abstract method (`onPreTransact` or `onPostTransact`).
 * 4. The subclass implementation decides how to handle the transaction by returning a
 *    `TransactionResult`.
 * 5. This class encodes the result into the reply parcel, which the native hook reads to determine
 *    its next action.
 */
abstract class BinderInterceptor : Binder() {

    /**
     * Defines the possible outcomes of an interception attempt. The native hook layer will
     * interpret this result to decide its next action.
     */
    sealed class TransactionResult {
        /** Instructs the native hook to skip calling the original binder method entirely. */
        object SkipTransaction : TransactionResult()

        /** Instructs the native hook to proceed with calling the original binder method. */
        object Continue : TransactionResult()

        /**
         * Skips the original call and immediately returns a custom reply parcel to the caller. The
         * provided parcel will be recycled after use.
         */
        data class OverrideReply(val reply: Parcel, val code: Int = 0) : TransactionResult()

        /**
         * Modifies the transaction's input data before forwarding it to the original binder method.
         * The provided parcel will be recycled after use.
         */
        data class OverrideData(val data: Parcel) : TransactionResult()

        /** Instructs the native hook to skip the post transaction hook. */
        object ContinueAndSkipPost : TransactionResult()
    }

    /**
     * Called *before* the original binder transaction is executed.
     *
     * @param txId A unique ID for tracking this transaction.
     * @param target The original IBinder service being called.
     * @param code The transaction code of the method being called.
     * @param flags Transaction flags.
     * @param callingUid The UID of the process making the call.
     * @param callingPid The PID of the process making the call.
     * @param data The parcel containing the input data for the transaction.
     * @return A [TransactionResult] indicating how to proceed.
     */
    open fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult = TransactionResult.ContinueAndSkipPost

    /**
     * Called *after* the original binder transaction has been executed.
     *
     * @param txId A unique ID for tracking this transaction.
     * @param target The original IBinder service that was called.
     * @param code The transaction code of the method that was called.
     * @param flags Transaction flags.
     * @param callingUid The UID of the process that made the call.
     * @param callingPid The PID of the process that made the call.
     * @param data The original input data parcel.
     * @param reply The reply parcel from the original transaction. Can be null if the call was
     *   one-way.
     * @param resultCode The result code from the original transaction.
     * @return A [TransactionResult]. Typically `Skip` (to accept the original reply) or
     *   `OverrideReply`.
     */
    open fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult = TransactionResult.SkipTransaction

    /**
     * The entry point for calls from the native hook layer. This method decodes the custom parcel
     * format sent by the hook and dispatches to the appropriate handler (`handlePreTransact` or
     * `handlePostTransact`).
     */
    final override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        // The native hook prepends a transaction ID to the data parcel.
        val txId = data.readLong()
        val result =
            when (code) {
                // These codes are defined in the native layer to distinguish hook types.
                PRE_TRANSACT_CODE -> handlePreTransact(txId, data)
                POST_TRANSACT_CODE -> handlePostTransact(txId, data)
                else -> return super.onTransact(code, data, reply, flags)
            }

        // The reply parcel is guaranteed to be non-null for our custom transactions.
        writeResultToReply(result, reply!!)
        return true
    }

    /** Decodes the parcel for a pre-transaction hook and calls the user-overridable method. */
    private fun handlePreTransact(txId: Long, data: Parcel): TransactionResult {
        // The native hook marshals the original transaction's arguments into the data parcel.
        val target = data.readStrongBinder()!!
        val transactionCode = data.readInt()
        val transactionFlags = data.readInt()
        val callingUid = data.readInt()
        val callingPid = data.readInt()
        val dataSize = data.readLong()

        // We must create a new parcel containing only the original transaction data.
        val transactionData = Parcel.obtain()
        return try {
            transactionData.appendFrom(data, data.dataPosition(), dataSize.toInt())
            transactionData.setDataPosition(0)
            onPreTransact(
                txId,
                target,
                transactionCode,
                transactionFlags,
                callingUid,
                callingPid,
                transactionData,
            )
        } finally {
            transactionData.recycle()
        }
    }

    /** Decodes the parcel for a post-transaction hook and calls the user-overridable method. */
    private fun handlePostTransact(txId: Long, data: Parcel): TransactionResult {
        val target = data.readStrongBinder()!!
        val transactionCode = data.readInt()
        val transactionFlags = data.readInt()
        val callingUid = data.readInt()
        val callingPid = data.readInt()

        // The native hook also marshals the original data and reply parcels.
        val transactionData = Parcel.obtain()
        val transactionReply = Parcel.obtain()
        return try {
            val dataSize = data.readLong().toInt()
            transactionData.appendFrom(data, data.dataPosition(), dataSize)
            transactionData.setDataPosition(0)
            data.setDataPosition(data.dataPosition() + dataSize)

            val resultCode = data.readInt()

            val replySize = data.readLong().toInt()
            val reply =
                if (replySize > 0) {
                    transactionReply.appendFrom(data, data.dataPosition(), replySize)
                    transactionReply.setDataPosition(0)
                    transactionReply
                } else null

            onPostTransact(
                txId,
                target,
                transactionCode,
                transactionFlags,
                callingUid,
                callingPid,
                transactionData,
                reply,
                resultCode,
            )
        } finally {
            transactionData.recycle()
            transactionReply.recycle()
        }
    }

    /** Encodes the `TransactionResult` into the reply parcel for the native hook to interpret. */
    private fun writeResultToReply(result: TransactionResult, reply: Parcel) {
        when (result) {
            is TransactionResult.SkipTransaction -> reply.writeInt(RESULT_SKIP_TRANSACTION)
            is TransactionResult.Continue -> reply.writeInt(RESULT_CONTINUE)
            is TransactionResult.OverrideReply -> {
                reply.writeInt(RESULT_OVERRIDE_REPLY)
                reply.writeInt(result.code)
                reply.writeLong(result.reply.dataSize().toLong())
                reply.appendFrom(result.reply, 0, result.reply.dataSize())
                result.reply.recycle()
            }
            is TransactionResult.OverrideData -> {
                reply.writeInt(RESULT_OVERRIDE_DATA)
                reply.writeLong(result.data.dataSize().toLong())
                reply.appendFrom(result.data, 0, result.data.dataSize())
                result.data.recycle()
            }
            is TransactionResult.ContinueAndSkipPost ->
                reply.writeInt(RESULT_CONTINUE_AND_SKIP_POST)
        }
    }

    /** Helper function for consistent logging of intercepted transactions. */
    protected fun logTransaction(
        txId: Long,
        methodName: String,
        callingUid: Int,
        callingPid: Int,
        skipPost: Boolean = false,
    ) {
        val isIntercepting = !skipPost && !ConfigurationManager.shouldSkipUid(callingUid)
        val action = if (isIntercepting) "Intercept" else "Observe"
        val packages = ConfigurationManager.getPackagesForUid(callingUid).joinToString()
        val message =
            "[TX_ID: $txId] $action $methodName for packages=[$packages] (uid=$callingUid, pid=$callingPid)"
        if (isIntercepting) {
            SystemLogger.debug(message)
        } else {
            SystemLogger.verbose(message)
        }
    }

    companion object {
        // These codes must be kept in sync with the native injection library.

        // --- Backdoor Codes ---
        // Special transaction code to ask the injected library for its backdoor binder.
        private const val BACKDOOR_TRANSACTION_CODE = 0xdeadbeef.toInt()
        // Code used by the backdoor binder to register a new interceptor.
        private const val REGISTER_INTERCEPTOR_CODE = 1
        // Code used by the backdoor binder to unregister an interceptor.
        private const val UNREGISTER_INTERCEPTOR_CODE = 2

        // --- Hook Type Codes ---
        // Indicates that the call is for a pre-transaction hook.
        private const val PRE_TRANSACT_CODE = 1
        // Indicates that the call is for a post-transaction hook.
        private const val POST_TRANSACT_CODE = 2

        // --- Result Codes ---
        // Instructs the native hook to skip the original transaction.
        private const val RESULT_SKIP_TRANSACTION = 1
        // Instructs the native hook to execute the original transaction.
        private const val RESULT_CONTINUE = 2
        // Instructs the native hook to return a custom reply.
        private const val RESULT_OVERRIDE_REPLY = 3
        // Instructs the native hook to use modified input data for the transaction.
        private const val RESULT_OVERRIDE_DATA = 4
        // Instructs the native hook to skip the post transaction hook.
        private const val RESULT_CONTINUE_AND_SKIP_POST = 5

        /**
         * Probes a binder service to see if our native library has been injected. If successful, it
         * returns a "backdoor" binder that can be used to register interceptors.
         */
        fun getBackdoor(binder: IBinder): IBinder? {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            return try {
                if (binder.transact(BACKDOOR_TRANSACTION_CODE, data, reply, 0)) {
                    SystemLogger.debug("Backdoor access granted for binder: $binder")
                    reply.readStrongBinder()
                } else {
                    SystemLogger.debug("Backdoor not found for binder: $binder")
                    null
                }
            } catch (e: Exception) {
                SystemLogger.error("Failed to transact for backdoor.", e)
                null
            } finally {
                data.recycle()
                reply.recycle()
            }
        }

        /** Uses the backdoor binder to register an interceptor for a specific target service. */
        fun register(backdoor: IBinder, target: IBinder, interceptor: BinderInterceptor) {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                data.writeStrongBinder(target)
                data.writeStrongBinder(interceptor)
                backdoor.transact(REGISTER_INTERCEPTOR_CODE, data, reply, 0)
                SystemLogger.info("Registered interceptor for target: $target")
            } catch (e: Exception) {
                SystemLogger.error("Failed to register binder interceptor.", e)
            } finally {
                data.recycle()
                reply.recycle()
            }
        }

        /** Uses the backdoor binder to unregister an interceptor for a specific target service. */
        fun unregister(backdoor: IBinder, target: IBinder) {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                data.writeStrongBinder(target)
                backdoor.transact(UNREGISTER_INTERCEPTOR_CODE, data, reply, 0)
                SystemLogger.info("Unregistered interceptor for target: $target")
            } catch (e: Exception) {
                SystemLogger.error("Failed to unregister binder interceptor.", e)
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
    }
}
