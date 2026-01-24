package org.matrix.TEESimulator.interception.keystore

import android.os.Parcel
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor.TransactionResult
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Handler for listEntries and listEntriesBatched transaction interception.
 *
 * This class manages the interception of IKeystoreService.listEntries() calls to inject
 * software-backed keys into the results alongside hardware-backed keys.
 */
object ListEntriesHandler {

    private data class ListEntriesParams(
        val domain: Int,
        val namespace: Long,
        val startPastAlias: String?,
    )

    private val pendingParams = ConcurrentHashMap<Long, ListEntriesParams>()

    /**
     * Handles pre-transaction interception for listEntries calls. Parses and stores parameters for
     * later use in post-transaction processing.
     */
    fun handlePreTransact(
        txId: Long,
        code: Int,
        callingUid: Int,
        data: Parcel,
        listEntriesBatchedCode: Int,
    ): TransactionResult {
        if (ConfigurationManager.shouldSkipUid(callingUid))
            return TransactionResult.ContinueAndSkipPost

        return runCatching {
                InterceptorUtils.resetParcelForReading(data, IKeystoreService.DESCRIPTOR)
                val domain = data.readInt()
                val namespace = data.readLong()
                val startPastAlias = if (code == listEntriesBatchedCode) data.readString() else null

                if (domain == Domain.APP) {
                    val methodName =
                        if (code == listEntriesBatchedCode) "listEntriesBatched" else "listEntries"
                    SystemLogger.debug("[TX_ID: $txId] Intercepting $methodName for APP domain.")
                    pendingParams[txId] = ListEntriesParams(domain, namespace, startPastAlias)
                }

                data.setDataPosition(0)
                TransactionResult.Continue
            }
            .getOrElse {
                val methodName =
                    if (code == listEntriesBatchedCode) "listEntriesBatched" else "listEntries"
                SystemLogger.error("[TX_ID: $txId] Failed to parse $methodName params", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    /**
     * Handles post-transaction interception for listEntries calls. Merges software-backed keys with
     * hardware-backed keys in the response.
     */
    fun handlePostTransact(txId: Long, callingUid: Int, reply: Parcel): TransactionResult {
        val params = pendingParams.remove(txId) ?: return TransactionResult.SkipTransaction

        return runCatching {
                val effectiveNamespace =
                    if (params.namespace == -1L) callingUid.toLong() else params.namespace
                if (effectiveNamespace != callingUid.toLong())
                    return TransactionResult.SkipTransaction

                val softwareKeys =
                    KeyMintSecurityLevelInterceptor.getSoftwareKeyDescriptors(
                        callingUid,
                        effectiveNamespace,
                    )

                val filteredSoftwareKeys =
                    params.startPastAlias?.let { startAlias ->
                        softwareKeys.filter { (it.alias ?: "") > startAlias }
                    } ?: softwareKeys

                if (filteredSoftwareKeys.isEmpty()) return TransactionResult.SkipTransaction

                reply.setDataPosition(0)
                reply.readException()
                val originalList = reply.createTypedArray(KeyDescriptor.CREATOR) ?: emptyArray()

                val mergedArray =
                    InterceptorUtils.mergeKeyDescriptors(originalList, filteredSoftwareKeys)

                SystemLogger.info(
                    "[TX_ID: $txId] listEntries: Merged ${originalList.size} hardware + ${filteredSoftwareKeys.size} software keys."
                )

                InterceptorUtils.createTypedArrayReply(mergedArray)
            }
            .getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed to inject listEntries reply", it)
                TransactionResult.SkipTransaction
            }
    }
}
