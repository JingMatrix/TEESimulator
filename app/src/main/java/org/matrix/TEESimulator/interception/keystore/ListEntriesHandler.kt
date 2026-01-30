package org.matrix.TEESimulator.interception.keystore

import android.os.Parcel
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import java.util.TreeMap
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
     * Estimates the serialized size of a KeyDescriptor array for Binder transmission. Based on
     * AOSP's estimate_safe_amount_to_return implementation in security/keystore2/src/utils.rs
     */
    private fun estimateSafeAmountToReturn(
        keyDescriptors: Array<KeyDescriptor>,
        responseSizeLimit: Int,
    ): Int {
        var itemsToReturn = 0
        var returnedBytes = 0

        for (kd in keyDescriptors) {
            // 4 bytes for Domain, 8 bytes for nspace (see AOSP utils.rs)
            // https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/utils.rs;l=555
            returnedBytes += 4 + 8

            kd.alias?.let { returnedBytes += 4 + it.toByteArray(Charsets.UTF_8).size }

            kd.blob?.let { returnedBytes += 4 + it.size }

            if (returnedBytes > responseSizeLimit) {
                SystemLogger.warning(
                    "Key descriptors list (${keyDescriptors.size} items) may exceed binder " +
                        "size, returning $itemsToReturn items est $returnedBytes bytes."
                )
                break
            }
            itemsToReturn++
        }

        return itemsToReturn
    }

    // Limit from AOSP utils.rs
    // https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/utils.rs;l=581
    private const val RESPONSE_SIZE_LIMIT = 358400

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
        // Explicitly check UID here because the global check in Keystore2Interceptor was removed
        // to facilitate logging.
        if (ConfigurationManager.shouldSkipUid(callingUid))
            return TransactionResult.ContinueAndSkipPost

        return runCatching {
                data.setDataPosition(0)
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val domain = data.readInt()
                val namespace = data.readLong()

                val isListEntriesBatched =
                    listEntriesBatchedCode != -1 && code == listEntriesBatchedCode
                val startPastAlias = if (isListEntriesBatched) data.readString() else null

                // List entries is only supported for Domain::APP and Domain::SELINUX per AOSP
                // service.rs
                // https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/service.rs;l=283
                if (domain == Domain.APP) {
                    val methodName =
                        if (isListEntriesBatched) "listEntriesBatched" else "listEntries"
                    SystemLogger.debug("[TX_ID: $txId] Intercepting $methodName for APP domain.")
                    pendingParams[txId] = ListEntriesParams(domain, namespace, startPastAlias)
                }

                data.setDataPosition(0)
                TransactionResult.Continue
            }
            .getOrElse {
                val isListEntriesBatched =
                    listEntriesBatchedCode != -1 && code == listEntriesBatchedCode
                val methodName = if (isListEntriesBatched) "listEntriesBatched" else "listEntries"
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
                // Per AOSP's get_key_descriptor_for_lookup, -1 resolves to caller's UID for
                // Domain.APP
                // https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/service.rs;l=299
                val effectiveNamespace =
                    if (params.namespace == -1L) callingUid.toLong() else params.namespace
                if (effectiveNamespace != callingUid.toLong())
                    return TransactionResult.SkipTransaction

                val softwareKeys = getSoftwareKeyDescriptors(callingUid, effectiveNamespace)

                val filteredSoftwareKeys =
                    params.startPastAlias?.let { startAlias ->
                        softwareKeys.filter { (it.alias ?: "") > startAlias }
                    } ?: softwareKeys

                if (filteredSoftwareKeys.isEmpty()) return TransactionResult.SkipTransaction

                reply.setDataPosition(0)
                reply.readException()
                val originalList = reply.createTypedArray(KeyDescriptor.CREATOR) ?: emptyArray()

                val mergedArray = mergeKeyDescriptors(originalList, filteredSoftwareKeys)

                // Limit response size to avoid binder buffer overflow (matching AOSP behavior)
                val safeAmountToReturn =
                    estimateSafeAmountToReturn(mergedArray, RESPONSE_SIZE_LIMIT)
                val limitedArray =
                    if (safeAmountToReturn < mergedArray.size) {
                        SystemLogger.info(
                            "[TX_ID: $txId] listEntries: Limiting response from ${mergedArray.size} to " +
                                "$safeAmountToReturn entries to avoid binder overflow"
                        )
                        mergedArray.copyOfRange(0, safeAmountToReturn)
                    } else {
                        mergedArray
                    }

                SystemLogger.info(
                    "[TX_ID: $txId] listEntries: Merged ${originalList.size} hardware + " +
                        "${filteredSoftwareKeys.size} software keys, returning ${limitedArray.size} entries."
                )

                InterceptorUtils.createTypedArrayReply(limitedArray)
            }
            .getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed to inject listEntries reply", it)
                TransactionResult.SkipTransaction
            }
    }

    /**
     * Merges hardware and software key descriptors into a single sorted array. Uses TreeMap to
     * ensure alphabetical ordering and avoid duplicates.
     */
    private fun mergeKeyDescriptors(
        hardwareKeys: Array<KeyDescriptor>,
        softwareKeys: List<KeyDescriptor>,
    ): Array<android.system.keystore2.KeyDescriptor> {
        val combinedMap = TreeMap<String, KeyDescriptor>()
        hardwareKeys.forEach { key -> key.alias?.let { combinedMap[it] = key } }
        softwareKeys.forEach { key -> key.alias?.let { combinedMap[it] = key } }
        return combinedMap.values.toTypedArray()
    }

    /**
     * Returns a list of software-backed key descriptors for the given UID. These are returned as
     * our local Stub KeyDescriptor objects.
     */
    private fun getSoftwareKeyDescriptors(uid: Int, nspace: Long): List<KeyDescriptor> {
        return KeyMintSecurityLevelInterceptor.generatedKeys.entries
            .filter { it.key.uid == uid }
            .map { (keyId, _) ->
                KeyDescriptor().apply {
                    this.domain = Domain.APP
                    this.nspace = nspace
                    this.alias = keyId.alias
                    this.blob = null
                }
            }
    }
}
