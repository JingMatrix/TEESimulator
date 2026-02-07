package org.matrix.TEESimulator.interception.keystore

import android.os.Parcel
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import java.util.TreeMap
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Handler to intercept listEntries and listEntriesBatched transactions.
 *
 * References for all mentioned functions in AOSP:
 * https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/database.rs
 * https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/service.rs
 * https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/utils.rs
 */
object ListEntriesHandler {

    // Estimate for maximum size of a Binder response in bytes.
    private const val RESPONSE_SIZE_LIMIT = 358400

    // Based on AOSP function `estimate_safe_amount_to_return` in utils.rs.
    private fun estimateSafeAmountToReturn(
        keyDescriptors: Array<KeyDescriptor>,
        responseSizeLimit: Int,
    ): Int {
        var itemsToReturn = 0
        var returnedBytes = 0

        for (kd in keyDescriptors) {
            // 4 bytes for the Domain enum
            // 8 bytes for the Namespace long
            returnedBytes += 4 + 8

            kd.alias?.let { returnedBytes += 4 + it.toByteArray(Charsets.UTF_8).size }
            kd.blob?.let { returnedBytes += 4 + it.size }

            if (returnedBytes > responseSizeLimit) {
                SystemLogger.warning(
                    "Key descriptors list (${keyDescriptors.size} items) may exceed binder size limit, returning $itemsToReturn items with estimated size: $returnedBytes bytes."
                )
                break
            }
            itemsToReturn++
        }

        return itemsToReturn
    }

    // Parse and store parameters for later use (in post-transaction).
    fun cacheParameters(txId: Long, data: Parcel, isBatchMode: Boolean): ListEntriesParams? {
        data.enforceInterface(IKeystoreService.DESCRIPTOR)

        val domain = data.readInt()
        val namespace = data.readLong()
        val startPastAlias = if (isBatchMode) data.readString() else null

        // List entries is only supported for Domain::APP and Domain::SELINUX.
        // See AOSP function `get_key_descriptor_for_lookup` in service.rs.
        // Note that all generated keys belong to Domain::APP.
        if (domain == Domain.APP) {
            val params = ListEntriesParams(domain, namespace, startPastAlias)
            SystemLogger.debug("[TX_ID: $txId] Cached $params.")
            return params
        }

        return null
    }

    // Merge software-backed keys with hardware-backed keys in the reply parcel.
    fun injectGeneratedKeys(
        txId: Long,
        callingUid: Int,
        params: ListEntriesParams,
        reply: Parcel,
    ): Array<KeyDescriptor> {
        // By default we use the calling uid as namespace if domain is Domain::APP.
        // The namespace parameter is thus ignored for non-privileged applications.
        // See AOSP function `get_key_descriptor_for_lookup` in service.rs.
        val keysToInject =
            extractGeneratedKeyDescriptors(callingUid, callingUid.toLong(), params.startPastAlias)
        val originalList = reply.createTypedArray(KeyDescriptor.CREATOR)!!
        val mergedArray = mergeKeyDescriptors(originalList, keysToInject)

        // Limit response size to avoid binder buffer overflow.
        // See AOSP function `list_key_entries` in utils.rs.
        val safeAmountToReturn = estimateSafeAmountToReturn(mergedArray, RESPONSE_SIZE_LIMIT)

        return if (safeAmountToReturn < mergedArray.size) {
            SystemLogger.debug(
                "[TX_ID: $txId] Listing entries are truncated [${mergedArray.size} -> $safeAmountToReturn] to avoid transaction overflow."
            )
            mergedArray.copyOfRange(0, safeAmountToReturn)
        } else {
            SystemLogger.debug(
                "[TX_ID: $txId] Listing entries returns ${mergedArray.size} [injected: ${keysToInject.size}] keys."
            )
            mergedArray
        }
    }

    // Merge hardware and software key descriptors into a single sorted array.
    private fun mergeKeyDescriptors(
        hardwareKeys: Array<KeyDescriptor>,
        keysToInject: List<KeyDescriptor>,
    ): Array<KeyDescriptor> {
        // Uses TreeMap to ensure alphabetical ordering and uniqueness (prefer injected keys).
        val combinedMap = TreeMap<String, KeyDescriptor>()
        hardwareKeys.forEach { key -> key.alias?.let { combinedMap[it] = key } }
        keysToInject.forEach { key -> key.alias?.let { combinedMap[it] = key } }
        return combinedMap.values.toTypedArray()
    }

    // Based on AOSP function `list_past_alias` in database.rs
    private fun extractGeneratedKeyDescriptors(
        uid: Int,
        namespace: Long,
        startPastAlias: String?,
    ): List<KeyDescriptor> {
        return KeyMintSecurityLevelInterceptor.generatedKeys.keys
            .filter { it.uid == uid && (startPastAlias == null || it.alias < startPastAlias) }
            .map { keyId ->
                KeyDescriptor().apply {
                    this.domain = Domain.APP
                    this.nspace = namespace
                    this.alias = keyId.alias
                    this.blob = null
                }
            }
    }
}

// Parameters of AOSP function `list_key_entries` in utils.rs.
data class ListEntriesParams(val domain: Int, val namespace: Long, val startPastAlias: String?)
