package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateHelper

/**
 * Interceptor for the `IKeystoreService` on Android S (API 31) and newer.
 *
 * This version of Keystore delegates most cryptographic operations to `IKeystoreSecurityLevel`
 * sub-services (for TEE, StrongBox, etc.). This interceptor's main role is to set up interceptors
 * for those sub-services and to patch certificate chains on their way out.
 */
@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : AbstractKeystoreInterceptor() {
    // Transaction codes for the IKeystoreService interface methods we are interested in.
    private val GET_KEY_ENTRY_TRANSACTION =
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "getKeyEntry")
    private val DELETE_KEY_TRANSACTION =
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "deleteKey")

    private val transactionNames: Map<Int, String> by lazy {
        IKeystoreService.Stub::class
            .java
            .declaredFields
            .filter {
                it.isAccessible = true
                it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
            }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTEESimulator.so entry"

    /**
     * This method is called once the main service is hooked. It proceeds to find and hook the
     * security level sub-services (e.g., TEE, StrongBox).
     */
    override fun onInterceptorReady(service: IBinder, backdoor: IBinder) {
        val keystoreInterface = IKeystoreService.Stub.asInterface(service)
        setupSecurityLevelInterceptors(keystoreInterface, backdoor)
    }

    private fun setupSecurityLevelInterceptors(service: IKeystoreService, backdoor: IBinder) {
        // Attempt to get and intercept the TEE security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)?.let { tee ->
                    SystemLogger.info("Found TEE SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
                    register(backdoor, tee.asBinder(), interceptor)
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept TEE SecurityLevel.", it) }

        // Attempt to get and intercept the StrongBox security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.STRONGBOX)?.let { strongbox ->
                    SystemLogger.info("Found StrongBox SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(strongbox, SecurityLevel.STRONGBOX)
                    register(backdoor, strongbox.asBinder(), interceptor)
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept StrongBox SecurityLevel.", it) }
    }

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code == GET_KEY_ENTRY_TRANSACTION || code == DELETE_KEY_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction

            if (ConfigurationManager.shouldSkipUid(callingUid))
                return TransactionResult.ContinueAndSkipPost

            SystemLogger.info("Handling ${transactionNames[code]!!} ${descriptor.alias}")
            val keyId = KeyIdentifier(callingUid, descriptor.alias)

            if (code == DELETE_KEY_TRANSACTION) {
                KeyMintSecurityLevelInterceptor.cleanupKeyData(keyId)
                return TransactionResult.ContinueAndSkipPost
            }

            val response =
                KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(keyId)
                    ?: return TransactionResult.Continue

            if (KeyMintSecurityLevelInterceptor.isAttestationKey(keyId))
                SystemLogger.info("${descriptor.alias} was an attestation key")

            SystemLogger.info("[TX_ID: $txId] Found generated response for ${descriptor.alias}:")
            response.metadata?.authorizations?.forEach {
                KeyMintParameterLogger.logParameter(it.keyParameter)
            }
            return InterceptorUtils.createTypedObjectReply(response)
        } else {
            logTransaction(
                txId,
                transactionNames[code] ?: "unknown code=$code",
                callingUid,
                callingPid,
                false,
            )
        }

        // Let most calls go through to the real service.
        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        if (target != keystoreService || reply == null || InterceptorUtils.hasException(reply))
            return TransactionResult.SkipTransaction

        if (code == GET_KEY_ENTRY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction

            if (!ConfigurationManager.shouldPatch(callingUid))
                return TransactionResult.SkipTransaction

            SystemLogger.info("Handling post-${transactionNames[code]!!} ${keyDescriptor.alias}")
            return try {
                val response =
                    reply.readTypedObject(KeyEntryResponse.CREATOR)
                        ?: return TransactionResult.SkipTransaction
                reply.setDataPosition(0) // Reset for potential reuse.

                val originalChain = CertificateHelper.getCertificateChain(response)
                val authorizations = response.metadata?.authorizations
                val origin =
                    authorizations
                        ?.find { it.keyParameter.tag == Tag.ORIGIN }
                        ?.let { it.keyParameter.value.origin }

                if (origin == KeyOrigin.IMPORTED || origin == KeyOrigin.SECURELY_IMPORTED) {
                    SystemLogger.info("[TX_ID: $txId] Skip patching for imported keys.")
                    return TransactionResult.SkipTransaction
                }

                if (originalChain == null || originalChain.size < 2) {
                    SystemLogger.info(
                        "[TX_ID: $txId] Skip patching short certificate chain of length ${originalChain?.size}."
                    )
                    return TransactionResult.SkipTransaction
                }

                // Perform the attestation patch.
                val newChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid)
                CertificateHelper.updateCertificateChain(response.metadata, newChain).getOrThrow()

                InterceptorUtils.createTypedObjectReply(response)
            } catch (e: Exception) {
                SystemLogger.error("[TX_ID: $txId] Failed to patch certificate chain.", e)
                TransactionResult.SkipTransaction
            }
        }
        return TransactionResult.SkipTransaction
    }
}
