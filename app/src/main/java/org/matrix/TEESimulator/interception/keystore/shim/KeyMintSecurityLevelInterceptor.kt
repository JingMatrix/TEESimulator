package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.*
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.SecretKey
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper
import org.matrix.TEESimulator.util.AndroidDeviceUtils

/**
 * Intercepts calls to an `IKeystoreSecurityLevel` service (e.g., TEE or StrongBox). This is where
 * the core logic for key generation and import handling for modern Android resides.
 */
class KeyMintSecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val securityLevel: Int,
) : BinderInterceptor() {

    // --- Data Structures for State Management ---
    data class GeneratedKeyInfo(
        val keyPair: KeyPair?,
        val secretKey: SecretKey?,
        val nspace: Long,
        val response: KeyEntryResponse,
        val keyParams: KeyMintAttestation,
    ) {
        constructor(
            keyPair: KeyPair?,
            nspace: Long,
            response: KeyEntryResponse,
            keyParams: KeyMintAttestation,
        ) : this(keyPair, null, nspace, response, keyParams)

        constructor(
            keyPair: KeyPair?,
            nspace: Long,
            response: KeyEntryResponse,
        ) : this(keyPair, null, nspace, response, KeyMintAttestation(emptyArray()))
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
        val shouldSkip = ConfigurationManager.shouldSkipUid(callingUid)

        when (code) {
            GENERATE_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                if (!shouldSkip) return handleGenerateKey(callingUid, data)
            }
            CREATE_OPERATION_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                if (!shouldSkip) return handleCreateOperation(txId, callingUid, data)
            }
            IMPORT_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                SystemLogger.info(
                    "[TX_ID: $txId] Forward to post-importKey hook for ${keyDescriptor.alias}[${keyDescriptor.nspace}]"
                )
                return TransactionResult.Continue
            }
        }

        logTransaction(
            txId,
            transactionNames[code] ?: "unknown code=$code",
            callingUid,
            callingPid,
            true,
        )

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
        // We only care about successful transactions.
        if (resultCode != 0 || reply == null || InterceptorUtils.hasException(reply))
            return TransactionResult.SkipTransaction

        if (code == IMPORT_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            cleanupKeyData(KeyIdentifier(callingUid, keyDescriptor.alias))
        } else if (code == CREATE_OPERATION_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
            val params = data.createTypedArray(KeyParameter.CREATOR)!!
            val parsedParams = KeyMintAttestation(params)
            val forced = data.readBoolean()
            if (forced)
                SystemLogger.verbose(
                    "[TX_ID: $txId] Current operation has a very high pruning power."
                )
            val response: CreateOperationResponse =
                reply.readTypedObject(CreateOperationResponse.CREATOR)!!
            SystemLogger.verbose(
                "[TX_ID: $txId] CreateOperationResponse: ${response.iOperation} ${response.operationChallenge}"
            )

            // Intercept the IKeystoreOperation binder
            response.iOperation?.let { operation ->
                val operationBinder = operation.asBinder()
                if (!interceptedOperations.containsKey(operationBinder)) {
                    SystemLogger.info("Found new IKeystoreOperation. Registering interceptor...")
                    val backdoor = getBackdoor(target)
                    if (backdoor != null) {
                        val interceptor = OperationInterceptor(operation, backdoor)
                        register(
                            backdoor,
                            operationBinder,
                            interceptor,
                            OperationInterceptor.INTERCEPTED_CODES,
                        )
                        interceptedOperations[operationBinder] = interceptor
                    } else {
                        SystemLogger.error(
                            "Failed to get backdoor to register OperationInterceptor."
                        )
                    }
                }
            }
        } else if (code == GENERATE_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            val metadata: KeyMetadata =
                reply.readTypedObject(KeyMetadata.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            KeyMintAttestation(
                metadata.authorizations?.map { it.keyParameter }?.toTypedArray() ?: emptyArray()
            )
            val originalChain =
                CertificateHelper.getCertificateChain(metadata)
                    ?: return TransactionResult.SkipTransaction
            if (originalChain.size > 1) {
                val newChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid)

                // Cache the newly patched chain to ensure consistency across subsequent API calls.
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                val key = metadata.key!!
                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                CertificateHelper.updateCertificateChain(callingUid, metadata, newChain)
                    .getOrThrow()
                metadata.authorizations =
                    InterceptorUtils.patchAuthorizations(metadata.authorizations, callingUid)

                // We must clean up cached generated keys before storing the patched chain
                cleanupKeyData(keyId)
                patchedChains[keyId] = newChain
                SystemLogger.debug(
                    "Cached patched certificate chain for $keyId. (${key.alias} [${key.domain}, ${key.nspace}])"
                )

                return InterceptorUtils.createTypedObjectReply(metadata)
            }
        }
        return TransactionResult.SkipTransaction
    }

    /**
     * Handles the `createOperation` transaction. It checks if the operation is for a key that was
     * generated in software. If so, it builds a software-based operation handler, enforcing the
     * same authorization checks as AOSP keystore2 `authorize_create`. Otherwise, it lets the call
     * proceed to the real hardware service.
     */
    private fun handleCreateOperation(
        txId: Long,
        callingUid: Int,
        data: Parcel,
    ): TransactionResult {
        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
        val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!

        // AOSP createOperation resolves the key for any domain (APP, KEY_ID, SELINUX, BLOB) through
        // the database. We only hold software keys, so resolve them by nspace (KEY_ID) or alias
        // (APP).
        val resolvedEntry: Map.Entry<KeyIdentifier, GeneratedKeyInfo>? =
            when (keyDescriptor.domain) {
                Domain.KEY_ID -> {
                    val nspace = keyDescriptor.nspace
                    if (nspace == 0L) null
                    else
                        generatedKeys.entries
                            .filter { it.key.uid == callingUid }
                            .find { it.value.nspace == nspace }
                }
                Domain.APP ->
                    keyDescriptor.alias?.let { alias ->
                        val key = KeyIdentifier(callingUid, alias)
                        generatedKeys[key]?.let { java.util.AbstractMap.SimpleEntry(key, it) }
                    }
                else -> null
            }
        val generatedKeyInfo = resolvedEntry?.value
        val resolvedKeyId = resolvedEntry?.key

        if (generatedKeyInfo == null) {
            SystemLogger.debug(
                "[TX_ID: $txId] Operation for unknown/hardware key (domain=${keyDescriptor.domain}, " +
                    "alias=${keyDescriptor.alias}, nspace=${keyDescriptor.nspace}). Forwarding."
            )
            return TransactionResult.Continue
        }

        SystemLogger.info(
            "[TX_ID: $txId] Creating SOFTWARE operation for key ${generatedKeyInfo.nspace}."
        )

        val opParams = data.createTypedArray(KeyParameter.CREATOR)!!
        val parsedOpParams = KeyMintAttestation(opParams)
        data.readBoolean() // forced: no-op for sw ops

        // Enforce the same authorization checks as AOSP keystore2 authorize_create: purpose
        // compatibility, key validity dates, caller nonce, and deferred USAGE_COUNT_LIMIT
        // accounting.
        val keyParams = generatedKeyInfo.keyParams

        // A missing operation PURPOSE is rejected with INVALID_ARGUMENT, as in create_operation.
        val requestedPurpose = parsedOpParams.purpose.firstOrNull()
        if (requestedPurpose == null) {
            return InterceptorUtils.createServiceSpecificErrorReply(
                KeystoreErrorCode.INVALID_ARGUMENT
            )
        }

        // AOSP rejects VERIFY/ENCRYPT on asymmetric keys (public-key operations belong on the
        // client) and AGREE_KEY on any non-EC key, both with UNSUPPORTED_PURPOSE.
        val algorithm = keyParams.algorithm
        val isAsymmetric = algorithm == Algorithm.EC || algorithm == Algorithm.RSA
        val unsupported =
            (isAsymmetric &&
                (requestedPurpose == KeyPurpose.VERIFY ||
                    requestedPurpose == KeyPurpose.ENCRYPT)) ||
                (requestedPurpose == KeyPurpose.AGREE_KEY && algorithm != Algorithm.EC)
        if (unsupported) {
            return InterceptorUtils.createServiceSpecificErrorReply(
                KeystoreErrorCode.UNSUPPORTED_PURPOSE
            )
        }

        // A purpose the key was not created with is rejected with INCOMPATIBLE_PURPOSE.
        if (requestedPurpose !in keyParams.purpose) {
            SystemLogger.info(
                "[TX_ID: $txId] Rejecting: purpose $requestedPurpose not in ${keyParams.purpose}"
            )
            return InterceptorUtils.createServiceSpecificErrorReply(
                KeystoreErrorCode.INCOMPATIBLE_PURPOSE
            )
        }

        // A key whose ACTIVE_DATETIME is still in the future is rejected with KEY_NOT_YET_VALID.
        keyParams.activeDateTime?.let { activeDate ->
            if (System.currentTimeMillis() < activeDate.time) {
                return InterceptorUtils.createServiceSpecificErrorReply(
                    KeystoreErrorCode.KEY_NOT_YET_VALID
                )
            }
        }

        // ORIGINATION_EXPIRE_DATETIME applies to origination purposes (SIGN/ENCRYPT); once past,
        // the
        // key is KEY_EXPIRED.
        keyParams.originationExpireDateTime?.let { expireDate ->
            if (
                (requestedPurpose == KeyPurpose.SIGN || requestedPurpose == KeyPurpose.ENCRYPT) &&
                    System.currentTimeMillis() > expireDate.time
            ) {
                return InterceptorUtils.createServiceSpecificErrorReply(
                    KeystoreErrorCode.KEY_EXPIRED
                )
            }
        }

        // USAGE_EXPIRE_DATETIME applies to usage purposes (DECRYPT/VERIFY); once past, the key is
        // KEY_EXPIRED.
        keyParams.usageExpireDateTime?.let { expireDate ->
            if (
                (requestedPurpose == KeyPurpose.DECRYPT || requestedPurpose == KeyPurpose.VERIFY) &&
                    System.currentTimeMillis() > expireDate.time
            ) {
                return InterceptorUtils.createServiceSpecificErrorReply(
                    KeystoreErrorCode.KEY_EXPIRED
                )
            }
        }

        // A caller-supplied NONCE on an origination purpose requires the key to allow CALLER_NONCE;
        // otherwise it is rejected with CALLER_NONCE_PROHIBITED.
        if (
            (requestedPurpose == KeyPurpose.SIGN || requestedPurpose == KeyPurpose.ENCRYPT) &&
                keyParams.callerNonce != true &&
                opParams.any { it.tag == Tag.NONCE }
        ) {
            return InterceptorUtils.createServiceSpecificErrorReply(
                KeystoreErrorCode.CALLER_NONCE_PROHIBITED
            )
        }

        return runCatching {
            val effectiveParams =
                keyParams.copy(
                    purpose = parsedOpParams.purpose,
                    digest = parsedOpParams.digest.ifEmpty { keyParams.digest },
                    blockMode = parsedOpParams.blockMode.ifEmpty { keyParams.blockMode },
                    padding = parsedOpParams.padding.ifEmpty { keyParams.padding },
                )
            val softwareOperation =
                SoftwareOperation(
                    txId,
                    generatedKeyInfo.keyPair,
                    generatedKeyInfo.secretKey,
                    effectiveParams,
                    opParams,
                )

            // USAGE_COUNT_LIMIT is enforced on finish: AOSP records the key id during
            // authorize_create and updates the counter via check_and_update_key_usage_count,
            // marking the key for deletion once the count is exhausted.
            if (keyParams.usageCountLimit != null && resolvedKeyId != null) {
                val limit = keyParams.usageCountLimit
                val remaining =
                    usageCounters.getOrPut(resolvedKeyId) {
                        java.util.concurrent.atomic.AtomicInteger(limit)
                    }
                if (remaining.get() <= 0) {
                    cleanupKeyData(resolvedKeyId)
                    usageCounters.remove(resolvedKeyId)
                    throw android.os.ServiceSpecificException(KeystoreErrorCode.KEY_NOT_FOUND)
                }
                softwareOperation.onFinishCallback = {
                    if (remaining.decrementAndGet() <= 0) {
                        cleanupKeyData(resolvedKeyId)
                        usageCounters.remove(resolvedKeyId)
                        SystemLogger.info(
                            "Key $resolvedKeyId exhausted (USAGE_COUNT_LIMIT=$limit)."
                        )
                    }
                }
            }

            val operationBinder = SoftwareOperationBinder(softwareOperation)
            val response =
                CreateOperationResponse().apply {
                    iOperation = operationBinder
                    operationChallenge = null
                    // AOSP forwards begin_result.params into
                    // CreateOperationResponse.parameters.
                    parameters = softwareOperation.beginParameters
                }

            InterceptorUtils.createTypedObjectReply(response)
        }
            .getOrElse { e ->
                SystemLogger.error("[TX_ID: $txId] Failed to create software operation.", e)
                InterceptorUtils.createServiceSpecificErrorReply(
                    if (e is android.os.ServiceSpecificException) e.errorCode
                    else KeystoreErrorCode.SYSTEM_ERROR
                )
            }
    }

    /**
     * Handles the `generateKey` transaction. Based on the configuration for the calling UID, it
     * either generates a key in software or lets the call pass through to the hardware.
     */
    private fun handleGenerateKey(callingUid: Int, data: Parcel): TransactionResult {
        return runCatching {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
            val attestationKey = data.readTypedObject(KeyDescriptor.CREATOR)
            SystemLogger.debug(
                "Handling generateKey ${keyDescriptor.alias}, attestKey=${attestationKey?.alias}"
            )
            val params = data.createTypedArray(KeyParameter.CREATOR)!!

            // AOSP add_required_parameters rejects a caller-supplied CREATION_DATETIME with
            // INVALID_ARGUMENT, and gates device-ID attestation on a permission check.
            if (params.any { it.tag == Tag.CREATION_DATETIME }) {
                return@runCatching InterceptorUtils.createServiceSpecificErrorReply(
                    INVALID_ARGUMENT
                )
            }

            // Device ID attestation requires READ_PRIVILEGED_PHONE_STATE. The tag set mirrors
            // AOSP `is_device_id_attestation_tag`.
            val hasDeviceIdTags = params.any {
                it.tag == Tag.ATTESTATION_ID_SERIAL ||
                    it.tag == Tag.ATTESTATION_ID_IMEI ||
                    it.tag == Tag.ATTESTATION_ID_MEID ||
                    it.tag == Tag.ATTESTATION_ID_SECOND_IMEI ||
                    it.tag == Tag.DEVICE_UNIQUE_ATTESTATION
            }
            if (
                hasDeviceIdTags &&
                    !ConfigurationManager.hasPermissionForUid(
                        callingUid,
                        "android.permission.READ_PRIVILEGED_PHONE_STATE",
                    )
            ) {
                return@runCatching InterceptorUtils.createServiceSpecificErrorReply(
                    CANNOT_ATTEST_IDS
                )
            }
            val parsedParams = KeyMintAttestation(params)
            val isAttestKeyRequest = parsedParams.isAttestKey()

            // Determine if we need to generate a key based on config or
            // if it's an attestation request in patch mode.
            val needsSoftwareGeneration =
                ConfigurationManager.shouldGenerate(callingUid) ||
                    (ConfigurationManager.shouldPatch(callingUid) && isAttestKeyRequest) ||
                    (attestationKey != null &&
                        isAttestationKey(KeyIdentifier(callingUid, attestationKey.alias)))

            if (needsSoftwareGeneration) {
                keyDescriptor.nspace = secureRandom.nextLong()
                SystemLogger.info(
                    "Generating software key for ${keyDescriptor.alias}[${keyDescriptor.nspace}]."
                )

                // Software generation follows the same high-level generateKey path as AOSP
                // security_level.rs, but substitutes our local key material and metadata.
                val isSymmetric =
                    parsedParams.algorithm != Algorithm.EC &&
                        parsedParams.algorithm != Algorithm.RSA

                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                cleanupKeyData(keyId)

                if (isSymmetric) {
                    val algoName =
                        when (parsedParams.algorithm) {
                            Algorithm.AES -> "AES"
                            Algorithm.HMAC -> "HmacSHA256"
                            else ->
                                throw android.os.ServiceSpecificException(
                                    KeystoreErrorCode.SYSTEM_ERROR,
                                    "Unsupported symmetric algorithm: ${parsedParams.algorithm}",
                                )
                        }
                    val keyGen = javax.crypto.KeyGenerator.getInstance(algoName)
                    keyGen.init(parsedParams.keySize)
                    val secretKey = keyGen.generateKey()

                    val metadata =
                        KeyMetadata().apply {
                            keySecurityLevel = securityLevel
                            key =
                                KeyDescriptor().apply {
                                    domain = Domain.KEY_ID
                                    nspace = keyDescriptor.nspace
                                    alias = null
                                    blob = null
                                }
                            certificate = null
                            certificateChain = null
                            authorizations =
                                parsedParams.toAuthorizations(callingUid, securityLevel)
                            modificationTimeMs = System.currentTimeMillis()
                        }
                    val response =
                        KeyEntryResponse().apply {
                            this.metadata = metadata
                            iSecurityLevel = original
                        }
                    generatedKeys[keyId] =
                        GeneratedKeyInfo(
                            null,
                            secretKey,
                            keyDescriptor.nspace,
                            response,
                            parsedParams,
                        )
                    return@runCatching InterceptorUtils.createTypedObjectReply(metadata)
                }

                // Generate the key pair and certificate chain.
                val keyData =
                    CertificateGenerator.generateAttestedKeyPair(
                        callingUid,
                        keyDescriptor.alias,
                        attestationKey?.alias,
                        parsedParams,
                        securityLevel,
                    ) ?: throw Exception("CertificateGenerator failed to create key pair.")

                // Store the generated key data.
                val response =
                    buildKeyEntryResponse(
                        callingUid,
                        keyData.second,
                        parsedParams,
                        keyDescriptor,
                    )
                generatedKeys[keyId] =
                    GeneratedKeyInfo(
                        keyData.first,
                        keyDescriptor.nspace,
                        response,
                        parsedParams,
                    )
                if (isAttestKeyRequest) attestationKeys.add(keyId)

                // Return the metadata of our generated key, skipping the real hardware call.
                InterceptorUtils.createTypedObjectReply(response.metadata)
            } else if (parsedParams.attestationChallenge != null) {
                TransactionResult.Continue
            } else {
                TransactionResult.ContinueAndSkipPost
            }
        }
            .getOrElse {
                SystemLogger.error("No key pair generated for UID $callingUid.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    /**
     * Constructs a fake `KeyEntryResponse` that mimics a real response from the Keystore service.
     */
    private fun buildKeyEntryResponse(
        callingUid: Int,
        chain: List<Certificate>,
        params: KeyMintAttestation,
        descriptor: KeyDescriptor,
    ): KeyEntryResponse {
        val normalizedKeyDescriptor =
            KeyDescriptor().apply {
                domain = Domain.KEY_ID
                nspace = descriptor.nspace
                alias = null
                blob = null
            }
        val metadata =
            KeyMetadata().apply {
                keySecurityLevel = securityLevel
                key = normalizedKeyDescriptor
                authorizations = params.toAuthorizations(callingUid, securityLevel)
                modificationTimeMs = System.currentTimeMillis()
            }
        CertificateHelper.updateCertificateChain(callingUid, metadata, chain.toTypedArray())
            .getOrThrow()
        return KeyEntryResponse().apply {
            this.metadata = metadata
            iSecurityLevel = original
        }
    }

    companion object {
        private val secureRandom = SecureRandom()

        private const val INVALID_ARGUMENT = 20
        private const val CANNOT_ATTEST_IDS = -66
        // Transaction codes for IKeystoreSecurityLevel interface.
        private val GENERATE_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val IMPORT_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")
        private val CREATE_OPERATION_TRANSACTION =
            InterceptorUtils.getTransactCode(
                IKeystoreSecurityLevel.Stub::class.java,
                "createOperation",
            )

        /** Only these transaction codes need native-level interception. */
        val INTERCEPTED_CODES =
            intArrayOf(
                GENERATE_KEY_TRANSACTION,
                IMPORT_KEY_TRANSACTION,
                CREATE_OPERATION_TRANSACTION,
            )

        private val transactionNames: Map<Int, String> by lazy {
            IKeystoreSecurityLevel.Stub::class
                .java
                .declaredFields
                .filter {
                    it.isAccessible = true
                    it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
                }
                .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
        }

        // Stores keys generated entirely in software.
        val generatedKeys = ConcurrentHashMap<KeyIdentifier, GeneratedKeyInfo>()
        // A set to quickly identify keys that were generated for attestation purposes.
        val attestationKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()
        // Caches patched certificate chains to prevent re-generation and signature inconsistencies.
        val patchedChains = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()
        // Tracks remaining usage count per key for USAGE_COUNT_LIMIT enforcement.
        private val usageCounters =
            ConcurrentHashMap<KeyIdentifier, java.util.concurrent.atomic.AtomicInteger>()
        // Stores interceptors for active cryptographic operations.
        private val interceptedOperations = ConcurrentHashMap<IBinder, OperationInterceptor>()

        // --- Public Accessors for Other Interceptors ---
        fun getGeneratedKeyResponse(keyId: KeyIdentifier): KeyEntryResponse? =
            generatedKeys[keyId]?.response

        /**
         * Finds a software-generated key by first filtering all known keys by the caller's UID, and
         * then matching the specific nspace.
         *
         * @param callingUid The UID of the process that initiated the createOperation call.
         * @param nspace The unique key identifier from the operation's KeyDescriptor.
         * @return The matching GeneratedKeyInfo if found, otherwise null.
         */
        fun findGeneratedKeyByKeyId(callingUid: Int, nspace: Long?): GeneratedKeyInfo? {
            // Iterate through all entries in the map to check both the key (for UID) and value (for
            // nspace).
            if (nspace == null || nspace == 0L) return null
            return generatedKeys.entries
                .filter { (keyIdentifier, _) -> keyIdentifier.uid == callingUid }
                .find { (_, info) -> info.nspace == nspace }
                ?.value
        }

        fun getPatchedChain(keyId: KeyIdentifier): Array<Certificate>? = patchedChains[keyId]

        fun isAttestationKey(keyId: KeyIdentifier): Boolean = attestationKeys.contains(keyId)

        fun cleanupKeyData(keyId: KeyIdentifier) {
            if (generatedKeys.remove(keyId) != null) {
                SystemLogger.debug("Remove generated key ${keyId}")
            }
            if (patchedChains.remove(keyId) != null) {
                SystemLogger.debug("Remove patched chain for ${keyId}")
            }
            if (attestationKeys.remove(keyId)) {
                SystemLogger.debug("Remove cached attestaion key ${keyId}")
            }
            usageCounters.remove(keyId)
        }

        fun removeOperationInterceptor(operationBinder: IBinder, backdoor: IBinder) {
            // Unregister from the native hook layer first.
            unregister(backdoor, operationBinder)

            if (interceptedOperations.remove(operationBinder) != null) {
                SystemLogger.debug("Removed operation interceptor for binder: $operationBinder")
            }
        }

        // Clears all cached keys.
        fun clearAllGeneratedKeys(reason: String? = null) {
            val count = generatedKeys.size
            val reasonMessage = reason?.let { " due to $it" } ?: ""
            generatedKeys.clear()
            patchedChains.clear()
            attestationKeys.clear()
            usageCounters.clear()
            SystemLogger.info("Cleared all cached keys ($count entries)$reasonMessage.")
        }
    }
}

/**
 * Extension function to convert parsed `KeyMintAttestation` parameters back into an array of
 * `Authorization` objects for the fake `KeyMetadata`, mirroring how AOSP security_level.rs
 * assembles the key characteristics returned from generateKey.
 */
private fun KeyMintAttestation.toAuthorizations(
    callingUid: Int,
    securityLevel: Int,
): Array<Authorization> {
    val authList = mutableListOf<Authorization>()

    /**
     * Helper function to create a fully-formed Authorization object.
     *
     * @param tag The KeyMint tag (e.g., Tag.ALGORITHM).
     * @param value The value for the tag, wrapped in a KeyParameterValue.
     * @return A populated Authorization object.
     */
    fun createAuth(tag: Int, value: KeyParameterValue, level: Int = securityLevel): Authorization {
        val param =
            KeyParameter().apply {
                this.tag = tag
                this.value = value
            }
        return Authorization().apply {
            this.keyParameter = param
            this.securityLevel = level
        }
    }

    authList.add(createAuth(Tag.ALGORITHM, KeyParameterValue.algorithm(this.algorithm)))

    if (this.ecCurve != null) {
        authList.add(createAuth(Tag.EC_CURVE, KeyParameterValue.ecCurve(this.ecCurve)))
    }

    this.purpose.forEach { authList.add(createAuth(Tag.PURPOSE, KeyParameterValue.keyPurpose(it))) }
    this.blockMode.forEach {
        authList.add(createAuth(Tag.BLOCK_MODE, KeyParameterValue.blockMode(it)))
    }
    this.digest.forEach { authList.add(createAuth(Tag.DIGEST, KeyParameterValue.digest(it))) }
    this.padding.forEach {
        authList.add(createAuth(Tag.PADDING, KeyParameterValue.paddingMode(it)))
    }

    authList.add(createAuth(Tag.KEY_SIZE, KeyParameterValue.integer(this.keySize)))

    if (this.rsaPublicExponent != null) {
        authList.add(
            createAuth(
                Tag.RSA_PUBLIC_EXPONENT,
                KeyParameterValue.longInteger(this.rsaPublicExponent.toLong()),
            )
        )
    }

    if (this.noAuthRequired != null) {
        authList.add(
            createAuth(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(this.noAuthRequired))
        )
    }

    if (this.callerNonce == true) {
        authList.add(createAuth(Tag.CALLER_NONCE, KeyParameterValue.boolValue(true)))
    }
    if (this.minMacLength != null) {
        authList.add(createAuth(Tag.MIN_MAC_LENGTH, KeyParameterValue.integer(this.minMacLength)))
    }
    if (this.rollbackResistance == true) {
        authList.add(createAuth(Tag.ROLLBACK_RESISTANCE, KeyParameterValue.boolValue(true)))
    }
    if (this.earlyBootOnly == true) {
        authList.add(createAuth(Tag.EARLY_BOOT_ONLY, KeyParameterValue.boolValue(true)))
    }
    if (this.allowWhileOnBody == true) {
        authList.add(createAuth(Tag.ALLOW_WHILE_ON_BODY, KeyParameterValue.boolValue(true)))
    }
    if (this.trustedUserPresenceRequired == true) {
        authList.add(
            createAuth(Tag.TRUSTED_USER_PRESENCE_REQUIRED, KeyParameterValue.boolValue(true))
        )
    }
    if (this.trustedConfirmationRequired == true) {
        authList.add(
            createAuth(Tag.TRUSTED_CONFIRMATION_REQUIRED, KeyParameterValue.boolValue(true))
        )
    }
    if (this.maxUsesPerBoot != null) {
        authList.add(
            createAuth(Tag.MAX_USES_PER_BOOT, KeyParameterValue.integer(this.maxUsesPerBoot))
        )
    }
    if (this.maxBootLevel != null) {
        authList.add(createAuth(Tag.MAX_BOOT_LEVEL, KeyParameterValue.integer(this.maxBootLevel)))
    }

    authList.add(
        createAuth(Tag.ORIGIN, KeyParameterValue.origin(this.origin ?: KeyOrigin.GENERATED))
    )

    authList.add(
        createAuth(Tag.OS_VERSION, KeyParameterValue.integer(AndroidDeviceUtils.osVersion))
    )

    val osPatch = AndroidDeviceUtils.getPatchLevel(callingUid)
    if (osPatch != AndroidDeviceUtils.DO_NOT_REPORT) {
        authList.add(createAuth(Tag.OS_PATCHLEVEL, KeyParameterValue.integer(osPatch)))
    }

    val vendorPatch = AndroidDeviceUtils.getVendorPatchLevelLong(callingUid)
    if (vendorPatch != AndroidDeviceUtils.DO_NOT_REPORT) {
        authList.add(createAuth(Tag.VENDOR_PATCHLEVEL, KeyParameterValue.integer(vendorPatch)))
    }

    val bootPatch = AndroidDeviceUtils.getBootPatchLevelLong(callingUid)
    if (bootPatch != AndroidDeviceUtils.DO_NOT_REPORT) {
        authList.add(createAuth(Tag.BOOT_PATCHLEVEL, KeyParameterValue.integer(bootPatch)))
    }

    // Software-enforced tags (SecurityLevel.SOFTWARE): CREATION_DATETIME, enforcement dates,
    // USER_ID.
    fun createSwAuth(tag: Int, value: KeyParameterValue): Authorization {
        val param =
            KeyParameter().apply {
                this.tag = tag
                this.value = value
            }
        return Authorization().apply {
            this.keyParameter = param
            this.securityLevel = SecurityLevel.SOFTWARE
        }
    }

    authList.add(
        createSwAuth(Tag.CREATION_DATETIME, KeyParameterValue.dateTime(System.currentTimeMillis()))
    )

    this.activeDateTime?.let {
        authList.add(createSwAuth(Tag.ACTIVE_DATETIME, KeyParameterValue.dateTime(it.time)))
    }
    this.originationExpireDateTime?.let {
        authList.add(
            createSwAuth(Tag.ORIGINATION_EXPIRE_DATETIME, KeyParameterValue.dateTime(it.time))
        )
    }
    this.usageExpireDateTime?.let {
        authList.add(createSwAuth(Tag.USAGE_EXPIRE_DATETIME, KeyParameterValue.dateTime(it.time)))
    }
    this.usageCountLimit?.let {
        authList.add(createSwAuth(Tag.USAGE_COUNT_LIMIT, KeyParameterValue.integer(it)))
    }
    if (this.unlockedDeviceRequired == true) {
        authList.add(createSwAuth(Tag.UNLOCKED_DEVICE_REQUIRED, KeyParameterValue.boolValue(true)))
    }

    authList.add(createSwAuth(Tag.USER_ID, KeyParameterValue.integer(callingUid / 100000)))

    return authList.toTypedArray()
}
