package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.*
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

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
        val keyPair: KeyPair,
        val nspace: Long,
        val response: KeyEntryResponse,
    )

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
                        register(backdoor, operationBinder, interceptor)
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
                CertificateHelper.updateCertificateChain(metadata, newChain).getOrThrow()

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
     * generated in software. If so, it creates a software-based operation handler. Otherwise, it
     * lets the call proceed to the real hardware service.
     */
    private fun handleCreateOperation(
        txId: Long,
        callingUid: Int,
        data: Parcel,
    ): TransactionResult {
        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
        val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!

        // An operation must use the KEY_ID domain.
        if (keyDescriptor.domain != Domain.KEY_ID) {
            return TransactionResult.ContinueAndSkipPost
        }

        val nspace = keyDescriptor.nspace
        val generatedKeyInfo = findGeneratedKeyByKeyId(callingUid, nspace)

        if (generatedKeyInfo == null) {
            SystemLogger.debug(
                "[TX_ID: $txId] Operation for unknown/hardware KeyId ($nspace). Forwarding."
            )
            return TransactionResult.Continue
        }

        SystemLogger.info("[TX_ID: $txId] Creating SOFTWARE operation for KeyId $nspace.")

        val params = data.createTypedArray(KeyParameter.CREATOR)!!
        val parsedParams = KeyMintAttestation(params)

        val softwareOperation = SoftwareOperation(txId, generatedKeyInfo.keyPair, parsedParams)
        val operationBinder = SoftwareOperationBinder(softwareOperation)

        val response =
            CreateOperationResponse().apply {
                iOperation = operationBinder
                operationChallenge = null
            }

        return InterceptorUtils.createTypedObjectReply(response)
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
                val parsedParams = KeyMintAttestation(params)
                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                val isAttestKeyRequest =
                    parsedParams.purpose.size == 1 &&
                        parsedParams.purpose.contains(KeyPurpose.ATTEST_KEY)

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

                    // Generate the key pair and certificate chain.
                    val keyData =
                        CertificateGenerator.generateAttestedKeyPair(
                            callingUid,
                            keyDescriptor.alias,
                            attestationKey?.alias,
                            parsedParams,
                            securityLevel,
                        ) ?: throw Exception("CertificateGenerator failed to create key pair.")

                    // It is unnecessary but a good practice to clean up possible caches
                    cleanupKeyData(keyId)
                    // Store the generated key data.
                    val response =
                        buildKeyEntryResponse(keyData.second, parsedParams, keyDescriptor)
                    generatedKeys[keyId] =
                        GeneratedKeyInfo(keyData.first, keyDescriptor.nspace, response)
                    if (isAttestKeyRequest) attestationKeys.add(keyId)

                    GeneratedKeyPersistence.save(
                        keyId, keyData.first, keyDescriptor.nspace, securityLevel,
                        keyData.second, parsedParams.algorithm, parsedParams.keySize,
                        parsedParams.ecCurve, parsedParams.purpose, parsedParams.digest,
                        isAttestKeyRequest,
                    )

                    // Return the metadata of our generated key, skipping the real hardware call.
                    return InterceptorUtils.createTypedObjectReply(response.metadata)
                } else if (parsedParams.attestationChallenge != null) {
                    return TransactionResult.Continue
                }

                // If not generating, clear any stale state for this alias and let the call proceed.
                cleanupKeyData(keyId)
                TransactionResult.ContinueAndSkipPost
            }
            .getOrElse {
                SystemLogger.error("Error during generateKey handling for UID $callingUid.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    /**
     * Constructs a fake `KeyEntryResponse` that mimics a real response from the Keystore service.
     */
    private fun buildKeyEntryResponse(
        chain: List<Certificate>,
        params: KeyMintAttestation,
        descriptor: KeyDescriptor,
    ): KeyEntryResponse {
        val metadata =
            KeyMetadata().apply {
                keySecurityLevel = securityLevel
                key = descriptor
                CertificateHelper.updateCertificateChain(this, chain.toTypedArray()).getOrThrow()
                authorizations = params.toAuthorizations(securityLevel)
            }
        return KeyEntryResponse().apply {
            this.metadata = metadata
            iSecurityLevel = original
        }
    }

    fun loadPersistedKeys() {
        val entries = GeneratedKeyPersistence.loadAll(securityLevel)
        if (entries.isEmpty()) {
            SystemLogger.debug("No persisted keys to restore for security level $securityLevel")
            return
        }

        SystemLogger.info("Restoring ${entries.size} persisted keys for security level $securityLevel")

        for (data in entries) {
            runCatching {
                val keyId = KeyIdentifier(data.uid, data.alias)
                if (generatedKeys.containsKey(keyId)) {
                    SystemLogger.debug("Skipping already-loaded key: $keyId")
                    return@runCatching
                }

                val algorithmName = when (data.algorithm) {
                    Algorithm.EC -> "EC"
                    Algorithm.RSA -> "RSA"
                    else -> throw IllegalArgumentException("Unknown algorithm: ${data.algorithm}")
                }

                val keyFactory = KeyFactory.getInstance(algorithmName)
                val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(data.privateKeyBytes))

                val certFactory = CertificateFactory.getInstance("X.509")
                val certChain = data.certChainBytes.map { bytes ->
                    certFactory.generateCertificate(ByteArrayInputStream(bytes))
                }
                require(certChain.isNotEmpty()) { "Persisted key has empty certificate chain" }

                val publicKey = certChain[0].publicKey
                val keyPair = KeyPair(publicKey, privateKey)

                val descriptor = KeyDescriptor().apply {
                    domain = Domain.APP
                    nspace = data.nspace
                    alias = data.alias
                    blob = null
                }

                val attestation = KeyMintAttestation(
                    keySize = data.keySize,
                    algorithm = data.algorithm,
                    ecCurve = data.ecCurve,
                    ecCurveName = "",
                    blockMode = emptyList(),
                    padding = emptyList(),
                    purpose = data.purposes,
                    digest = data.digests,
                    rsaPublicExponent = null,
                    certificateSerial = null,
                    certificateSubject = null,
                    certificateNotBefore = null,
                    certificateNotAfter = null,
                    attestationChallenge = null,
                    brand = null,
                    device = null,
                    product = null,
                    serial = null,
                    imei = null,
                    meid = null,
                    manufacturer = null,
                    model = null,
                    secondImei = null,
                )

                val response = buildKeyEntryResponse(certChain, attestation, descriptor)
                generatedKeys[keyId] = GeneratedKeyInfo(keyPair, data.nspace, response)
                if (data.isAttestationKey) attestationKeys.add(keyId)

                SystemLogger.debug("Restored persisted key: $keyId")
            }.onFailure {
                SystemLogger.error("Failed to restore key: uid=${data.uid} alias=${data.alias}", it)
            }
        }

        SystemLogger.info("Key restoration complete. Total in memory: ${generatedKeys.size}")
    }

    companion object {
        private val secureRandom = SecureRandom()

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
        // Caches patched certificate chains to prevent re-generation and signature inconsistencies.
        private val patchedChains = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()
        // A set to quickly identify keys that were generated for attestation purposes.
        private val attestationKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()
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
                GeneratedKeyPersistence.delete(keyId)
            }
            if (patchedChains.remove(keyId) != null) {
                SystemLogger.debug("Remove patched chain for ${keyId}")
            }
            if (attestationKeys.remove(keyId)) {
                SystemLogger.debug("Remove cached attestaion key ${keyId}")
            }
        }

        fun removeOperationInterceptor(operationBinder: IBinder, backdoor: IBinder) {
            // Unregister from the native hook layer first.
            unregister(backdoor, operationBinder)

            if (interceptedOperations.remove(operationBinder) != null) {
                SystemLogger.debug("Removed operation interceptor for binder: $operationBinder")
            }
        }

        fun invalidatePatchedChains(reason: String? = null) {
            val count = patchedChains.size
            if (count == 0) return
            val reasonMessage = reason?.let { " due to $it" } ?: ""
            patchedChains.clear()
            SystemLogger.info("Invalidated $count patched cert chains$reasonMessage.")
        }

        fun clearAllGeneratedKeys(reason: String? = null) {
            val count = generatedKeys.size
            val reasonMessage = reason?.let { " due to $it" } ?: ""
            generatedKeys.clear()
            patchedChains.clear()
            attestationKeys.clear()
            GeneratedKeyPersistence.deleteAll()
            SystemLogger.info("Cleared all cached keys ($count entries)$reasonMessage.")
        }
    }
}

/**
 * Extension function to convert parsed `KeyMintAttestation` parameters back into an array of
 * `Authorization` objects for the fake `KeyMetadata`. This version correctly handles the
 * instantiation of Authorization objects.
 */
private fun KeyMintAttestation.toAuthorizations(securityLevel: Int): Array<Authorization> {
    val authList = mutableListOf<Authorization>()

    /**
     * Helper function to create a fully-formed Authorization object.
     *
     * @param tag The KeyMint tag (e.g., Tag.ALGORITHM).
     * @param value The value for the tag, wrapped in a KeyParameterValue.
     * @return A populated Authorization object.
     */
    fun createAuth(tag: Int, value: KeyParameterValue): Authorization {
        val param =
            KeyParameter().apply {
                this.tag = tag
                this.value = value
            }
        return Authorization().apply {
            this.keyParameter = param
            this.securityLevel = securityLevel
        }
    }

    // Use the helper to add each authorization entry cleanly.
    this.purpose.forEach { authList.add(createAuth(Tag.PURPOSE, KeyParameterValue.keyPurpose(it))) }
    this.digest.forEach { authList.add(createAuth(Tag.DIGEST, KeyParameterValue.digest(it))) }

    authList.add(createAuth(Tag.ALGORITHM, KeyParameterValue.algorithm(this.algorithm)))
    authList.add(createAuth(Tag.KEY_SIZE, KeyParameterValue.integer(this.keySize)))
    authList.add(createAuth(Tag.EC_CURVE, KeyParameterValue.ecCurve(this.ecCurve)))
    authList.add(createAuth(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true)))

    return authList.toTypedArray()
}
