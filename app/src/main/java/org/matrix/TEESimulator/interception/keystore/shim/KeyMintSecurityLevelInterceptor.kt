package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.*
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
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
    data class GeneratedKeyInfo(val keyPair: KeyPair, val response: KeyEntryResponse)

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code == GENERATE_KEY_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            return handleGenerateKey(callingUid, data)
        } else if (code == IMPORT_KEY_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val alias =
                data.readTypedObject(KeyDescriptor.CREATOR)?.alias
                    ?: return TransactionResult.ContinueAndSkipPost
            SystemLogger.info("Handling post-${transactionNames[code]} ${alias}")
            return TransactionResult.Continue
        } else {
            logTransaction(
                txId,
                transactionNames[code] ?: "unknown code=$code",
                callingUid,
                callingPid,
                false,
            )
        }
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
        // We only care about successful 'importKey' transactions to clean cached keys.
        if (
            code == IMPORT_KEY_TRANSACTION &&
                resultCode == 0 &&
                reply != null &&
                !InterceptorUtils.hasException(reply)
        ) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            cleanupKeyData(KeyIdentifier(callingUid, keyDescriptor.alias))
        }
        return TransactionResult.SkipTransaction
    }

    /**
     * Handles the `generateKey` transaction. Based on the configuration for the calling UID, it
     * either generates a key in software or lets the call pass through to the hardware.
     */
    private fun handleGenerateKey(callingUid: Int, data: Parcel): TransactionResult {
        return runCatching {
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
                    SystemLogger.info("Generating software key for ${keyId}.")

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
                        buildKeyEntryResponse(keyData.second, parsedParams, keyDescriptor)

                    generatedKeys[keyId] = GeneratedKeyInfo(keyData.first, response)
                    if (isAttestKeyRequest) attestationKeys.add(keyId)

                    // Return the metadata of our generated key, skipping the real hardware call.
                    val resultParcel =
                        Parcel.obtain().apply {
                            writeNoException()
                            writeTypedObject(response.metadata, 0)
                        }
                    return TransactionResult.OverrideReply(0, resultParcel)
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

    companion object {
        // Transaction codes for IKeystoreSecurityLevel interface.
        private val GENERATE_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val IMPORT_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")

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
        private val attestationKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()

        // --- Public Accessors for Other Interceptors ---
        fun getGeneratedKeyResponse(keyId: KeyIdentifier): KeyEntryResponse? =
            generatedKeys[keyId]?.response

        fun isAttestationKey(keyId: KeyIdentifier): Boolean = attestationKeys.contains(keyId)

        fun cleanupKeyData(keyId: KeyIdentifier) {
            if (generatedKeys.remove(keyId) != null) {
                SystemLogger.debug("Remove generated key ${keyId}")
            }
            if (attestationKeys.remove(keyId)) {
                SystemLogger.debug("Remove cached attestaion key ${keyId}")
            }
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
