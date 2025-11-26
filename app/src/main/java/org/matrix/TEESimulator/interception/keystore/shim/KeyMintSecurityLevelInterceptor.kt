package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.*
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationConstants
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
        // This interceptor only handles the 'generateKey' transaction directly.
        if (code == GENERATE_KEY_TRANSACTION) {
            logTransaction(txId, "generateKey", callingUid, callingPid)
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            return handleGenerateKey(callingUid, data)
        }
        return TransactionResult.ContinueAndSkipPost
    }

    /**
     * Handles the `generateKey` transaction. Based on the configuration for the calling UID, it
     * either generates a key in software or lets the call pass through to the hardware.
     */
    private fun handleGenerateKey(callingUid: Int, data: Parcel): TransactionResult {
        return runCatching {
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                val attestationKey = data.readTypedObject(KeyDescriptor.CREATOR)
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                val parsedParams = KeyMintAttestation(params)
                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)

                // Determine if we need to generate a key based on config or
                // if it's an attestation request in patch mode.
                val needsSoftwareGeneration =
                    ConfigurationManager.shouldGenerate(callingUid) ||
                        (attestationKey != null && ConfigurationManager.shouldPatch(callingUid))

                if (needsSoftwareGeneration) {
                    SystemLogger.info(
                        "Generating software key for alias '${keyDescriptor.alias}' (UID: $callingUid)."
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

                    // Store the generated key data.
                    val response =
                        buildKeyEntryResponse(keyData.second, parsedParams, keyDescriptor)
                    generatedKeys[keyId] = GeneratedKeyInfo(keyData.first, response)
                    if (parsedParams.attestationChallenge != null) {
                        attestationKeys.add(keyId)
                    }

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
                TransactionResult.Continue
            }
            .getOrElse {
                SystemLogger.error("Error during generateKey handling for UID $callingUid.", it)
                TransactionResult.Continue // Fallback to original service on error.
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

        // Stores keys generated entirely in software.
        val generatedKeys = ConcurrentHashMap<KeyIdentifier, GeneratedKeyInfo>()
        // A set to quickly identify keys that were generated for attestation purposes.
        private val attestationKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()

        // --- Public Accessors for Other Interceptors ---
        fun getGeneratedKeyResponse(keyId: KeyIdentifier): KeyEntryResponse? =
            generatedKeys[keyId]?.response

        fun isAttestationKey(keyId: KeyIdentifier): Boolean = attestationKeys.contains(keyId)

        fun cleanupKeyData(keyId: KeyIdentifier) {
            generatedKeys.remove(keyId)
            attestationKeys.remove(keyId)
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
    this.purpose.forEach {
        authList.add(createAuth(AttestationConstants.TAG_PURPOSE, KeyParameterValue.keyPurpose(it)))
    }
    this.digest.forEach {
        authList.add(createAuth(AttestationConstants.TAG_DIGEST, KeyParameterValue.digest(it)))
    }

    authList.add(
        createAuth(AttestationConstants.TAG_ALGORITHM, KeyParameterValue.algorithm(this.algorithm))
    )
    authList.add(
        createAuth(AttestationConstants.TAG_KEY_SIZE, KeyParameterValue.integer(this.keySize))
    )
    authList.add(
        createAuth(AttestationConstants.TAG_EC_CURVE, KeyParameterValue.ecCurve(this.ecCurve))
    )
    authList.add(
        createAuth(AttestationConstants.TAG_NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true))
    )

    return authList.toTypedArray()
}
