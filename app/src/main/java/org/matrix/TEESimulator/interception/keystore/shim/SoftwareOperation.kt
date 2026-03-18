package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.hardware.security.keymint.Tag
import android.os.RemoteException
import android.system.keystore2.IKeystoreOperation
import android.system.keystore2.KeyParameters
import java.security.KeyPair
import java.security.Signature
import java.security.SignatureException
import javax.crypto.Cipher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger

/*
 * References:
 * https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/operation.rs
 * https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/security_level.rs
 */

// A sealed interface to represent the different cryptographic operations we can perform.
private sealed interface CryptoPrimitive {
    fun updateAad(data: ByteArray?)

    fun update(data: ByteArray?): ByteArray?

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?

    fun abort()

    /** Returns parameters from the begin phase (e.g. GCM nonce), or null if none. */
    fun getBeginParameters(): Array<KeyParameter>? = null
}

// Helper object to map KeyMint constants to JCA algorithm strings.
private object JcaAlgorithmMapper {
    fun mapSignatureAlgorithm(params: KeyMintAttestation): String {
        val digest =
            when (params.digest.firstOrNull()) {
                Digest.SHA_2_256 -> "SHA256"
                Digest.SHA_2_384 -> "SHA384"
                Digest.SHA_2_512 -> "SHA512"
                else -> "NONE"
            }
        val keyAlgo =
            when (params.algorithm) {
                Algorithm.EC -> "ECDSA"
                Algorithm.RSA -> "RSA"
                else ->
                    throw IllegalArgumentException(
                        "Unsupported signature algorithm: ${params.algorithm}"
                    )
            }
        return "${digest}with${keyAlgo}"
    }

    fun mapCipherAlgorithm(params: KeyMintAttestation): String {
        val keyAlgo =
            when (params.algorithm) {
                Algorithm.RSA -> "RSA"
                Algorithm.AES -> "AES"
                else ->
                    throw IllegalArgumentException(
                        "Unsupported cipher algorithm: ${params.algorithm}"
                    )
            }
        val blockMode =
            when (params.blockMode.firstOrNull()) {
                BlockMode.ECB -> "ECB"
                BlockMode.CBC -> "CBC"
                BlockMode.GCM -> "GCM"
                else -> "ECB" // Default for RSA
            }
        val padding =
            when (params.padding.firstOrNull()) {
                PaddingMode.NONE -> "NoPadding"
                PaddingMode.PKCS7 -> "PKCS7Padding"
                PaddingMode.RSA_PKCS1_1_5_ENCRYPT -> "PKCS1Padding"
                PaddingMode.RSA_OAEP -> "OAEPPadding"
                else -> "NoPadding" // Default for GCM
            }
        return "$keyAlgo/$blockMode/$padding"
    }
}

// Concrete implementation for Signing.
private class Signer(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initSign(keyPair.private)
        }

    override fun updateAad(data: ByteArray?) {}

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray {
        if (data != null) update(data)
        return this.signature.sign()
    }

    override fun abort() {}
}

// Concrete implementation for Verification.
private class Verifier(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initVerify(keyPair.public)
        }

    override fun updateAad(data: ByteArray?) {}

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) update(data)
        if (signature == null) throw SignatureException("Signature to verify is null")
        if (!this.signature.verify(signature)) {
            // Throwing an exception is how Keystore signals verification failure.
            throw SignatureException("Signature verification failed")
        }
        // A successful verification returns no data.
        return null
    }

    override fun abort() {}
}

// Concrete implementation for Encryption/Decryption.
private class CipherPrimitive(
    keyPair: KeyPair,
    params: KeyMintAttestation,
    private val opMode: Int,
) : CryptoPrimitive {
    private val cipher: Cipher =
        Cipher.getInstance(JcaAlgorithmMapper.mapCipherAlgorithm(params)).apply {
            val key = if (opMode == Cipher.ENCRYPT_MODE) keyPair.public else keyPair.private
            init(opMode, key)
        }

    override fun updateAad(data: ByteArray?) {
        if (data != null) cipher.updateAAD(data)
    }

    override fun update(data: ByteArray?): ByteArray? =
        if (data != null) cipher.update(data) else null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
        if (data != null) cipher.doFinal(data) else cipher.doFinal()

    override fun abort() {}

    /**
     * Returns the cipher IV as a NONCE parameter for GCM operations.
     *
     * https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/security_level.rs;l=402
     */
    override fun getBeginParameters(): Array<KeyParameter>? {
        val iv = cipher.iv ?: return null
        return arrayOf(
            KeyParameter().apply {
                tag = Tag.NONCE
                value = KeyParameterValue.blob(iv)
            }
        )
    }
}

/**
 * A software-only implementation of a cryptographic operation. This class acts as a controller,
 * delegating to a specific cryptographic primitive based on the operation's purpose.
 *
 * Tracks operation lifecycle: once [finish] or [abort] is called, subsequent calls will throw. This
 * matches AOSP keystore2 behavior where finalized operations return INVALID_OPERATION_HANDLE
 * (operation.rs: l=26, 320).
 */
class SoftwareOperation(private val txId: Long, keyPair: KeyPair, params: KeyMintAttestation) {
    private val primitive: CryptoPrimitive

    @Volatile private var finalized = false

    init {
        val purpose = params.purpose.firstOrNull()
        val purposeName = KeyMintParameterLogger.purposeNames[purpose] ?: "UNKNOWN"
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Initializing for purpose: $purposeName.")

        primitive =
            when (purpose) {
                KeyPurpose.SIGN -> Signer(keyPair, params)
                KeyPurpose.VERIFY -> Verifier(keyPair, params)
                KeyPurpose.ENCRYPT -> CipherPrimitive(keyPair, params, Cipher.ENCRYPT_MODE)
                KeyPurpose.DECRYPT -> CipherPrimitive(keyPair, params, Cipher.DECRYPT_MODE)
                else ->
                    throw UnsupportedOperationException("Unsupported operation purpose: $purpose")
            }
    }

    /** Parameters produced during begin (e.g. GCM nonce), to populate CreateOperationResponse. */
    val beginParameters: KeyParameters?
        // security_level.rs: l=402
        get() {
            val params = primitive.getBeginParameters() ?: return null
            if (params.isEmpty()) return null
            return KeyParameters().apply { keyParameter = params }
        }

    private fun checkActive() {
        if (finalized) throw IllegalStateException("INVALID_OPERATION_HANDLE")
    }

    fun updateAad(data: ByteArray?) {
        checkActive()
        try {
            primitive.updateAad(data)
        } catch (e: Exception) {
            finalized = true
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to updateAad.", e)
            throw e
        }
    }

    fun update(data: ByteArray?): ByteArray? {
        checkActive()
        try {
            return primitive.update(data)
        } catch (e: Exception) {
            finalized = true
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to update operation.", e)
            throw e
        }
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        checkActive()
        try {
            val result = primitive.finish(data, signature)
            SystemLogger.info("[SoftwareOp TX_ID: $txId] Finished operation successfully.")
            return result
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to finish operation.", e)
            throw e
        } finally {
            finalized = true
        }
    }

    fun abort() {
        checkActive()
        finalized = true
        primitive.abort()
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Operation aborted.")
    }
}

/**
 * The Binder interface for [SoftwareOperation].
 *
 * All methods are synchronized to prevent concurrent access, matching AOSP's Mutex-protected
 * KeystoreOperation wrapper. Input data is validated against [MAX_RECEIVE_DATA] (32KB) to match
 * AOSP's enforced limit (operation.rs: l=74, 216, 809).
 */
class SoftwareOperationBinder(private val operation: SoftwareOperation) :
    IKeystoreOperation.Stub() {

    private fun checkInputLength(data: ByteArray?) {
        // operation.rs: l=337
        if (data != null && data.size > MAX_RECEIVE_DATA)
            throw IllegalStateException("TOO_MUCH_DATA")
    }

    @Throws(RemoteException::class)
    override fun updateAad(aadInput: ByteArray?) {
        synchronized(this) {
            checkInputLength(aadInput)
            operation.updateAad(aadInput)
        }
    }

    @Throws(RemoteException::class)
    override fun update(input: ByteArray?): ByteArray? {
        synchronized(this) {
            checkInputLength(input)
            return operation.update(input)
        }
    }

    @Throws(RemoteException::class)
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? {
        synchronized(this) {
            checkInputLength(input)
            checkInputLength(signature)
            return operation.finish(input, signature)
        }
    }

    @Throws(RemoteException::class)
    override fun abort() {
        synchronized(this) { operation.abort() }
    }

    companion object {
        // operation.rs: l=216
        private const val MAX_RECEIVE_DATA = 0x8000
    }
}
