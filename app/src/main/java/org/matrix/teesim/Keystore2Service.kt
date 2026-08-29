package org.matrix.teesim

import android.os.IBinder
import java.lang.reflect.InvocationTargetException

/**
 * Reflective bridge to keystore2's binder service (`android.system.keystore2.IKeystoreService`),
 * used to delete a key the proper way: asking keystore2 to remove it in its own privileged context,
 * rather than editing its database from underneath it. Reflection keeps the daemon free of
 * keystore2's large AIDL surface — the real classes resolve on the device at runtime.
 *
 * A key is addressed by `Domain.KEY_ID`, so keystore2 looks it up by its own keyentry id and needs
 * no namespace or alias from us; it still enforces its own access control, so a caller our SELinux
 * context isn't allowed to touch is rejected — which the caller treats as "fall back to a direct
 * database delete".
 */
object Keystore2Service {

    private const val SERVICE = "android.system.keystore2.IKeystoreService/default"
    private const val DOMAIN_KEY_ID = 4 // android.system.keystore2.Domain.KEY_ID

    /**
     * The resolved IKeystoreService: its interface class, the service instance, and KeyDescriptor
     * class.
     */
    private class Svc(val iface: Class<*>, val service: Any?, val descriptorClass: Class<*>)

    /**
     * Resolve keystore2's binder and reflect the classes we call, or null (logged) if unavailable.
     * A freshly spawned delete-helper can outrun keystore2's service registration at boot, so wait
     * (bounded) for the service to appear, as the main branch does.
     */
    private fun connect(): Svc? {
        val serviceManager = Class.forName("android.os.ServiceManager")
        val getService = serviceManager.getMethod("getService", String::class.java)
        var binder = getService.invoke(null, SERVICE) as? IBinder
        var waitedMs = 0
        while (binder == null && waitedMs < 5000) {
            Thread.sleep(100)
            waitedMs += 100
            binder = getService.invoke(null, SERVICE) as? IBinder
        }
        if (binder == null) {
            SystemLogger.warning("Keystore2Service: service $SERVICE not found after ${waitedMs}ms")
            return null
        }
        val stub = Class.forName("android.system.keystore2.IKeystoreService\$Stub")
        val service = stub.getMethod("asInterface", IBinder::class.java).invoke(null, binder)
        val iface = Class.forName("android.system.keystore2.IKeystoreService")
        val descriptorClass = Class.forName("android.system.keystore2.KeyDescriptor")
        return Svc(iface, service, descriptorClass)
    }

    /** A KeyDescriptor addressing keyentry [keyId] by Domain.KEY_ID; alias and blob stay null. */
    private fun Svc.keyIdDescriptor(keyId: Long): Any {
        val d = descriptorClass.getConstructor().newInstance()
        descriptorClass.getField("domain").setInt(d, DOMAIN_KEY_ID)
        descriptorClass.getField("nspace").setLong(d, keyId)
        return d
    }

    /**
     * Ask keystore2 to delete the key with keyentry id [keyId]. Returns true on success; false if
     * the service is absent or the call is rejected (e.g. SELinux denies our context) — logged
     * either way.
     */
    fun deleteKeyById(keyId: Long): Boolean {
        return try {
            val svc = connect() ?: return false
            svc.iface
                .getMethod("deleteKey", svc.descriptorClass)
                .invoke(svc.service, svc.keyIdDescriptor(keyId))
            SystemLogger.info("Keystore2Service: deleted key id=$keyId via keystore2 API")
            true
        } catch (e: Throwable) {
            val cause = (e as? InvocationTargetException)?.targetException ?: e
            SystemLogger.warning(
                "Keystore2Service.deleteKeyById($keyId) failed: ${cause.javaClass.simpleName}: ${cause.message}"
            )
            false
        }
    }

    /**
     * Run one owner-only keystore2 operation on keyentry [keyId] as its owning app [uid]. keystore2
     * authorizes such operations (delete, cert update) by the caller's EFFECTIVE uid, and only the
     * owner qualifies, so the daemon cannot act on another app's key directly. Instead we spawn a
     * throwaway app_process that re-executes [App] with subcommand [op]: it seteuid's to [uid] and
     * calls keystore2 as that app (binder reports the effective uid). The child runs as root first,
     * so it can read our dex; [App.main] parses `op uid keyId [extraArgs…]`. Returns the child's
     * exit code: 0 done, 1 keystore2 refused, 2 could-not-seteuid, -1 could-not-spawn.
     */
    private fun spawnOwnerOp(
        op: String,
        uid: Int,
        keyId: Long,
        extraArgs: List<String> = emptyList(),
    ): Int {
        return try {
            val cp = System.getProperty("java.class.path")
            if (cp.isNullOrEmpty()) return -1
            val cmd =
                listOf(
                    "/system/bin/app_process",
                    "-Djava.class.path=$cp",
                    "/",
                    "--nice-name=teesim-$op",
                    "org.matrix.teesim.App",
                    op,
                    uid.toString(),
                    keyId.toString(),
                ) + extraArgs
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            val code = p.exitValue()
            SystemLogger.info(
                "spawnOwnerOp('$op', keyId=$keyId, uid=$uid): child exit $code" +
                    if (out.isEmpty()) "" else " | ${out.takeLast(180)}"
            )
            code
        } catch (e: Throwable) {
            SystemLogger.warning("spawnOwnerOp('$op', keyId=$keyId, uid=$uid) spawn failed", e)
            -1
        }
    }

    /**
     * Delete keyentry [keyId] as its owning app [uid] — the owner-scoped delete (see
     * [spawnOwnerOp]). Only the owner's delete evicts keystore2's cache, so a direct database
     * delete is the caller's fallback. Returns 0 deleted, 1 keystore2 refused, 2 could-not-seteuid,
     * -1 could-not-spawn.
     */
    fun deleteKeyByIdAsUid(keyId: Long, uid: Int): Int = spawnOwnerOp("del", uid, keyId)

    /**
     * Fetch keystore2's stored supplementary attestation info for [tag] (e.g. MODULE_HASH's
     * DER-encoded module list) via `IKeystoreService.getSupplementaryAttestationInfo`. Returns the
     * raw bytes, or null if the service is absent, the method is missing (pre-Android-16
     * keystore2), or keystore2 has not yet received the info (`INFO_NOT_AVAILABLE`) — logged either
     * way. The method carries no permission gate in keystore2, so our context is accepted; the
     * bytes are the exact blob keystore2 stores, and their SHA-256 is the MODULE_HASH tag value.
     */
    fun getSupplementaryAttestationInfo(tag: Int): ByteArray? {
        return try {
            val svc = connect() ?: return null
            val method =
                svc.iface.methods.firstOrNull { it.name == "getSupplementaryAttestationInfo" }
            if (method == null) {
                SystemLogger.warning(
                    "Keystore2Service: getSupplementaryAttestationInfo absent (pre-v4 keystore2)"
                )
                return null
            }
            method.invoke(svc.service, tag) as? ByteArray
        } catch (e: Throwable) {
            val cause = (e as? InvocationTargetException)?.targetException ?: e
            SystemLogger.warning(
                "Keystore2Service.getSupplementaryAttestationInfo($tag) failed: ${cause.javaClass.simpleName}: ${cause.message}"
            )
            null
        }
    }

    /**
     * Ask keystore2 to replace the stored public/attestation certificate ([publicCert], the leaf
     * DER) and its chain ([certificateChain], the DER concatenation of the rest) for the key with
     * keyentry id [keyId], leaving the key blob itself untouched. This is how a pre-existing key's
     * attestation is re-rooted to the keybox. Returns true on success; false if the service is
     * absent or the call is rejected — logged either way.
     */
    fun updateSubcomponent(
        keyId: Long,
        publicCert: ByteArray?,
        certificateChain: ByteArray?,
    ): Boolean {
        return try {
            val svc = connect() ?: return false
            svc.iface
                .getMethod(
                    "updateSubcomponent",
                    svc.descriptorClass,
                    ByteArray::class.java,
                    ByteArray::class.java,
                )
                .invoke(svc.service, svc.keyIdDescriptor(keyId), publicCert, certificateChain)
            SystemLogger.info("Keystore2Service: updated attestation certs for key id=$keyId")
            true
        } catch (e: Throwable) {
            val cause = (e as? InvocationTargetException)?.targetException ?: e
            SystemLogger.warning(
                "Keystore2Service.updateSubcomponent($keyId) failed: ${cause.javaClass.simpleName}: ${cause.message}"
            )
            false
        }
    }

    /**
     * Re-root keyentry [keyId]'s stored certificates as its owning app [uid] — the owner-scoped
     * cert update (see [spawnOwnerOp]). The leaf and the rest of the chain go to the child through
     * two short-lived files under [Const.DATA_DIR] (argv can't carry DER cleanly), which the child
     * reads as root before it drops to [uid]. Returns 0 updated, 1 keystore2 refused (or the certs
     * were unreadable), 2 could-not-seteuid, -1 could-not-spawn — the caller falls back to a direct
     * database write on any non-zero result.
     */
    fun updateSubcomponentAsUid(keyId: Long, uid: Int, leaf: ByteArray, chain: ByteArray): Int {
        val dir = java.io.File(Const.DATA_DIR, ".resign").apply { mkdirs() }
        val leafFile = java.io.File(dir, "$keyId.leaf")
        val chainFile = java.io.File(dir, "$keyId.chain")
        return try {
            leafFile.writeBytes(leaf)
            chainFile.writeBytes(chain)
            spawnOwnerOp(
                "resign",
                uid,
                keyId,
                listOf(leafFile.absolutePath, chainFile.absolutePath),
            )
        } catch (e: Throwable) {
            SystemLogger.warning(
                "updateSubcomponentAsUid(keyId=$keyId, uid=$uid) failed: ${e.javaClass.simpleName}: ${e.message}"
            )
            -1
        } finally {
            try {
                leafFile.delete()
            } catch (_: Throwable) {}
            try {
                chainFile.delete()
            } catch (_: Throwable) {}
        }
    }
}
