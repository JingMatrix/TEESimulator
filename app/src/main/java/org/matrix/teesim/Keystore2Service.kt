package org.matrix.teesim

import android.os.IBinder
import java.lang.reflect.InvocationTargetException

/**
 * Reflective bridge to keystore2's binder service (`android.system.keystore2.IKeystoreService`), used
 * to delete a key the proper way: asking keystore2 to remove it in its own privileged context, rather
 * than editing its database from underneath it. Reflection keeps the daemon free of keystore2's large
 * AIDL surface — the real classes resolve on the device at runtime.
 *
 * A key is addressed by `Domain.KEY_ID`, so keystore2 looks it up by its own keyentry id and needs no
 * namespace or alias from us; it still enforces its own access control, so a caller our SELinux context
 * isn't allowed to touch is rejected — which the caller treats as "fall back to a direct database
 * delete".
 */
object Keystore2Service {

    private const val SERVICE = "android.system.keystore2.IKeystoreService/default"
    private const val DOMAIN_KEY_ID = 4 // android.system.keystore2.Domain.KEY_ID

    /** The resolved IKeystoreService: its interface class, the service instance, and KeyDescriptor class. */
    private class Svc(val iface: Class<*>, val service: Any?, val descriptorClass: Class<*>)

    /** Resolve keystore2's binder and reflect the classes we call, or null (logged) if unavailable. A
     *  freshly spawned delete-helper can outrun keystore2's service registration at boot, so wait
     *  (bounded) for the service to appear, as the main branch does. */
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
     * Ask keystore2 to delete the key with keyentry id [keyId]. Returns true on success; false if the
     * service is absent or the call is rejected (e.g. SELinux denies our context) — logged either way.
     */
    fun deleteKeyById(keyId: Long): Boolean {
        return try {
            val svc = connect() ?: return false
            svc.iface.getMethod("deleteKey", svc.descriptorClass)
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
     * Delete keyentry [keyId] as its owning app [uid]. keystore2 only lets a key's owner delete it (and
     * only that evicts its cache), so we cannot remove another app's key directly — we spawn a child
     * app_process that seteuid's to [uid] before calling keystore2 (binder reports the effective uid).
     * The child runs as root first, so it can read our dex; App.main handles the "del" arguments. Returns
     * the child's exit code: 0 deleted, 1 keystore2 refused, 2 could-not-seteuid, -1 could-not-spawn.
     */
    fun deleteKeyByIdAsUid(keyId: Long, uid: Int): Int {
        return try {
            val cp = System.getProperty("java.class.path")
            if (cp.isNullOrEmpty()) return -1
            val cmd = listOf(
                "/system/bin/app_process", "-Djava.class.path=$cp", "/",
                "--nice-name=teesim-del", "org.matrix.teesim.App", "del", uid.toString(), keyId.toString(),
            )
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            val code = p.exitValue()
            SystemLogger.info(
                "deleteKeyByIdAsUid(keyId=$keyId, uid=$uid): child exit $code" +
                    if (out.isEmpty()) "" else " | ${out.takeLast(180)}"
            )
            code
        } catch (e: Throwable) {
            SystemLogger.warning("deleteKeyByIdAsUid(keyId=$keyId, uid=$uid) spawn failed", e)
            -1
        }
    }

    /**
     * Ask keystore2 to replace the stored public/attestation certificate ([publicCert], the leaf DER)
     * and its chain ([certificateChain], the DER concatenation of the rest) for the key with keyentry id
     * [keyId], leaving the key blob itself untouched. This is how a pre-existing key's attestation is
     * re-rooted to the keybox. Returns true on success; false if the service is absent or the call is
     * rejected — logged either way.
     */
    fun updateSubcomponent(keyId: Long, publicCert: ByteArray?, certificateChain: ByteArray?): Boolean {
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

}
