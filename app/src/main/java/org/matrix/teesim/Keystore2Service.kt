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

    /** Resolve keystore2's binder and reflect the classes we call, or null (logged) if unavailable. */
    private fun connect(): Svc? {
        val serviceManager = Class.forName("android.os.ServiceManager")
        val binder =
            serviceManager.getMethod("getService", String::class.java).invoke(null, SERVICE) as? IBinder
        if (binder == null) {
            SystemLogger.warning("Keystore2Service: service $SERVICE not found")
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
