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

    /**
     * Ask keystore2 to delete the key with keyentry id [keyId]. Returns true on success; false if the
     * service is absent or the call is rejected (e.g. SELinux denies our context) — logged either way.
     */
    fun deleteKeyById(keyId: Long): Boolean {
        return try {
            val serviceManager = Class.forName("android.os.ServiceManager")
            val binder =
                serviceManager.getMethod("getService", String::class.java).invoke(null, SERVICE) as? IBinder
            if (binder == null) {
                SystemLogger.warning("Keystore2Service: service $SERVICE not found")
                return false
            }

            val stub = Class.forName("android.system.keystore2.IKeystoreService\$Stub")
            val service = stub.getMethod("asInterface", IBinder::class.java).invoke(null, binder)
            val iface = Class.forName("android.system.keystore2.IKeystoreService")

            val descriptorClass = Class.forName("android.system.keystore2.KeyDescriptor")
            val descriptor = descriptorClass.getConstructor().newInstance()
            descriptorClass.getField("domain").setInt(descriptor, DOMAIN_KEY_ID)
            descriptorClass.getField("nspace").setLong(descriptor, keyId)
            // alias and blob stay null: KEY_ID addresses the key directly.

            iface.getMethod("deleteKey", descriptorClass).invoke(service, descriptor)
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
}
