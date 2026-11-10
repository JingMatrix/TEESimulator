package org.matrix.teesim

/**
 * What a profile field left empty resolves to, and where that value came from.
 *
 * A profile states what it wants attested; every field it leaves empty takes a default, and this is
 * the only place that decides what the default is. Two sources answer, in order:
 *
 * 1. the keybox the profile signs with, when it is an RKP keybox that records the device it was
 *    provisioned for — its verified boot hash, its manufacturer, and the build fingerprint, which
 *    spells out the brand, product and device names;
 * 2. the harvest, which is this device: the value the real TEE attested, or the one the daemon read
 *    from the OS when the attested leaf carried none.
 *
 * The keybox comes first because it is the thing signing the chain. A record that reports this
 * device under a keybox provisioned for another contradicts the keybox itself, and both halves sit
 * in the same certificate for anyone to compare. The harvest is never modified to say otherwise —
 * it is what this device is, and it stays the answer for every field no keybox speaks to.
 */
object ProfileDefaults {

    /**
     * One field's default: the value, and whether the keybox or this device is the one saying it.
     */
    data class Default(val value: String, val fromKeybox: Boolean)

    /**
     * The device-identity fields a keybox can speak to. The rest of the ids (model, serial, imei,
     * imei2, meid) have no keybox source at all and always default to the harvest.
     */
    private val KEYBOX_IDS = setOf("brand", "device", "product", "manufacturer")

    /** Every field whose default this resolves, in the order the WebUI lists them. */
    val FIELDS =
        listOf(
            "brand",
            "device",
            "product",
            "manufacturer",
            "model",
            "serial",
            "imei",
            "imei2",
            "meid",
            "verifiedBootHash",
        )

    /**
     * The defaults in force for the keybox named [keyboxName], against [harvest]. Reads the keybox
     * from disk, which is once per config push (and once per WebUI request that asks); the file is
     * small and the parse is not on any hot path. A field with no value from either source is
     * absent, which is what declining to attest it looks like.
     */
    fun of(keyboxName: String, harvest: Harvester.Record): Map<String, Default> =
        from(KeyboxInspector.provisioning(keyboxName), harvest)

    /** The same, for a statement already read. */
    fun from(stated: KeyboxDetail.Provisioning?, harvest: Harvester.Record): Map<String, Default> =
        buildMap {
            for (field in FIELDS) {
                val fromKeybox =
                    when {
                        field == "verifiedBootHash" -> stated?.bootHash?.toHex()
                        field in KEYBOX_IDS -> stated?.ids?.get(field)
                        else -> null
                    }
                val value =
                    fromKeybox
                        ?: when (field) {
                            "verifiedBootHash" -> harvest.effectiveBootHash().toHex()
                            else -> harvest.effective(field)
                        }
                if (value.isNotBlank()) put(field, Default(value, fromKeybox != null))
            }
        }

    /**
     * The value profile [p] presents for [field]: its own when it names one, else the default. A
     * blank result means neither source has it, which declines that field.
     */
    fun effective(p: ConfigStore.ProfileConfig, field: String, defaults: Map<String, Default>) =
        own(p, field).ifBlank { defaults[field]?.value ?: "" }

    /**
     * The verified boot hash profile [p] attests: its own spoof, else the keybox's, else this
     * device's. Always 32 real bytes — the harvest's own fallback guarantees the last of those is
     * never the all-zero value an unlocked bootloader reports.
     */
    fun bootHash(p: ConfigStore.ProfileConfig, harvest: Harvester.Record): ByteArray =
        bootHash(p, harvest, of(p.keybox, harvest))

    /** The same, for a caller that has already resolved [p]'s defaults. */
    fun bootHash(
        p: ConfigStore.ProfileConfig,
        harvest: Harvester.Record,
        defaults: Map<String, Default>,
    ): ByteArray =
        hexBytes32(effective(p, "verifiedBootHash", defaults)) ?: harvest.effectiveBootHash()

    /** What the profile itself says for [field], before any default. */
    private fun own(p: ConfigStore.ProfileConfig, field: String): String =
        when (field) {
            "brand" -> p.brand
            "device" -> p.device
            "product" -> p.product
            "manufacturer" -> p.manufacturer
            "model" -> p.model
            "serial" -> p.serial
            "imei" -> p.imei
            "imei2" -> p.imei2
            "meid" -> p.meid
            "verifiedBootHash" -> p.verifiedBootHash
            else -> ""
        }

    private fun hexBytes32(hex: String): ByteArray? {
        if (hex.length != 64 || !hex.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
            return null
        }
        return ByteArray(32) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }
}
