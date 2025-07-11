package at.asitplus.signum.indispensable.asn1

/**
 * Holds known OIDs and their descriptions.
 * If `indispensable-oids` is part of your classpath, call `KnownOIDs.describeAll()` to add descriptions for all
 * known OID constants shipped with the module.
 */
private val oidDescriptions= mutableMapOf<ObjectIdentifier,String>()
object KnownOIDs : MutableMap<ObjectIdentifier, String> by oidDescriptions {

    /**
     * Returns a human-readable description of [key] (if known and loaded).
     * If `indispensable-oids` is part of your classpath, call `KnownOIDs.describeAll()` to add descriptions for all
     * known OID constants shipped with the module.
     */
    override fun get(key: ObjectIdentifier) = super[key]

    /**
     * Adds or overrides a description for [key]. This is useful for communicating context to humans, especially for (but not limited to) debugging.
     * This method is neither thread-safe nor coroutine-safe! Unguarded concurrent calls can cause loss of descriptions.
     * OID descriptions need to live outside the actual OID objects, because this semantic enhancement will never be serialized and thus cannot be deserialized.
     */
    override fun put(key: ObjectIdentifier, value: String): String? = super.put(key, value)

}