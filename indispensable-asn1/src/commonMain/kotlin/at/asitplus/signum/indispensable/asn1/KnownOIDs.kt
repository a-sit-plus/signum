package at.asitplus.signum.indispensable.asn1

/**
 * Holds known OIDs and their descriptions.
 * If `indispensable-oids` is part of your classpath, call `KnownOIDs.describeAll()` to add descriptions for all
 * known OID constants shipped with the module.
 */
//we cannot delegate to a mutable map due to https://youtrack.jetbrains.com/issue/KT-79096
object KnownOIDs : MutableMap<ObjectIdentifier,String>{

    private val oidDescriptions = mutableMapOf<ObjectIdentifier, String>()

    override val size: Int
        get() = oidDescriptions.size

    override fun isEmpty(): Boolean {
        return oidDescriptions.isEmpty()
    }

    override fun containsKey(key: ObjectIdentifier): Boolean {
        return oidDescriptions.containsKey(key)
    }

    override fun containsValue(value: String): Boolean {
        return oidDescriptions.containsValue(value)
    }

    /**
     * Returns a human-readable description of [key] (if known and loaded).
     * If `indispensable-oids` is part of your classpath, call `KnownOIDs.describeAll()` to add descriptions for all
     * known OID constants shipped with the module.
     */
    override fun get(key: ObjectIdentifier) = oidDescriptions[key]
    
    override val keys: MutableSet<ObjectIdentifier>
        get() = oidDescriptions.keys
    
    override val values: MutableCollection<String>
        get() = oidDescriptions.values
    
    override val entries: MutableSet<MutableMap.MutableEntry<ObjectIdentifier, String>>
        get() = oidDescriptions.entries

    /**
     * Adds or overrides a description for [key]. This is useful for communicating context to humans, especially for (but not limited to) debugging.
     * This method is neither thread-safe nor coroutine-safe! Unguarded concurrent calls can cause loss of descriptions.
     * OID descriptions need to live outside the actual OID objects, because this semantic enhancement will never be serialized and thus cannot be deserialized.
     */
    override fun put(
        key: ObjectIdentifier,
        value: String
    ): String? {
        return oidDescriptions.put(key, value)
    }

    override fun remove(key: ObjectIdentifier): String? {
        return oidDescriptions.remove(key)
    }

    override fun putAll(from: Map<out ObjectIdentifier, String>) {
        oidDescriptions.putAll(from)
    }

    override fun clear() {
        oidDescriptions.clear()
    }

}