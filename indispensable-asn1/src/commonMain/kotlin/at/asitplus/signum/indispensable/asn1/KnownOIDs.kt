package at.asitplus.signum.indispensable.asn1

/**
 * Holds known OIDs and (if provided) OID deescriptions
 * */
object KnownOIDs {

    private val oidDescriptions = mutableMapOf<ObjectIdentifier, String>()

    /**
     * Adds or overrides a description of an Object Identifier. This is useful for communicating context to humans, especially for (but not limited to) debugging.
     * This method is neither thread-safe nor coroutine-safe! Unguarded concurrent calls can cause loss of descriptions.
     * OID descriptions need to live outside the actual OID objects, because this semantic enhancement will never be serialized and thus cannot be deserialized.
     */
    fun describe(oid: ObjectIdentifier, description: String) = apply { oidDescriptions[oid] = description }

    /**
     * Returns a human-readable description of this OID (if known and loaded).
     * If `indispensable-oids` is part of your classpath, call `KnownOIDs.describeAll()` to add descriptions for all
     * known OIDs.
     * An OID's description can be set/overridden using [describe]
     */
    val ObjectIdentifier.description: String? get() = oidDescriptions[this]

}