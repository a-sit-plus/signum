package at.asitplus.signum.indispensable.asn1

/**
 * Holds known OIDs and (if provided) OID deescriptions
 * */
object KnownOIDs {

    private val oidDescriptions = mutableMapOf<ObjectIdentifier, String>()

    /**
     * Adds or overrides a description of an Object Identifier. This is useful for communicating context to humans, especially for (but not limited to) debugging.
     * Most well-known OIDs are already described in [OidMap].
     * This method is neither thread-safe nor coroutine-safe! Unguarded concurrent calls can cause loss of descriptions.
     * OID descriptions need to live outside the actual OID objects, because this semantic enhancement will never be serialized and thus cannot be deserialized.
     */
    fun ObjectIdentifier.setDescription(description: String) = apply { oidDescriptions[this] = description }

    /**
     * Returns a human-readable description of this OID. Virtually all commonly used OIDs will have this method pull a description from [KnownOIDs]/[OidMap].
     * An OID's description can be set/overridden using [setDescription]
     */
    val ObjectIdentifier.description: String? get() = oidDescriptions[this]

}