package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.OidMap.lookupDescription

private val customOidDescriptions = mutableMapOf<ObjectIdentifier, String>()

/**
 * Adds or overrides a description of an Object Identifier. This is useful for communicating context to humans, especially for (but not limited to) debugging.
 * Most well-known OIDs are already described in [OidMap].
 * This method is neither thread-safe not coroutine-safe! Unguarded concurrent calls can cause loss of descriptions.
 * OID descriptions need to live outside the actual OID objects, because this semantic enhancement will never be serialized and thus cannot be deserialized.
 */
fun ObjectIdentifier.describe(description: String) = apply { customOidDescriptions[this] = description }

/**
 * Returns a human-readable description of this OID. Virtually all commonly used OIDs will have this method pull a description from [KnownOIDs]/[OidMap].
 * An OID's description can be set/overridden using [describe]
 */
val ObjectIdentifier.description: String? get() = customOidDescriptions[this] ?: lookupDescription()
