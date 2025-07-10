package at.asitplus.signum.indispensable.asn1

/**
 * Ensures that known OIDs have their description attached. Call this method if you want human-readable OIDs for debugging.
 *
 * The first call to this function triggers the initialization process of all [KnownOIDs] descriptions.
 * Future calls to this function are a NOOP.
 */
fun KnownOIDs.describeAll() {
    OidMap.initDescriptions()
}