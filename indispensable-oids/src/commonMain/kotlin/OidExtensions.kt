package at.asitplus.signum.indispensable.asn1

import at.asitplus.awesn1.describeAll as awesn1DescribeAll

/**
 * Ensures that known OIDs have their description attached. Call this method if you want human-readable OIDs for debugging.
 *
 * The first call to this function triggers the initialization process of all [KnownOIDs] descriptions.
 * Future calls to this function are a NOOP.
 */
@Deprecated(
    "Moved to at.asitplus.awesn1.describeAll().",
    ReplaceWith("at.asitplus.awesn1.KnownOIDs.describeAll()")
)
fun KnownOIDs.describeAll() {
    at.asitplus.awesn1.KnownOIDs.run { awesn1DescribeAll() }
}
