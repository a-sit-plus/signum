package at.asitplus.signum.indispensable.asn1.serialization.api

/**
 * Factory for the ASN.1 DER kotlinx-serialization format.
 *
 * Configuration is reserved for future use and currently ignored.
 */
fun DER(config: () -> Unit = {}) = at.asitplus.signum.indispensable.asn1.serialization.Der()

/**
 * Default ASN.1 DER kotlinx-serialization format instance.
 */
val DER = DER {  }
