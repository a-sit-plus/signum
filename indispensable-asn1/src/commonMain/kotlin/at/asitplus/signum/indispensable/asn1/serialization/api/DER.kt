package at.asitplus.signum.indispensable.asn1.serialization.api

import at.asitplus.signum.indispensable.asn1.serialization.DerBuilder
import at.asitplus.signum.indispensable.asn1.serialization.Der

/**
 * Factory for the ASN.1 DER kotlinx-serialization format.
 *
 * @param config optional builder block for DER settings (for example `encodeDefaults`)
 */
fun DER(config: DerBuilder.() -> Unit = {}) =
    DerBuilder()
        .apply(config)
        .build()
        .let { Der(it) }

/**
 * Default ASN.1 DER kotlinx-serialization format instance.
 */
val DER = DER {  }
