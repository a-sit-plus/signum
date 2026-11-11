package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension
import kotlinx.serialization.Serializable

/**
 * Basic Constraints Extension
 * RFC 5280: 4.2.1.9.
 * Defines whether the subject of the cert is a CA and how deep a cert path may exist through that CA.
 * A `null` [pathLenConstraint] on a CA means unbounded (encoded by omitting `pathLenConstraint`).
*/
data class BasicConstraints(
    val ca: Boolean,
    val pathLenConstraint: UInt? = null,
    override val critical: Boolean = true,
) : CertificateExtension {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.basicConstraints_2_5_29_19
    }

    init { require(ca || pathLenConstraint == null) { "Only CA certificates may have a path length constraint" } }

    /**
     * ASN.1 schema from [RFC 5280, Section 4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9).
     *
     * ```
     * BasicConstraints ::= SEQUENCE {
     *   cA                BOOLEAN DEFAULT FALSE,
     *   pathLenConstraint INTEGER (0..MAX) OPTIONAL }
     * ```
     * Used by the ASN.1 provider for encoding and decoding.
     */
    @Serializable
    internal class Asn1Representation(
        val cA: Boolean? = null,
        val pathLenConstraint: Asn1Integer? = null,
    )
}
