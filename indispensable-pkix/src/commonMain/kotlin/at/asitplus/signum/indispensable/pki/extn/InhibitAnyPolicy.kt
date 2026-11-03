package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension

/**
 * Inhibit Any-Policy Extension
 * This extension specifies the number of certs allowed in a chain before anyPolicy is no longer permitted
 * RFC 5280: 4.2.1.14.
 * */
data class InhibitAnyPolicy(
    val skipCerts: Int,
    override val critical: Boolean = true,
) : CertificateExtension {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.inhibitAnyPolicy
    }

    init { require(skipCerts >= 0) { "skipCerts must be non-negative" } }
}
