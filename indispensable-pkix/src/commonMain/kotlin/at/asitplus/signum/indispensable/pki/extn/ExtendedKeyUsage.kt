package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension

/**
 * Extended Key Usage extension: `ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId`.
 * RFC 5280 §4.2.1.12.
 */
data class ExtendedKeyUsage(
    val keyUsages: Set<ObjectIdentifier>,
    override val critical: Boolean = false,
) : CertificateExtension {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.extKeyUsage
    }
}
