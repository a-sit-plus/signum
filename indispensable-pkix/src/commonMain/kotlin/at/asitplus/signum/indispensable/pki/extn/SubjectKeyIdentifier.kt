package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension

/**
 * Subject Key Identifier extension: `SubjectKeyIdentifier ::= KeyIdentifier` (an OCTET STRING).
 * RFC 5280 §4.2.1.2 — MUST be non-critical.
 */
data class SubjectKeyIdentifier(
    val keyIdentifier: ByteArray,
    override val critical: Boolean = false,
) : CertificateExtension {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.subjectKeyIdentifier
    }

    override fun equals(other: Any?): Boolean = other is SubjectKeyIdentifier && critical == other.critical && keyIdentifier.contentEquals(other.keyIdentifier)
    override fun hashCode(): Int = 31 * keyIdentifier.contentHashCode() + critical.hashCode()
}
