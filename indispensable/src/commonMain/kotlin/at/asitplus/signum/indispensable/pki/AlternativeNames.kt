package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1

/**
 * [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) {Subject||Issuer}AlternativeNames (SANs, IANs)
 * container class constructed from a certificate's [TbsCertificate.extensions] (filtered by OID).
 *
 * The contents are exposed as a typed list of [GeneralName]s, which is the single source of truth.
 * As this class parses [GeneralName]s upon initialisation, it may throw various kinds of [Throwable]s.
 * These are **not** limited to [Asn1Exception]s, which is why construction should be wrapped inside a
 * [runRethrowing] block, as done in [findSubjectAltNames] and [findIssuerAltNames].
 *
 * See [RFC 5280, Section 4.2.1.6](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6).
 */
class AlternativeNames(val generalNames: List<GeneralName>) : WithSourceRepresentation {

    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AlternativeNames) return false
        return generalNames == other.generalNames
    }

    override fun hashCode(): Int = generalNames.hashCode()

    override fun toString(): String =
        "AlternativeNames(" + "\nGeneralNames=${generalNames.joinToString()}".prependIndent("  ") + "\n)"

    companion object {

        @Throws(Asn1Exception::class)
        fun List<CertificateExtension>.findSubjectAltNames() =
            find(KnownOIDs.subjectAltName_2_5_29_17)

        @Throws(Asn1Exception::class)
        fun List<CertificateExtension>.findIssuerAltNames() =
            find(KnownOIDs.issuerAltName_2_5_29_18)

        private fun List<CertificateExtension>.find(oid: ObjectIdentifier): AlternativeNames? = runRethrowing {
            val matches = asSequence().filter { it.oid == oid }.iterator()
            if (!matches.hasNext()) return null
            val matchedExtension = matches.next()
            if (matches.hasNext()) throw Asn1StructuralException("More than one extension with oid $oid found")
            return AlternativeNames.fromAsn1(derBytes = matchedExtension.asn1.toRepresentation().value)
        }
    }
}
