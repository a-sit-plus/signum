package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation

/**
 * [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) {Subject||Issuer}AlternativeNames (SANs, IANs)
 * container class constructed from a certificate's [TbsCertificate.extensions] (filtered by OID).
 *
 * The contents are exposed as a semantic list of [GeneralName]s. ASN.1 conversion is supplied by
 * this module; certificate accessors read the interpreted SAN/IAN extensions without conversion.
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
            val names = (matchedExtension as? AlternativeNamesExtension)?.generalNames
                ?: throw UnsupportedOperationException("Cannot interpret alternative names in their source representation")
            return AlternativeNames(names)
        }
    }
}

/** Interpreted SAN/IAN content, usable independently of the extension's encoding. */
interface AlternativeNamesExtension : CertificateExtension {
    val generalNames: List<GeneralName>
}

data class SubjectAlternativeName(
    override val generalNames: List<GeneralName>,
    override val critical: Boolean = false,
) : AlternativeNamesExtension {
    override val oid get() = KnownOIDs.subjectAltName_2_5_29_17
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
}

data class IssuerAlternativeName(
    override val generalNames: List<GeneralName>,
    override val critical: Boolean = false,
) : AlternativeNamesExtension {
    override val oid get() = KnownOIDs.issuerAltName_2_5_29_18
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
}

/** Subject alternative names interpreted by the installed PKIX provider. */
val TbsCertificate.subjectAlternativeNames: AlternativeNames?
    get() = with(AlternativeNames) { extensions.findSubjectAltNames() }

/** Issuer alternative names interpreted by the installed PKIX provider. */
val TbsCertificate.issuerAlternativeNames: AlternativeNames?
    get() = with(AlternativeNames) { extensions.findIssuerAltNames() }
