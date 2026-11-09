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

internal object AlternativeNamesAsn1Provider : CertificateExtensionProvider {
    override fun decodeFromAsn1(asn1: at.asitplus.awesn1.crypto.pki.X509CertificateExtension): CertificateExtension? = when (asn1.oid) {
        KnownOIDs.subjectAltName_2_5_29_17 -> SubjectAlternativeName(AlternativeNames.fromAsn1(asn1.value).generalNames, asn1.critical)
        KnownOIDs.issuerAltName_2_5_29_18 -> IssuerAlternativeName(AlternativeNames.fromAsn1(asn1.value).generalNames, asn1.critical)
        else -> null
    }
    override fun encodeToAsn1(value: CertificateExtension): at.asitplus.awesn1.crypto.pki.X509CertificateExtension? =
        (value as? AlternativeNamesExtension)?.let {
            at.asitplus.awesn1.crypto.pki.X509CertificateExtension(it.oid, it.critical, AlternativeNames(it.generalNames).asn1.toDer())
        }
}
