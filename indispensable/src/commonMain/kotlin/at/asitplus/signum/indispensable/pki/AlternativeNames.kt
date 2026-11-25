package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation

/** Interpreted SAN or IAN content, independent of the extension's encoding. */
interface AlternativeNamesExtension : CertificateExtension {
    val generalNames: List<GeneralName>
}

/** The typed names in an [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) SAN or IAN extension. */
class AlternativeNames(val generalNames: List<GeneralName>) : WithSourceRepresentation {

    override val sourceRepresentation = SourceRepresentationStorage()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AlternativeNames) return false
        return generalNames == other.generalNames
    }

    override fun hashCode(): Int = generalNames.hashCode()

    override fun toString(): String =
        "AlternativeNames(" + "\nGeneralNames=${generalNames.joinToString()}".prependIndent("  ") + "\n)"

    companion object {

        /** Returns the interpreted subject alternative names, if available. */
        @Throws(Asn1Exception::class)
        fun List<CertificateExtension>.findSubjectAltNames() =
            find(KnownOIDs.subjectAltName_2_5_29_17)

        /** Returns the interpreted issuer alternative names, if available. */
        @Throws(Asn1Exception::class)
        fun List<CertificateExtension>.findIssuerAltNames() =
            find(KnownOIDs.issuerAltName_2_5_29_18)

        private fun List<CertificateExtension>.find(oid: ObjectIdentifier): AlternativeNames? {
            val matches = asSequence().filter { it.oid == oid }.iterator()
            if (!matches.hasNext()) return null
            val matchedExtension = matches.next()
            if (matches.hasNext()) throw Asn1StructuralException("More than one extension with oid $oid found")
            return (matchedExtension as? AlternativeNamesExtension)?.let { AlternativeNames(it.generalNames) }
        }
    }
}
