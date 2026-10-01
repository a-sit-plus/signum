package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509GeneralNames
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.issuerAltName_2_5_29_18
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.internals.orLazy

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
sealed interface AlternativeNames : Encodable {

    val generalNames: List<GeneralName>

    companion object : Decodable<AlternativeNames> {

        operator fun invoke(asn1Representation: X509GeneralNames): AlternativeNames =
            X509AlternativeNames(null, asn1Representation)

        fun fromGeneralNames(generalNames: List<GeneralName>): AlternativeNames =
            X509AlternativeNames(generalNames, null)

        @Throws(Asn1Exception::class)
        fun fromAsn1Representation(element: X509GeneralNames): AlternativeNames =
            X509AlternativeNames(null, element)

        @Throws(Asn1Exception::class)
        fun List<CertificateExtension>.findSubjectAltNames() = runRethrowing {
            find(KnownOIDs.subjectAltName_2_5_29_17)?.let { AlternativeNames(it) }
        }

        @Throws(Asn1Exception::class)
        fun List<CertificateExtension>.findIssuerAltNames() = runRethrowing {
            find(KnownOIDs.issuerAltName_2_5_29_18)?.let { AlternativeNames(it) }
        }

        private fun List<CertificateExtension>.find(oid: ObjectIdentifier): X509GeneralNames? {
            val matches = mapNotNull { it.asn1Representation }.filter { it.oid == oid }
            if (matches.size > 1) throw Asn1StructuralException("More than one extension with oid $oid found")
            return if (matches.isEmpty()) null
            else at.asitplus.awesn1.serialization.DER.decodeFromTlv(
                X509GeneralNames.serializer(),
                Asn1Element.parse(matches.first().value),
            )
        }
    }
}

private class X509AlternativeNames(
    providedGeneralNames: List<GeneralName>?,
    providedAsn1Representation: X509GeneralNames?,
) : AlternativeNames {
    init { require((providedGeneralNames != null) != (providedAsn1Representation != null)) }

    override val representations: Map<Encodable.Representation, Any>

        get() = mapOf(X509 to x509Model)

    internal val x509Model: X509GeneralNames by providedAsn1Representation orLazy {
        X509GeneralNames(generalNames.map { requireNotNull(it.asn1Representation) { "GeneralName has no X.509 representation" } })
    }

    override val generalNames: List<GeneralName> by providedGeneralNames orLazy {
        x509Model.entries.map { GeneralName.fromAsn1Representation(it) }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AlternativeNames) return false
        return x509Model == other.asn1Representation
    }

    override fun hashCode(): Int = x509Model.hashCode()

    override fun toString(): String =
        "AlternativeNames(" + "\nGeneralNames=${generalNames.joinToString()}".prependIndent("  ") + "\n)"
}
