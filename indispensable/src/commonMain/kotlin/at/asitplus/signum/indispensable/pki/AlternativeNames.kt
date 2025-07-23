package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.runRethrowing
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findSubjectAltNames
import at.asitplus.signum.indispensable.pki.pkiExtensions.GeneralName


/**
 * [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) {Subject||Issuer}AlternativeNames (SANs, IANs)
 * container class constructed from a certificate's [extensions] (i.e. [TbsCertificate.extensions] filtered by OID).
 * Hence, this class is not intended to be used for constructing SANs or IANs, but used to extract them from a certificate.
 *
 * As this class performs some structural validations upon initialisation, it may throw various kinds of [Throwable]s.
 * These are **not** limited to [Asn1Exception]s, which is why constructor invocation should be wrapped inside
 * a [runRethrowing] block, as done in [findSubjectAltNames] and [findIssuerAltNames].
 *
 * See [RFC 5280, Section 4.2.1.6](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6)
 * for details on the properties of this container class, as they are named accordingly.
 */
@ConsistentCopyVisibility
data class AlternativeNames
@Throws(Throwable::class)
private constructor(private val extensions: List<Asn1Element>) {

    val generalNames: List<GeneralName> = parseGeneralName()

    private fun parseGeneralName(): List<GeneralName> =
        extensions.map { GeneralName.decodeFromTlv(it) }

    override fun toString(): String {
        val bld =
            StringBuilder("\nGeneralNames=").append(generalNames.joinToString())
        return "AlternativeNames(" + bld.toString().prependIndent("  ") + "\n)"
    }

    companion object {
        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findSubjectAltNames() = runRethrowing {
            find(KnownOIDs.subjectAltName_2_5_29_17)?.let { AlternativeNames(it) }
        }

        @Throws(Asn1Exception::class)
        fun List<X509CertificateExtension>.findIssuerAltNames() = runRethrowing {
            find(KnownOIDs.issuerAltName_2_5_29_18)?.let { AlternativeNames(it) }
        }

        /**not for public use, since it forces [Asn1EncapsulatingOctetString]*/
        private fun List<X509CertificateExtension>.find(oid: ObjectIdentifier): List<Asn1Element>? {
            val matches = filter { it.oid == oid }
            if (matches.size > 1) throw Asn1StructuralException("More than one extension with oid $oid found")
            return if (matches.isEmpty()) null
            else ((matches.first().value as Asn1EncapsulatingOctetString).children.firstOrNull() as Asn1Sequence?)?.children
        }
    }
}
