package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.DERTags.toImplicitTag
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findSubjectAltNames


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

    val dnsNames: List<String>? = parseStringSANs(SubjectAltNameImplicitTags.dNSName)
    val rfc822Names: List<String>? = parseStringSANs(SubjectAltNameImplicitTags.rfc822Name)
    val uris: List<String>? = parseStringSANs(SubjectAltNameImplicitTags.uniformResourceIdentifier)

    val ipAddresses: List<ByteArray> = extensions.filter { it.tag == SubjectAltNameImplicitTags.iPAddress }.apply {
        forEach {
            if (it !is Asn1Primitive)
                throw Asn1StructuralException("Invalid iPAddress Alternative Name found: ${it.toDerHexString()}")
            else if (it.content.size != 4 && it.content.size != 16) throw Asn1StructuralException("Invalid iPAddress Alternative Name found: ${it.toDerHexString()}")
        }
    }.map { (it as Asn1Primitive).content }

    val directoryNames: List<List<RelativeDistinguishedName>> =
        extensions.filter { it.tag == SubjectAltNameImplicitTags.directoryName }.apply {
            forEach {
                if (it !is Asn1Sequence) throw Asn1StructuralException("Invalid directoryName Alternative Name found: ${it.toDerHexString()}")
            }
        }.map { (it as Asn1Sequence).children.map { RelativeDistinguishedName.decodeFromTlv(it as Asn1Set) } }

    val otherNames: List<Asn1Sequence> =
        extensions.filter { it.tag == SubjectAltNameImplicitTags.otherName }.apply {
            forEach {
                if (it !is Asn1Sequence) throw Asn1StructuralException("Invalid otherName Alternative Name found: ${it.toDerHexString()}")
            }
        }.map {
            (it as Asn1Sequence).also {
                if (it.children.size != 2) throw Asn1StructuralException("Invalid otherName Alternative Name found (!=2 children): ${it.toDerHexString()}")
                if (it.children.last().tag != 0u.toImplicitTag()) throw Asn1StructuralException("Invalid otherName Alternative Name found (implicit tag != 0): ${it.toDerHexString()}")
                ObjectIdentifier.parse((it.children.first() as Asn1Primitive).content) //this throws if something is off
            }
        }
    val ediPartyNames: List<Asn1Sequence> =
        extensions.filter { it.tag == SubjectAltNameImplicitTags.ediPartyName }.apply {
            forEach {
                if (it !is Asn1Sequence) throw Asn1StructuralException("Invalid ediPartyName Alternative Name found: ${it.toDerHexString()}")
            }
        }.map {
            (it as Asn1Sequence).also {
                if (it.children.size > 2) throw Asn1StructuralException("Invalid partyName Alternative Name found (>2 children): ${it.toDerHexString()}")
                if (it.children.find { it.tag != 0u.toImplicitTag() && it.tag != 1u.toImplicitTag() } != null) throw Asn1StructuralException(
                    "Invalid partyName Alternative Name found (illegal implicit tag): ${it.toDerHexString()}"
                )
                //TODO: strict string parsing
            }
        }

    val x400Addresses: List<Asn1Sequence> =
        extensions.filter { it.tag == SubjectAltNameImplicitTags.x400Address }.apply {
            forEach {
                if (it !is Asn1Sequence) throw Asn1StructuralException("Invalid x400Address Alternative Name found: ${it.toDerHexString()}")
            }
        }.map {
            (it as Asn1Sequence).also {
                //TODO: strict structural parsing
            }
        }

    val registeredIDs: List<ObjectIdentifier> =
        extensions.filter { it.tag == SubjectAltNameImplicitTags.registeredID }.apply {
            forEach {
                if (it !is Asn1Primitive) throw Asn1StructuralException("Invalid registeredID Alternative Name found: ${it.toDerHexString()}")
            }
        }.map { ObjectIdentifier.parse((it as Asn1Primitive).content) }

    private fun parseStringSANs(implicitTag: UByte) =
        extensions.filter { it.tag == implicitTag }.apply {
            forEach { if (it !is Asn1Primitive) throw Asn1StructuralException("Invalid dnsName Alternative Name found: ${it.toDerHexString()}") }
        }.map { (it as Asn1Primitive).content.decodeToString() }

    override fun toString(): String {
        val bld =
            StringBuilder("\notherNames=").append(otherNames.joinToString { it.prettyPrint() })
        bld.append("\nrfc822Names=").append(rfc822Names?.joinToString())
        bld.append("\ndnsNames=").append(dnsNames?.joinToString())
        bld.append("\nx400addresses=").append(x400Addresses.joinToString { it.prettyPrint() })
        bld.append("\ndirectoryNames=").append(directoryNames.joinToString())
        bld.append("\nediPartyNames=").append(ediPartyNames.joinToString { it.prettyPrint() })
        bld.append("\nuris=").append(uris?.joinToString())
        @OptIn(ExperimentalStdlibApi::class)
        bld.append("\nipAddresses=").append(ipAddresses.joinToString { it.toHexString(HexFormat.UpperCase) })
        bld.append("\nregisteredIDs=").append(registeredIDs.joinToString())
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

/**
 * Enumeration of implicit tags used to indicate different `SubjectAltName`s
 */
object SubjectAltNameImplicitTags {
    val otherName = 0u.toImplicitTag()
    val rfc822Name = 1u.toImplicitTag()
    val dNSName = 2u.toImplicitTag()
    val x400Address = 3u.toImplicitTag()
    val directoryName = 4u.toImplicitTag()
    val ediPartyName = 5u.toImplicitTag()
    val uniformResourceIdentifier = 6u.toImplicitTag()
    val iPAddress = 7u.toImplicitTag()
    val registeredID = 8u.toImplicitTag()
}
