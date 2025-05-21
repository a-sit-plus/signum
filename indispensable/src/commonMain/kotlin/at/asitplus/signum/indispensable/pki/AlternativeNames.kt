package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.runRethrowing
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findSubjectAltNames
import at.asitplus.signum.indispensable.pki.pkiExtensions.GeneralNameOption
import at.asitplus.signum.indispensable.pki.pkiExtensions.UriName
import at.asitplus.signum.indispensable.pki.pkiExtensions.X500Name


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
    val uris: List<UriName>? =
        extensions.filter { GeneralNameOption.NameType.fromTagValue(it.tag.tagValue) == GeneralNameOption.NameType.URI }
            .map { ext ->
                UriName.doDecode(ext.asPrimitive())
            }

    val ipAddresses: List<ByteArray> =
        extensions.filter { it.tag == SubjectAltNameImplicitTags.iPAddress }.apply {
            forEach {
                if (it !is Asn1Primitive)
                    throw Asn1StructuralException("Invalid iPAddress Alternative Name found: ${it.toDerHexString()}")
                else if (it.content.size != 4 && it.content.size != 16) throw Asn1StructuralException(
                    "Invalid iPAddress Alternative Name found: ${it.toDerHexString()}"
                )
            }
        }.map { (it as Asn1Primitive).content }

    val directoryNames: List<X500Name> =
        extensions.filter { GeneralNameOption.NameType.fromTagValue(it.tag.tagValue) == GeneralNameOption.NameType.DIRECTORY }
            .map { ext ->
                ext as? Asn1ExplicitlyTagged
                    ?: throw Asn1StructuralException("Invalid directoryName Alternative Name found: ${ext.toDerHexString()}")

                val sequence = ext.children.singleOrNull() as? Asn1Sequence
                    ?: throw Asn1StructuralException("Invalid directoryName Alternative Name found: ${ext.toDerHexString()}")

                X500Name.decodeFromTlv(sequence)
            }

    val otherNames: List<Asn1Sequence> =
        extensions.filter { it.tag == SubjectAltNameImplicitTags.otherName }.apply {
            forEach {
                if (it !is Asn1Sequence) throw Asn1StructuralException("Invalid otherName Alternative Name found: ${it.toDerHexString()}")
            }
        }.map {
            (it as Asn1Sequence).also {
                if (it.children.size != 2) throw Asn1StructuralException("Invalid otherName Alternative Name found (!=2 children): ${it.toDerHexString()}")
                if (it.children.last().tag != SubjectAltNameImplicitTags.otherName) throw Asn1StructuralException(
                    "Invalid otherName Alternative Name found (implicit tag != 0): ${it.toDerHexString()}"
                )
                ObjectIdentifier.decodeFromAsn1ContentBytes((it.children.first() as Asn1Primitive).content) //this throws if something is off
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
                if (it.children.find { it.tag != SubjectAltNameImplicitTags.otherName && it.tag != SubjectAltNameImplicitTags.rfc822Name } != null) throw Asn1StructuralException(
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
        }.map { ObjectIdentifier.decodeFromAsn1ContentBytes((it as Asn1Primitive).content) }

    private fun parseStringSANs(implicitTag: Asn1Element.Tag) =
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
        bld.append("\nipAddresses=")
            .append(ipAddresses.joinToString { it.toHexString(HexFormat.UpperCase) })
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
    val otherName = Asn1.ImplicitTag(0uL)
    val rfc822Name = Asn1.ImplicitTag(1uL)
    val dNSName = Asn1.ImplicitTag(2uL)
    val x400Address = Asn1.ImplicitTag(3uL)
    val directoryName = Asn1.ImplicitTag(4uL)
    val ediPartyName = Asn1.ImplicitTag(5uL)
    val uniformResourceIdentifier = Asn1.ImplicitTag(6uL)
    val iPAddress = Asn1.ImplicitTag(7uL)
    val registeredID = Asn1.ImplicitTag(8uL)
}
