package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1Set
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.GeneralNameTags
import at.asitplus.awesn1.crypto.pki.X509GeneralNames
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.issuerAltName_2_5_29_18
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.encodeToTlv
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findSubjectAltNames
import at.asitplus.signum.internals.orLazy
import kotlinx.serialization.KSerializer

//TODO: replace with SRDJAN's structure
/**
 * [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) {Subject||Issuer}AlternativeNames (SANs, IANs)
 * container class constructed from a certificate's [extensions] (i.e. [TbsCertificate.extensions] filtered by OID).
 *
 * As this class performs some structural validations upon initialisation, it may throw various kinds of [Throwable]s.
 * These are **not** limited to [Asn1Exception]s, which is why constructor invocation should be wrapped inside
 * a [runRethrowing] block, as done in [findSubjectAltNames] and [findIssuerAltNames].
 *
 * See [RFC 5280, Section 4.2.1.6](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6)
 * for details on the properties of this container class, as they are named accordingly.
 */
sealed interface AlternativeNames {
    val dnsNames: List<String>
    val rfc822Names: List<String>
    val uris: List<String>
    val ipAddresses: List<ByteArray>
    val directoryNames: List<List<RelativeDistinguishedName>>
    val registeredIDs: List<ObjectIdentifier>

    sealed interface X509Representable : AlternativeNames, DerEncodable<X509GeneralNames> {
        val otherNames: List<Asn1Sequence>
        val ediPartyNames: List<Asn1Sequence>
        val x400Addresses: List<Asn1Sequence>
    }

    companion object : DerDecodable<X509GeneralNames, X509Representable> {
        operator fun invoke(asn1Representation: X509GeneralNames): X509Representable =
            X509AlternativeNames(asn1Representation)

        operator fun invoke(
            dnsNames: List<String> = emptyList(),
            rfc822Names: List<String> = emptyList(),
            uris: List<String> = emptyList(),
            ipAddresses: List<ByteArray> = emptyList(),
            directoryNames: List<List<RelativeDistinguishedName>> = emptyList(),
            registeredIDs: List<ObjectIdentifier> = emptyList(),
            otherNames: List<Asn1Sequence> = emptyList(),
            ediPartyNames: List<Asn1Sequence> = emptyList(),
            x400Addresses: List<Asn1Sequence> = emptyList(),
        ): X509Representable = X509AlternativeNames(
            AlternativeNamesContent(
                dnsNames = dnsNames,
                rfc822Names = rfc822Names,
                uris = uris,
                ipAddresses = ipAddresses,
                directoryNames = directoryNames,
                registeredIDs = registeredIDs,
                otherNames = otherNames,
                ediPartyNames = ediPartyNames,
                x400Addresses = x400Addresses,
            )
        )

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<X509GeneralNames>,
            src: Asn1Element,
            der: Der,
        ): X509Representable =
            X509AlternativeNames(der.decodeFromTlv(serializer, src))

        @Throws(Asn1Exception::class)
        fun List<CertificateExtension>.findSubjectAltNames() = runRethrowing {
            find(KnownOIDs.subjectAltName_2_5_29_17)?.let { AlternativeNames(it) }
        }

        @Throws(Asn1Exception::class)
        fun List<CertificateExtension>.findIssuerAltNames() = runRethrowing {
            find(KnownOIDs.issuerAltName_2_5_29_18)?.let { AlternativeNames(it) }
        }

        private fun List<CertificateExtension>.find(oid: ObjectIdentifier): X509GeneralNames? {
            val matches = filterIsInstance<CertificateExtension.X509Representable>().filter { it.oid == oid }
            if (matches.size > 1) throw Asn1StructuralException("More than one extension with oid $oid found")
            return if (matches.isEmpty()) null
            else decodeFromTlv(
                X509GeneralNames.serializer(),
                Asn1Element.parse(matches.first().derEncodedValue),
            ).asn1Representation
        }
    }
}

private class AlternativeNamesContent(
    val dnsNames: List<String>,
    val rfc822Names: List<String>,
    val uris: List<String>,
    val ipAddresses: List<ByteArray>,
    val directoryNames: List<List<RelativeDistinguishedName>>,
    val registeredIDs: List<ObjectIdentifier>,
    val otherNames: List<Asn1Sequence>,
    val ediPartyNames: List<Asn1Sequence>,
    val x400Addresses: List<Asn1Sequence>,
) {
    init {
        ipAddresses.forEach {
            if (it.size != 4 && it.size != 16) throw Asn1StructuralException("Invalid iPAddress Alternative Name found")
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AlternativeNamesContent) return false
        return dnsNames == other.dnsNames &&
                rfc822Names == other.rfc822Names &&
                uris == other.uris &&
                ipAddresses.let {
                    it.size == other.ipAddresses.size &&
                            it.zip(other.ipAddresses).all { (a, b) -> a.contentEquals(b) }
                } &&
                directoryNames == other.directoryNames &&
                registeredIDs == other.registeredIDs &&
                otherNames == other.otherNames &&
                ediPartyNames == other.ediPartyNames &&
                x400Addresses == other.x400Addresses
    }

    override fun hashCode(): Int {
        var result = dnsNames.hashCode()
        result = 31 * result + rfc822Names.hashCode()
        result = 31 * result + uris.hashCode()
        result = 31 * result + ipAddresses.fold(1) { acc, value -> 31 * acc + value.contentHashCode() }
        result = 31 * result + directoryNames.hashCode()
        result = 31 * result + registeredIDs.hashCode()
        result = 31 * result + otherNames.hashCode()
        result = 31 * result + ediPartyNames.hashCode()
        result = 31 * result + x400Addresses.hashCode()
        return result
    }
}

private class X509AlternativeNames private constructor(
    providedContent: AlternativeNamesContent?,
    providedAsn1Representation: X509GeneralNames?,
) : AlternativeNames.X509Representable {

    constructor(content: AlternativeNamesContent) : this(content, null)

    constructor(asn1Representation: X509GeneralNames) : this(null, asn1Representation)

    override val asn1Representation: X509GeneralNames by providedAsn1Representation orLazy {
        X509GeneralNames(content.toEntries())
    }

    private val content: AlternativeNamesContent by providedContent orLazy {
        asn1Representation.entries.toAlternativeNamesContent()
    }

    override val dnsNames: List<String> get() = content.dnsNames
    override val rfc822Names: List<String> get() = content.rfc822Names
    override val uris: List<String> get() = content.uris
    override val ipAddresses: List<ByteArray> get() = content.ipAddresses
    override val directoryNames: List<List<RelativeDistinguishedName>> get() = content.directoryNames
    override val registeredIDs: List<ObjectIdentifier> get() = content.registeredIDs
    override val otherNames: List<Asn1Sequence> get() = content.otherNames
    override val ediPartyNames: List<Asn1Sequence> get() = content.ediPartyNames
    override val x400Addresses: List<Asn1Sequence> get() = content.x400Addresses

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AlternativeNames.X509Representable) return false
        return asn1Representation == other.asn1Representation
    }

    override fun hashCode(): Int = asn1Representation.hashCode()

    override fun toString(): String {
        val bld = StringBuilder("\notherNames=").append(otherNames.joinToString { it.prettyPrint() })
        bld.append("\nrfc822Names=").append(rfc822Names.joinToString())
        bld.append("\ndnsNames=").append(dnsNames.joinToString())
        bld.append("\nx400addresses=").append(x400Addresses.joinToString { it.prettyPrint() })
        bld.append("\ndirectoryNames=").append(directoryNames.joinToString())
        bld.append("\nediPartyNames=").append(ediPartyNames.joinToString { it.prettyPrint() })
        bld.append("\nuris=").append(uris.joinToString())
        @OptIn(ExperimentalStdlibApi::class)
        bld.append("\nipAddresses=").append(ipAddresses.joinToString { it.toHexString(HexFormat.UpperCase) })
        bld.append("\nregisteredIDs=").append(registeredIDs.joinToString())
        return "AlternativeNames(" + bld.toString().prependIndent("  ") + "\n)"
    }
}

private fun AlternativeNamesContent.toEntries(): List<Asn1Element> =
    buildList {
        addAll(otherNames)
        addAll(rfc822Names.map { it.asGeneralName(GeneralNameTags.rfc822Name) })
        addAll(dnsNames.map { it.asGeneralName(GeneralNameTags.dnsName) })
        addAll(x400Addresses)
        addAll(directoryNames.map { rdns ->
            Asn1.Sequence {
                rdns.forEach { +it.encodeToTlv() }
            } withImplicitTag GeneralNameTags.directoryName
        })
        addAll(ediPartyNames)
        addAll(uris.map { it.asGeneralName(GeneralNameTags.uniformResourceIdentifier) })
        addAll(ipAddresses.map { Asn1Primitive(GeneralNameTags.ipAddress, it) })
        addAll(registeredIDs.map {
            Asn1Primitive(GeneralNameTags.registeredID, it.encodeToTlv().content)
        })
    }

private fun String.asGeneralName(tag: Asn1Element.Tag): Asn1Primitive =
    Asn1Primitive(tag, encodeToByteArray())

private fun List<Asn1Element>.toAlternativeNamesContent(): AlternativeNamesContent =
    AlternativeNamesContent(
        dnsNames = parseStringSANs(GeneralNameTags.dnsName),
        rfc822Names = parseStringSANs(GeneralNameTags.rfc822Name),
        uris = parseStringSANs(GeneralNameTags.uniformResourceIdentifier),
        ipAddresses = filter { it.tag == GeneralNameTags.ipAddress }.map {
            it.requirePrimitive("iPAddress").content.also { content ->
                if (content.size != 4 && content.size != 16) {
                    throw Asn1StructuralException("Invalid iPAddress Alternative Name found: ${it.toDerHexString()}")
                }
            }
        },
        directoryNames = filter { it.tag == GeneralNameTags.directoryName }.map {
            it.requireSequence("directoryName").children.map { rdn -> RelativeDistinguishedName.fromTlv(rdn as Asn1Set) }
        },
        registeredIDs = filter { it.tag == GeneralNameTags.registeredID }.map {
            ObjectIdentifier.decodeFromAsn1ContentBytes(it.requirePrimitive("registeredID").content)
        },
        otherNames = filter { it.tag == GeneralNameTags.otherName }.map {
            it.requireSequence("otherName").also { otherName ->
                if (otherName.children.size != 2) {
                    throw Asn1StructuralException("Invalid otherName Alternative Name found (!=2 children): ${it.toDerHexString()}")
                }
                if (otherName.children.last().tag != GeneralNameTags.otherName) {
                    throw Asn1StructuralException("Invalid otherName Alternative Name found (implicit tag != 0): ${it.toDerHexString()}")
                }
                ObjectIdentifier.decodeFromAsn1ContentBytes(otherName.children.first().requirePrimitive("otherName").content)
            }
        },
        ediPartyNames = filter { it.tag == GeneralNameTags.ediPartyName }.map {
            it.requireSequence("ediPartyName").also { partyName ->
                if (partyName.children.size > 2) {
                    throw Asn1StructuralException("Invalid partyName Alternative Name found (>2 children): ${it.toDerHexString()}")
                }
                if (partyName.children.find { child ->
                        child.tag != GeneralNameTags.otherName && child.tag != GeneralNameTags.rfc822Name
                    } != null
                ) {
                    throw Asn1StructuralException("Invalid partyName Alternative Name found (illegal implicit tag): ${it.toDerHexString()}")
                }
            }
        },
        x400Addresses = filter { it.tag == GeneralNameTags.x400Address }.map {
            it.requireSequence("x400Address")
        },
    )

private fun List<Asn1Element>.parseStringSANs(implicitTag: Asn1Element.Tag) =
    filter { it.tag == implicitTag }.map { it.requirePrimitive("string").content.decodeToString() }

private fun Asn1Element.requirePrimitive(name: String): Asn1Primitive =
    this as? Asn1Primitive
        ?: throw Asn1StructuralException("Invalid $name Alternative Name found: ${toDerHexString()}")

private fun Asn1Element.requireSequence(name: String): Asn1Sequence =
    this as? Asn1Sequence
        ?: throw Asn1StructuralException("Invalid $name Alternative Name found: ${toDerHexString()}")

/**
 * Enumeration of implicit tags used to indicate different `SubjectAltName`s.
 */
@Deprecated("Use awesn1 GeneralNameTags instead")
object SubjectAltNameImplicitTags {
    val otherName = GeneralNameTags.otherName
    val rfc822Name = GeneralNameTags.rfc822Name
    val dNSName = GeneralNameTags.dnsName
    val x400Address = GeneralNameTags.x400Address
    val directoryName = GeneralNameTags.directoryName
    val ediPartyName = GeneralNameTags.ediPartyName
    val uniformResourceIdentifier = GeneralNameTags.uniformResourceIdentifier
    val iPAddress = GeneralNameTags.ipAddress
    val registeredID = GeneralNameTags.registeredID
}
