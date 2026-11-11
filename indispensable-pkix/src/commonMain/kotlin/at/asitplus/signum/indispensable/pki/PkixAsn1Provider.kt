package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.x500.*
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.Serializable

@Serializable
private data class EdiPartyWire(
    @Asn1Tag(0u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val nameAssigner: ExplicitlyTagged<Asn1String>? = null,
    @Asn1Tag(1u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val partyName: ExplicitlyTagged<Asn1String>,
) {
    init {
        require(listOfNotNull(nameAssigner?.value, partyName.value).all {
            (it is Asn1String.Teletex || it is Asn1String.Printable || it is Asn1String.Universal ||
                    it is Asn1String.UTF8 || it is Asn1String.BMP) && it.isValid != false
        }) { "EDI names must contain valid DirectoryStrings" }
    }
}

/** ASN.1 is one representation of the PKIX types; dispatch uses the existing provider mechanism. */
object PkixAsn1Provider : CertificateExtensionProvider, GeneralNameFormatProvider {
    override fun decodeFromAsn1(asn1: X509CertificateExtension): CertificateExtension? {
        return with(asn1) {
            when (oid) {
                BasicConstraints.oid -> Signum.Der.decodeFromByteArray<BasicConstraintsBody>(value).let {
                    val ca = it.cA ?: false
                    BasicConstraints(ca, it.pathLenConstraint?.toLong()?.also { length ->
                        require(length in 0..UInt.MAX_VALUE.toLong()) { "Invalid path length constraint" }
                    }?.toUInt(), critical)
                }
                KeyUsage.oid -> KeyUsage(UsageBit.parseExtension(Signum.Der.decodeFromByteArray<Asn1BitString>(value)), critical)
                SubjectKeyIdentifier.oid -> SubjectKeyIdentifier(Signum.Der.decodeFromByteArray<ByteArray>(value), critical)
                AuthorityKeyIdentifier.oid -> Signum.Der.decodeFromByteArray<AuthorityKeyIdentifierBody>(value).let {
                    AuthorityKeyIdentifier(it.keyIdentifier, it.authorityCertIssuer?.map { name -> GeneralName.fromAsn1(name) }.orEmpty(), it.authorityCertSerialNumber?.toBigInteger(), critical)
                }
                ExtendedKeyUsage.oid -> ExtendedKeyUsage(Signum.Der.decodeFromByteArray<List<ObjectIdentifier>>(value).toSet(), critical)
                InhibitAnyPolicy.oid -> InhibitAnyPolicy(Signum.Der.decodeFromByteArray<Asn1Integer>(value).toInt(), critical)
                PolicyConstraints.oid -> Signum.Der.decodeFromByteArray<PolicyConstraintsBody>(value).let {
                    PolicyConstraints(it.requireExplicitPolicy?.toInt(), it.inhibitPolicyMapping?.toInt(), critical)
                }
                PolicyMappings.oid -> PolicyMappings(Signum.Der.decodeFromByteArray<List<CertificatePolicyMap>>(value), critical)
                CertificatePolicies.oid -> CertificatePolicies(decodeCertificatePolicies(value), critical)
                KnownOIDs.subjectAltName_2_5_29_17 -> SubjectAlternativeName(AlternativeNames.fromAsn1(value).generalNames, critical)
                KnownOIDs.issuerAltName_2_5_29_18 -> IssuerAlternativeName(AlternativeNames.fromAsn1(value).generalNames, critical)
                NameConstraints.oid -> Signum.Der.decodeFromByteArray<NameConstraintsBody>(value).let {
                    NameConstraints(
                        it.permitted?.let { trees -> GeneralSubtrees(trees.map { tree -> GeneralSubtree.fromAsn1(tree) }) },
                        it.excluded?.let { trees -> GeneralSubtrees(trees.map { tree -> GeneralSubtree.fromAsn1(tree) }) },
                        critical,
                    )
                }
                else -> null
            }
        }
    }

    override fun encodeToAsn1(value: CertificateExtension): X509CertificateExtension? {
        val body = when (value) {
            is AlternativeNamesExtension -> AlternativeNames(value.generalNames).asn1.toDer()
            is BasicConstraints -> Signum.Der.encodeToByteArray(BasicConstraintsBody(
                value.ca.takeIf { it }, value.pathLenConstraint?.let { Asn1Integer(it) },
            ))
            is KeyUsage -> Signum.Der.encodeToByteArray(Asn1BitString(BitSet().apply { value.keyUsage.forEach { set(it.index) } }))
            is SubjectKeyIdentifier -> Signum.Der.encodeToByteArray(value.keyIdentifier)
            is AuthorityKeyIdentifier -> Signum.Der.encodeToByteArray(AuthorityKeyIdentifierBody(
                value.keyIdentifier, value.authorityCertIssuer.map { it.asn1.toRepresentation() }.ifEmpty { null }, value.authorityCertSerialNumber?.toAsn1Integer(),
            ))
            is ExtendedKeyUsage -> Signum.Der.encodeToByteArray(value.keyUsages.toList())
            is InhibitAnyPolicy -> Signum.Der.encodeToByteArray(Asn1Integer(value.skipCerts))
            is PolicyConstraints -> Signum.Der.encodeToByteArray(PolicyConstraintsBody(
                value.requireExplicitPolicy?.let { Asn1Integer(it) }, value.inhibitPolicyMapping?.let { Asn1Integer(it) },
            ))
            is PolicyMappings -> Signum.Der.encodeToByteArray(value.policyMappings)
            is CertificatePolicies -> encodeCertificatePolicies(value.certificatePolicies)
            is NameConstraints -> Signum.Der.encodeToByteArray(NameConstraintsBody(
                value.permitted?.trees?.map { it.asn1.toRepresentation() }, value.excluded?.trees?.map { it.asn1.toRepresentation() },
            ))
            else -> return null
        }
        return X509CertificateExtension(value.oid, value.critical, body)
    }

    override fun decodeFromAsn1(generalName: X509GeneralName): GeneralName? =
        when (generalName) {
            is X509GeneralName.Dns -> DNSName.fromAsn1Model(generalName)
            is X509GeneralName.Rfc822 -> RFC822Name.fromAsn1Model(generalName)
            is X509GeneralName.UniformResourceIdentifier -> UriName.fromAsn1Model(generalName)
            is X509GeneralName.IpAddress -> IPAddressName.fromAsn1Model(generalName)
            is X509GeneralName.Directory -> DirectoryName.fromAsn1Model(generalName)
            is X509GeneralName.RegisteredId -> RegisteredIDName.fromAsn1Model(generalName)
            is X509GeneralName.Other -> decodeOtherName(generalName)
            is X509GeneralName.EdiParty -> Signum.Der.decodeFromTlv(EdiPartyWire.serializer(), Asn1Sequence(generalName.elements)).let {
                EDIPartyName(it.partyName.value.value, it.nameAssigner?.value?.value)
            }
            is X509GeneralName.X400Address -> X400AddressName.fromAsn1Model(generalName)
            else -> null
        }

    override fun encodeToAsn1(generalName: GeneralName): X509GeneralName? = when (generalName) {
        is DNSName -> X509GeneralName.Dns(generalName.value)
        is RFC822Name -> X509GeneralName.Rfc822(generalName.value)
        is UriName -> X509GeneralName.UniformResourceIdentifier(generalName.host)
        is IPAddressName -> X509GeneralName.IpAddress(generalName.rawBytes)
        is DirectoryName -> X509GeneralName.Directory(generalName.name.asn1.toRepresentation())
        is RegisteredIDName -> X509GeneralName.RegisteredId(generalName.value)
        is OtherName -> encodeOtherName(generalName)
        is EDIPartyName -> Signum.Der.encodeToTlv(EdiPartyWire.serializer(), EdiPartyWire(
            generalName.nameAssigner?.let { ExplicitlyTagged(Asn1String.UTF8(it)) },
            ExplicitlyTagged(Asn1String.UTF8(generalName.partyName)),
        )).asSequence().let { X509GeneralName.EdiParty(it) }
        is X400AddressName -> generalName.x400Address
        else -> null
    }

}
