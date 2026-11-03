package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.toAsn1
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.x500.*
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/** ASN.1 is one representation of the PKIX types; dispatch uses the existing provider mechanism. */
object PkixAsn1Provider : CertificateExtensionProvider, GeneralNameFormatProvider {
    override fun decodeFromAsn1(asn1: X509CertificateExtension): CertificateExtension? = with(asn1) {
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
                AuthorityKeyIdentifier(it.keyIdentifier, it.authorityCertIssuer.orEmpty(), it.authorityCertSerialNumber?.toBigInteger(), critical)
            }
            ExtendedKeyUsage.oid -> ExtendedKeyUsage(Signum.Der.decodeFromByteArray<List<ObjectIdentifier>>(value).toSet(), critical)
            InhibitAnyPolicy.oid -> InhibitAnyPolicy(Signum.Der.decodeFromByteArray<Asn1Integer>(value).toInt(), critical)
            PolicyConstraints.oid -> Signum.Der.decodeFromByteArray<PolicyConstraintsBody>(value).let {
                PolicyConstraints(it.requireExplicitPolicy?.toInt(), it.inhibitPolicyMapping?.toInt(), critical)
            }
            PolicyMappings.oid -> PolicyMappings(Signum.Der.decodeFromByteArray<List<CertificatePolicyMap>>(value), critical)
            CertificatePolicies.oid -> CertificatePolicies(Signum.Der.decodeFromByteArray<List<PolicyInformation>>(value), critical)
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

    override fun encodeToAsn1(value: CertificateExtension): X509CertificateExtension? {
        val body = when (value) {
            is BasicConstraints -> Signum.Der.encodeToByteArray(BasicConstraintsBody(
                value.ca.takeIf { it }, value.pathLenConstraint?.let { Asn1Integer(it) },
            ))
            is KeyUsage -> Signum.Der.encodeToByteArray(Asn1BitString(BitSet().apply { value.keyUsage.forEach { set(it.index) } }))
            is SubjectKeyIdentifier -> Signum.Der.encodeToByteArray(value.keyIdentifier)
            is AuthorityKeyIdentifier -> Signum.Der.encodeToByteArray(AuthorityKeyIdentifierBody(
                value.keyIdentifier, value.authorityCertIssuer.ifEmpty { null }, value.authorityCertSerialNumber?.toAsn1Integer(),
            ))
            is ExtendedKeyUsage -> Signum.Der.encodeToByteArray(value.keyUsages.toList())
            is InhibitAnyPolicy -> Signum.Der.encodeToByteArray(Asn1Integer(value.skipCerts))
            is PolicyConstraints -> Signum.Der.encodeToByteArray(PolicyConstraintsBody(
                value.requireExplicitPolicy?.let { Asn1Integer(it) }, value.inhibitPolicyMapping?.let { Asn1Integer(it) },
            ))
            is PolicyMappings -> Signum.Der.encodeToByteArray(value.policyMappings)
            is CertificatePolicies -> Signum.Der.encodeToByteArray(value.certificatePolicies)
            is NameConstraints -> Signum.Der.encodeToByteArray(NameConstraintsBody(
                value.permitted?.trees?.map { it.toAsn1() }, value.excluded?.trees?.map { it.toAsn1() },
            ))
            else -> return null
        }
        return X509CertificateExtension(value.oid, value.critical, body)
    }

    override fun decodeFromAsn1(generalName: X509GeneralName): GeneralName? = when (generalName) {
        is X509GeneralName.Dns -> DNSName.fromAsn1Model(generalName)
        is X509GeneralName.Rfc822 -> RFC822Name.fromAsn1Model(generalName)
        is X509GeneralName.UniformResourceIdentifier -> UriName.fromAsn1Model(generalName)
        is X509GeneralName.IpAddress -> IPAddressName.fromAsn1Model(generalName)
        is X509GeneralName.Directory -> DirectoryName.fromAsn1Model(generalName)
        is X509GeneralName.RegisteredId -> RegisteredIDName.fromAsn1Model(generalName)
        is X509GeneralName.Other -> OtherName.fromAsn1Model(generalName)
        is X509GeneralName.EdiParty -> EDIPartyName.fromAsn1Model(generalName)
        is X509GeneralName.X400Address -> X400AddressName.fromAsn1Model(generalName)
        else -> null
    }

    override fun encodeToAsn1(generalName: GeneralName): X509GeneralName? = when (generalName) {
        is DNSName -> X509GeneralName.Dns(generalName.value.value)
        is RFC822Name -> X509GeneralName.Rfc822(generalName.value.value)
        is UriName -> X509GeneralName.UniformResourceIdentifier(generalName.host.value)
        is IPAddressName -> X509GeneralName.IpAddress(generalName.rawBytes)
        is DirectoryName -> X509GeneralName.Directory(generalName.name.toAsn1())
        is RegisteredIDName -> X509GeneralName.RegisteredId(generalName.value)
        is OtherName -> generalName.other
        is EDIPartyName -> generalName.ediParty
        is X400AddressName -> generalName.x400Address
        else -> null
    }
}
