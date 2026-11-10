package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.*
import at.asitplus.awesn1.crypto.pki.*
import kotlinx.serialization.modules.SerializersModuleBuilder
import at.asitplus.signum.indispensable.pki.extn.GeneralSubtree
import kotlinx.serialization.modules.SerializersModule

import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.indispensable.pki.attributes.Country
import at.asitplus.signum.indispensable.pki.attributes.DistinguishedNameQualifier
import at.asitplus.signum.indispensable.pki.attributes.DomainComponent
import at.asitplus.signum.indispensable.pki.attributes.EmailAddress
import at.asitplus.signum.indispensable.pki.attributes.Generation
import at.asitplus.signum.indispensable.pki.attributes.GivenName
import at.asitplus.signum.indispensable.pki.attributes.Initials
import at.asitplus.signum.indispensable.pki.attributes.Locality
import at.asitplus.signum.indispensable.pki.attributes.Organization
import at.asitplus.signum.indispensable.pki.attributes.OrganizationalUnit
import at.asitplus.signum.indispensable.pki.attributes.SerialNumber
import at.asitplus.signum.indispensable.pki.attributes.StateOrProvince
import at.asitplus.signum.indispensable.pki.attributes.Street
import at.asitplus.signum.indispensable.pki.attributes.Surname
import at.asitplus.signum.indispensable.pki.attributes.TelephoneNumber
import at.asitplus.signum.indispensable.pki.attributes.Title
import at.asitplus.signum.indispensable.pki.attributes.UserId
import at.asitplus.signum.indispensable.pki.extn.AuthorityKeyIdentifier
import at.asitplus.signum.indispensable.pki.extn.BasicConstraints
import at.asitplus.signum.indispensable.pki.extn.CertificatePolicies
import at.asitplus.signum.indispensable.pki.extn.ExtendedKeyUsage
import at.asitplus.signum.indispensable.pki.extn.InhibitAnyPolicy
import at.asitplus.signum.indispensable.pki.extn.KeyUsage
import at.asitplus.signum.indispensable.pki.extn.NameConstraints
import at.asitplus.signum.indispensable.pki.extn.PolicyConstraints
import at.asitplus.signum.indispensable.pki.extn.PolicyMappings
import at.asitplus.signum.indispensable.pki.extn.SubjectKeyIdentifier
import at.asitplus.signum.indispensable.pki.x500.DNSName
import at.asitplus.signum.indispensable.pki.x500.DirectoryName
import at.asitplus.signum.indispensable.pki.x500.EDIPartyName
import at.asitplus.signum.indispensable.pki.x500.IPAddressName
import at.asitplus.signum.indispensable.pki.x500.*
import at.asitplus.signum.indispensable.pki.x500.OtherName
import at.asitplus.signum.indispensable.pki.x500.RFC822Name
import at.asitplus.signum.indispensable.pki.x500.RegisteredIDName
import at.asitplus.signum.indispensable.pki.x500.UriName
import at.asitplus.signum.indispensable.pki.x500.X400AddressName

private val initializePkix by lazy {
    at.asitplus.signum.ServiceLoader.register<PolicyQualifierAsn1Provider>(BuiltinPolicyQualifiers)
    Signum.register(PkixAsn1Provider, SerializersModule {
        contextualAsn1(GeneralSubtree::class, X509GeneralSubtree.serializer(), { it.asn1.toRepresentation() }, { GeneralSubtree.fromAsn1(it) })
        contextualAsn1(CertificateExtension::class, X509CertificateExtension.serializer(), { it.asn1.toRepresentation() }, { CertificateExtension.fromAsn1(it) })
        contextualAsn1(GeneralName::class, X509GeneralName.serializer(), { it.asn1.toRepresentation() }, { GeneralName.fromAsn1(it) })
        contextualAsn1(Certificate::class, X509Certificate.serializer(), { it.asn1.toRepresentation() }, { Certificate.fromAsn1(it) })
        contextualAsn1(TbsCertificate::class, X509TbsCertificate.serializer(), { it.asn1.toRepresentation() }, { TbsCertificate.fromAsn1(it) })
        contextualAsn1(Name::class, X500Name.serializer(), { it.asn1.toRepresentation() }, { Name.fromAsn1(it) })
        contextualAsn1(RelativeDistinguishedName::class, X500RelativeDistinguishedName.serializer(), { it.asn1.toRepresentation() }, { RelativeDistinguishedName.fromAsn1(it) })
        contextualAsn1(AttributeTypeAndValue::class, X500AttributeTypeAndValue.serializer(), { it.asn1.toRepresentation() }, { AttributeTypeAndValue.fromAsn1(it) })
        contextualAsn1(AlternativeNames::class, X509GeneralNames.serializer(), { it.asn1.toRepresentation() }, { AlternativeNames.fromAsn1(it) })
        extension<BasicConstraints>()
        extension<NameConstraints>()
        extension<PolicyConstraints>()
        extension<CertificatePolicies>()
        extension<PolicyMappings>()
        extension<InhibitAnyPolicy>()
        extension<KeyUsage>()
        extension<AuthorityKeyIdentifier>()
        extension<ExtendedKeyUsage>()
        extension<SubjectKeyIdentifier>()
        generalName<DNSName>()
        generalName<RFC822Name>()
        generalName<UriName>()
        generalName<IPAddressName>()
        generalName<RegisteredIDName>()
        generalName<OtherName>()
        generalName<OpaqueOtherName>()
        generalName<HardwareModuleName>()
        generalName<SmtpUtf8Mailbox>()
        generalName<MacAddressName>()
        generalName<EDIPartyName>()
        generalName<X400AddressName>()
        generalName<DirectoryName>()
    })

    Signum.register(CommonName)
    Signum.register(Country)
    Signum.register(Locality)
    Signum.register(StateOrProvince)
    Signum.register(Organization)
    Signum.register(OrganizationalUnit)
    Signum.register(Title)
    Signum.register(Street)
    Signum.register(DomainComponent)
    Signum.register(DistinguishedNameQualifier)
    Signum.register(Surname)
    Signum.register(GivenName)
    Signum.register(Initials)
    Signum.register(Generation)
    Signum.register(EmailAddress)
    Signum.register(UserId)
    Signum.register(SerialNumber)
    Signum.register(TelephoneNumber)
}

/**
 * Install the PKIX ASN.1 provider and contextual serializers once during startup,
 * before the first [Signum.Der] access or X.500 name lookup. Custom providers register afterward.
 */
fun Signum.installPkix() { initializePkix }

private inline fun <reified T : CertificateExtension> SerializersModuleBuilder.extension() =
    contextualAsn1(T::class, X509CertificateExtension.serializer(), { it.asn1.toRepresentation() }, { CertificateExtension.fromAsn1(it) as T })

private inline fun <reified T : GeneralName> SerializersModuleBuilder.generalName() =
    contextualAsn1(T::class, X509GeneralName.serializer(), { it.asn1.toRepresentation() }, { GeneralName.fromAsn1(it) as T })

/** The chain ordered from trust anchor to leaf (reverse of the conventional leaf-first order). */
val CertificateChain.validationPath: CertificateChain get() = reversed()
