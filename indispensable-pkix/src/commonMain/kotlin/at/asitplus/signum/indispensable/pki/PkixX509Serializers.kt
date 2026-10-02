package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.pki.attributes.*
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.x500.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1Extension

private class PkixX509Serializer<T, Model>(
    private val delegate: KSerializer<Model>,
    private val toModel: (T) -> Model,
    private val fromModel: (Model) -> T,
) : KSerializer<T> {
    override val descriptor = delegate.descriptor
    override fun serialize(encoder: Encoder, value: T) = encoder.encodeSerializableValue(delegate, toModel(value))
    override fun deserialize(decoder: Decoder): T = fromModel(decoder.decodeSerializableValue(delegate))
}

private fun <T : CertificateExtension> extensionSerializer(fromModel: (Awesn1Extension) -> T): KSerializer<T> =
    PkixX509Serializer(Awesn1Extension.serializer(), { requireNotNull(it.asn1Representation) }, fromModel)

private fun <T : AttributeTypeAndValue> attributeSerializer(fromModel: (X500AttributeTypeAndValue) -> T): KSerializer<T> =
    PkixX509Serializer(X500AttributeTypeAndValue.serializer(), { requireNotNull(it.asn1Representation) }, fromModel)

private fun <T : GeneralName> nameSerializer(fromModel: (X509GeneralName) -> T): KSerializer<T> =
    PkixX509Serializer(X509GeneralName.serializer(), { requireNotNull(it.asn1Representation) }, fromModel)

/** Contextual DER serializers for the concrete PKIX types. Register once at startup, or use with a local DER instance. */
val signumPkixX509Serializers = SerializersModule {
    contextual(CommonName::class, attributeSerializer { CommonName.fromAsn1Representation(it) })
    contextual(Country::class, attributeSerializer { Country.fromAsn1Representation(it) })
    contextual(DistinguishedNameQualifier::class, attributeSerializer { DistinguishedNameQualifier.fromAsn1Representation(it) })
    contextual(DomainComponent::class, attributeSerializer { DomainComponent.fromAsn1Representation(it) })
    contextual(EmailAddress::class, attributeSerializer { EmailAddress.fromAsn1Representation(it) })
    contextual(Generation::class, attributeSerializer { Generation.fromAsn1Representation(it) })
    contextual(GivenName::class, attributeSerializer { GivenName.fromAsn1Representation(it) })
    contextual(Initials::class, attributeSerializer { Initials.fromAsn1Representation(it) })
    contextual(Locality::class, attributeSerializer { Locality.fromAsn1Representation(it) })
    contextual(Organization::class, attributeSerializer { Organization.fromAsn1Representation(it) })
    contextual(OrganizationalUnit::class, attributeSerializer { OrganizationalUnit.fromAsn1Representation(it) })
    contextual(SerialNumber::class, attributeSerializer { SerialNumber.fromAsn1Representation(it) })
    contextual(StateOrProvince::class, attributeSerializer { StateOrProvince.fromAsn1Representation(it) })
    contextual(Street::class, attributeSerializer { Street.fromAsn1Representation(it) })
    contextual(Surname::class, attributeSerializer { Surname.fromAsn1Representation(it) })
    contextual(TelephoneNumber::class, attributeSerializer { TelephoneNumber.fromAsn1Representation(it) })
    contextual(Title::class, attributeSerializer { Title.fromAsn1Representation(it) })
    contextual(UserId::class, attributeSerializer { UserId.fromAsn1Representation(it) })
    contextual(AuthorityKeyIdentifier::class, extensionSerializer { AuthorityKeyIdentifier.fromAsn1Representation(it) })
    contextual(BasicConstraints::class, extensionSerializer { BasicConstraints.fromAsn1Representation(it) })
    contextual(CertificatePolicies::class, extensionSerializer { CertificatePolicies.fromAsn1Representation(it) })
    contextual(ExtendedKeyUsage::class, extensionSerializer { ExtendedKeyUsage.fromAsn1Representation(it) })
    contextual(InhibitAnyPolicy::class, extensionSerializer { InhibitAnyPolicy.fromAsn1Representation(it) })
    contextual(KeyUsage::class, extensionSerializer { KeyUsage.fromAsn1Representation(it) })
    contextual(NameConstraints::class, extensionSerializer { NameConstraints.fromAsn1Representation(it) })
    contextual(PolicyConstraints::class, extensionSerializer { PolicyConstraints.fromAsn1Representation(it) })
    contextual(PolicyMappings::class, extensionSerializer { PolicyMappings.fromAsn1Representation(it) })
    contextual(SubjectKeyIdentifier::class, extensionSerializer { SubjectKeyIdentifier.fromAsn1Representation(it) })
    contextual(DNSName::class, nameSerializer { DNSName.fromAsn1Representation(it) })
    contextual(DirectoryName::class, nameSerializer { DirectoryName.fromAsn1Representation(it) })
    contextual(EDIPartyName::class, nameSerializer { EDIPartyName.fromAsn1Representation(it) })
    contextual(IPAddressName::class, nameSerializer { IPAddressName.fromAsn1Representation(it) })
    contextual(OtherName::class, nameSerializer { OtherName.fromAsn1Representation(it) })
    contextual(RFC822Name::class, nameSerializer { RFC822Name.fromAsn1Representation(it) })
    contextual(RegisteredIDName::class, nameSerializer { RegisteredIDName.fromAsn1Representation(it) })
    contextual(UriName::class, nameSerializer { UriName.fromAsn1Representation(it) })
    contextual(X400AddressName::class, nameSerializer { X400AddressName.fromAsn1Representation(it) })
}
