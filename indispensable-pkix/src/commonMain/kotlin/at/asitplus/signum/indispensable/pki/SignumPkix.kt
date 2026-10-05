package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.contextualAsn1
import at.asitplus.signum.indispensable.pki.extn.GeneralSubtree
import kotlinx.serialization.modules.SerializersModule

import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.ExperimentalAtomicApi
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
import at.asitplus.signum.indispensable.pki.x500.OtherName
import at.asitplus.signum.indispensable.pki.x500.RFC822Name
import at.asitplus.signum.indispensable.pki.x500.RegisteredIDName
import at.asitplus.signum.indispensable.pki.x500.UriName
import at.asitplus.signum.indispensable.pki.x500.X400AddressName

@OptIn(ExperimentalAtomicApi::class)
private val installed = AtomicBoolean(false)

/** Install the PKIX descriptors and their contextual serializers once during startup. */
@OptIn(ExperimentalAtomicApi::class)
fun Signum.installPkix() {
    if (!installed.compareAndSet(expectedValue = false, newValue = true)) return

    registerAsn1Serializers(SerializersModule {
        contextualAsn1(
            GeneralSubtree::class,
            X509GeneralSubtree.serializer(), { it.asn1Representation },
            { GeneralSubtree.fromAsn1Representation(it) },
        )
    })

    // Typed certificate extensions
    register(BasicConstraints)
    register(NameConstraints)
    register(PolicyConstraints)
    register(CertificatePolicies)
    register(PolicyMappings)
    register(InhibitAnyPolicy)
    register(KeyUsage)
    register(AuthorityKeyIdentifier)
    register(ExtendedKeyUsage)
    register(SubjectKeyIdentifier)

    // Typed X.500 attribute types
    register(CommonName)
    register(Country)
    register(Locality)
    register(StateOrProvince)
    register(Organization)
    register(OrganizationalUnit)
    register(Title)
    register(Street)
    register(DomainComponent)
    register(DistinguishedNameQualifier)
    register(Surname)
    register(GivenName)
    register(Initials)
    register(Generation)
    register(EmailAddress)
    register(UserId)
    register(SerialNumber)
    register(TelephoneNumber)

    // Typed GeneralName CHOICE alternatives
    register(DNSName)
    register(RFC822Name)
    register(UriName)
    register(IPAddressName)
    register(RegisteredIDName)
    register(OtherName)
    register(EDIPartyName)
    register(X400AddressName)
    register(DirectoryName)
}

/** The chain ordered from trust anchor to leaf (reverse of the conventional leaf-first order). */
val CertificateChain.validationPath: CertificateChain get() = reversed()
