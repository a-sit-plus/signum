package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.attributes.*

private val initializePkix by lazy {
    at.asitplus.signum.ServiceLoader.register<PolicyQualifierAsn1Provider>(BuiltinPolicyQualifiers)
    at.asitplus.signum.ServiceLoader.register<OtherNameAsn1Provider>(BuiltinOtherNames)
    Signum.register(PkixAsn1Provider)

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
 * Install the PKIX providers and attribute descriptors before the first X.500 name lookup.
 * Custom providers register afterward. No contextual ASN.1 serializers are installed.
 */
fun Signum.installPkix() { initializePkix }

/** The chain ordered from trust anchor to leaf (reverse of the conventional leaf-first order). */
val CertificateChain.validationPath: CertificateChain get() = reversed()
