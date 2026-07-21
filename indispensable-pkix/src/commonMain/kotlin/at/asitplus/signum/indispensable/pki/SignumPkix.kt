package at.asitplus.signum.indispensable.pki

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

/**
 * Entry point for the `indispensable-pkix` typed PKIX layer.
 *
 * The `indispensable` core parses every certificate extension and X.500 attribute
 * *generically* (via awesn1) and keeps its [CertificateExtension.Registry] /
 * [AttributeTypeAndValue.Registry] / [GeneralName.X509Representable.Registry]
 * **empty** by default. This module supplies the typed counterparts (e.g. [KeyUsage], [CommonName])
 * and registers their descriptors here.
 *
 * Call [install] once at startup (it is idempotent, but it **must** run before the first (de)serialization
 * of a certificate/RDN/GeneralName) The registries seal on first lookup, after which they are
 * immutable and [register][CertificateExtension.Descriptor.register] throws. After installation,
 * certificate parsing upgrades the generic extensions/attributes to their typed forms and the RFC
 * 4514 codec renders friendly keywords (`CN=`, `O=`, …) instead of dotted-OID forms.
 *
 * `pkix-supreme`'s validator entry points call [install] internally, so chain validation never runs
 * against an unpopulated registry. Third-party typed extensions/attributes use the very same registry
 * SPI ([CertificateExtension.Descriptor]/[AttributeTypeAndValue.Descriptor] + `register()`), registered
 * before the first (de)serialization.
 *
 * TODO: replace the explicit [install] call with a reliable multiplatform auto-trigger
 *  (e.g. `@EagerInitialization`) once one exists that fires dependably on every Kotlin target.
 */
@OptIn(ExperimentalAtomicApi::class)
object SignumPkix {

    private val installed = AtomicBoolean(false)

    /**
     * Registers all typed extension/attribute/general-name descriptors shipped with this module.
     * Idempotent and concurrency-safe: only the first caller performs registration (compare-and-set
     * guard), every subsequent call is a no-op. Registration must happen here — before the first
     * (de)serialization — because the registries seal on their first lookup.
     */
    fun install() {
        if (!installed.compareAndSet(expectedValue = false, newValue = true)) return

        // Typed certificate extensions
        BasicConstraints.register()
        NameConstraints.register()
        PolicyConstraints.register()
        CertificatePolicies.register()
        PolicyMappings.register()
        InhibitAnyPolicy.register()
        KeyUsage.register()
        AuthorityKeyIdentifier.register()
        ExtendedKeyUsage.register()
        SubjectKeyIdentifier.register()

        // Typed X.500 attribute types
        CommonName.register()
        Country.register()
        Locality.register()
        StateOrProvince.register()
        Organization.register()
        OrganizationalUnit.register()
        Title.register()
        Street.register()
        DomainComponent.register()
        DistinguishedNameQualifier.register()
        Surname.register()
        GivenName.register()
        Initials.register()
        Generation.register()
        EmailAddress.register()
        UserId.register()
        SerialNumber.register()
        TelephoneNumber.register()

        // Typed GeneralName CHOICE alternatives
        DNSName.register()
        RFC822Name.register()
        UriName.register()
        IPAddressName.register()
        RegisteredIDName.register()
        OtherName.register()
        EDIPartyName.register()
        X400AddressName.register()
        DirectoryName.register()
    }
}


/** The chain ordered from trust anchor to leaf (reverse of the conventional leaf-first order). */
val CertificateChain.validationPath: CertificateChain get() = reversed()