package at.asitplus.signum.indispensable.pki.attributes

import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValueProvider
import at.asitplus.signum.indispensable.pki.TextAttributeTypeAndValue

/** Typed semantic X.500 attributes installed by the PKIX text provider. */
class CommonName(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.commonName
    }
}

class Country(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.countryName
    }
}

class Locality(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.localityName
    }
}

class StateOrProvince(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.stateOrProvinceName
    }
}

class Organization(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.organizationName
    }
}

class OrganizationalUnit(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.organizationalUnitName
    }
}

class Title(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.title
    }
}

class Street(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.streetAddress
    }
}

class DomainComponent(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.domainComponent
    }
}

class DistinguishedNameQualifier(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.dnQualifier
    }
}

class Surname(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.surname
    }
}

class GivenName(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.givenName
    }
}

class Initials(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.initials
    }
}

class Generation(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.generationQualifier
    }
}

class EmailAddress(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.emailAddress
    }
}

class UserId(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.userId
    }
}

class SerialNumber(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.serialNumber
    }
}

class TelephoneNumber(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : Identifiable{
        override val oid = AttributeTypeAndValue.OID.telephoneNumber
    }
}

internal object PkixAttributeTypeAndValueProvider : AttributeTypeAndValueProvider {
    override fun decoderFor(oid: ObjectIdentifier): ((String) -> AttributeTypeAndValue)? = when (oid) {
        CommonName.oid -> ::CommonName
        Country.oid -> ::Country
        Locality.oid -> ::Locality
        StateOrProvince.oid -> ::StateOrProvince
        Organization.oid -> ::Organization
        OrganizationalUnit.oid -> ::OrganizationalUnit
        Title.oid -> ::Title
        Street.oid -> ::Street
        DomainComponent.oid -> ::DomainComponent
        DistinguishedNameQualifier.oid -> ::DistinguishedNameQualifier
        Surname.oid -> ::Surname
        GivenName.oid -> ::GivenName
        Initials.oid -> ::Initials
        Generation.oid -> ::Generation
        EmailAddress.oid -> ::EmailAddress
        UserId.oid -> ::UserId
        SerialNumber.oid -> ::SerialNumber
        TelephoneNumber.oid -> ::TelephoneNumber
        else -> null
    }
}
