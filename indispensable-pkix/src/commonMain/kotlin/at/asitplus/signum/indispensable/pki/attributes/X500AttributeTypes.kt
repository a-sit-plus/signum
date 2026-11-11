package at.asitplus.signum.indispensable.pki.attributes

import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.TextAttributeTypeAndValue

/**
 * Typed X.500 [AttributeTypeAndValue]s. These live in `indispensable-pkix` (not the lean core) and
 * contribute their typed descriptors and serializers through
 * [at.asitplus.signum.indispensable.pki.installPkix].
 * Without `indispensable-pkix` on the classpath, the core RFC 4514 codec uses generic structural
 * descriptors for standard shorthands and falls back to dotted OIDs for unknown attribute types.
 */

class CommonName(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<CommonName>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.commonName
        override val canonicalName = "CN"
        override fun fromString(value: String) = CommonName(value)
    }
}

class Country(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<Country>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.countryName
        override val canonicalName = "C"
        override fun fromString(value: String) = Country(value)
    }
}

class Locality(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<Locality>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.localityName
        override val canonicalName = "L"
        override fun fromString(value: String) = Locality(value)
    }
}

class StateOrProvince(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<StateOrProvince>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.stateOrProvinceName
        override val canonicalName = "ST"
        override fun fromString(value: String) = StateOrProvince(value)
    }
}

class Organization(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<Organization>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.organizationName
        override val canonicalName = "O"
        override fun fromString(value: String) = Organization(value)
    }
}

class OrganizationalUnit(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<OrganizationalUnit>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.organizationalUnitName
        override val canonicalName = "OU"
        override fun fromString(value: String) = OrganizationalUnit(value)
    }
}

class Title(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<Title>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.title
        override val canonicalName = "T"
        override fun fromString(value: String) = Title(value)
    }
}

class Street(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<Street>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.streetAddress
        override val canonicalName = "STREET"
        override fun fromString(value: String) = Street(value)
    }
}

class DomainComponent(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<DomainComponent>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.domainComponent
        override val canonicalName = "DC"
        override fun fromString(value: String) = DomainComponent(value)
    }
}

class DistinguishedNameQualifier(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<DistinguishedNameQualifier>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.dnQualifier
        override val canonicalName = "DNQUALIFIER"
        override fun fromString(value: String) = DistinguishedNameQualifier(value)
    }
}

class Surname(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<Surname>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.surname
        override val canonicalName = "SURNAME"
        override fun fromString(value: String) = Surname(value)
    }
}

class GivenName(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<GivenName>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.givenName
        override val canonicalName = "GIVENNAME"
        override fun fromString(value: String) = GivenName(value)
    }
}

class Initials(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<Initials>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.initials
        override val canonicalName = "INITIALS"
        override fun fromString(value: String) = Initials(value)
    }
}

class Generation(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<Generation>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.generationQualifier
        override val canonicalName = "GENERATION"
        override fun fromString(value: String) = Generation(value)
    }
}

class EmailAddress(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<EmailAddress>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.emailAddress
        override val canonicalName = "EMAILADDRESS"
        override fun fromString(value: String) = EmailAddress(value)
    }
}

class UserId(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<UserId>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.userId
        override val canonicalName = "UID"
        override fun fromString(value: String) = UserId(value)
    }
}

class SerialNumber(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<SerialNumber>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.serialNumber
        override val canonicalName = "SERIALNUMBER"
        override fun fromString(value: String) = SerialNumber(value)
    }
}

class TelephoneNumber(text: String) : TextAttributeTypeAndValue(Companion.oid, text) {
    companion object : AttributeTypeAndValue.Descriptor<TelephoneNumber>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.telephoneNumber
        override val canonicalName = "TELEPHONENUMBER"
        override fun fromString(value: String) = TelephoneNumber(value)
    }
}
