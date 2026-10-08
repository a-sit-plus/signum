package at.asitplus.signum.indispensable.pki.attributes

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.BaseX509AttributeTypeAndValue

/**
 * Typed X.500 [AttributeTypeAndValue]s. These live in `indispensable-pkix` (not the lean core) and
 * contribute their typed descriptors and serializers through
 * [at.asitplus.signum.indispensable.pki.installPkix].
 * Without `indispensable-pkix` on the classpath, the core RFC 4514 codec uses generic structural
 * descriptors for standard shorthands and falls back to dotted OIDs for unknown attribute types.
 */

class CommonName : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<CommonName>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.commonName
        override val canonicalName = "CN"
        override fun fromString(value: String) = CommonName(value)
        override fun fromValue(value: Asn1Element) = CommonName(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = CommonName(src)
    }
}

class Country : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.Printable(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<Country>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.countryName
        override val canonicalName = "C"
        override fun fromString(value: String) = Country(value)
        override fun fromValue(value: Asn1Element) = Country(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Country(src)
    }
}

class Locality : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<Locality>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.localityName
        override val canonicalName = "L"
        override fun fromString(value: String) = Locality(value)
        override fun fromValue(value: Asn1Element) = Locality(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Locality(src)
    }
}

class StateOrProvince : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<StateOrProvince>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.stateOrProvinceName
        override val canonicalName = "ST"
        override fun fromString(value: String) = StateOrProvince(value)
        override fun fromValue(value: Asn1Element) = StateOrProvince(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = StateOrProvince(src)
    }
}

class Organization : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<Organization>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.organizationName
        override val canonicalName = "O"
        override fun fromString(value: String) = Organization(value)
        override fun fromValue(value: Asn1Element) = Organization(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Organization(src)
    }
}

class OrganizationalUnit : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<OrganizationalUnit>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.organizationalUnitName
        override val canonicalName = "OU"
        override fun fromString(value: String) = OrganizationalUnit(value)
        override fun fromValue(value: Asn1Element) = OrganizationalUnit(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = OrganizationalUnit(src)
    }
}

class Title : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<Title>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.title
        override val canonicalName = "T"
        override fun fromString(value: String) = Title(value)
        override fun fromValue(value: Asn1Element) = Title(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Title(src)
    }
}

class Street : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<Street>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.streetAddress
        override val canonicalName = "STREET"
        override fun fromString(value: String) = Street(value)
        override fun fromValue(value: Asn1Element) = Street(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Street(src)
    }
}

class DomainComponent : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.IA5(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<DomainComponent>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.domainComponent
        override val canonicalName = "DC"
        override fun fromString(value: String) = DomainComponent(value)
        override fun fromValue(value: Asn1Element) = DomainComponent(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = DomainComponent(src)
    }
}

class DistinguishedNameQualifier : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.Printable(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<DistinguishedNameQualifier>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.dnQualifier
        override val canonicalName = "DNQUALIFIER"
        override fun fromString(value: String) = DistinguishedNameQualifier(value)
        override fun fromValue(value: Asn1Element) = DistinguishedNameQualifier(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = DistinguishedNameQualifier(src)
    }
}

class Surname : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<Surname>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.surname
        override val canonicalName = "SURNAME"
        override fun fromString(value: String) = Surname(value)
        override fun fromValue(value: Asn1Element) = Surname(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Surname(src)
    }
}

class GivenName : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<GivenName>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.givenName
        override val canonicalName = "GIVENNAME"
        override fun fromString(value: String) = GivenName(value)
        override fun fromValue(value: Asn1Element) = GivenName(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = GivenName(src)
    }
}

class Initials : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<Initials>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.initials
        override val canonicalName = "INITIALS"
        override fun fromString(value: String) = Initials(value)
        override fun fromValue(value: Asn1Element) = Initials(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Initials(src)
    }
}

class Generation : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<Generation>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.generationQualifier
        override val canonicalName = "GENERATION"
        override fun fromString(value: String) = Generation(value)
        override fun fromValue(value: Asn1Element) = Generation(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Generation(src)
    }
}

class EmailAddress : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.IA5(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<EmailAddress>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.emailAddress
        override val canonicalName = "EMAILADDRESS"
        override fun fromString(value: String) = EmailAddress(value)
        override fun fromValue(value: Asn1Element) = EmailAddress(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = EmailAddress(src)
    }
}

class UserId : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<UserId>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.userId
        override val canonicalName = "UID"
        override fun fromString(value: String) = UserId(value)
        override fun fromValue(value: Asn1Element) = UserId(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = UserId(src)
    }
}

class SerialNumber : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.Printable(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<SerialNumber>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.serialNumber
        override val canonicalName = "SERIALNUMBER"
        override fun fromString(value: String) = SerialNumber(value)
        override fun fromValue(value: Asn1Element) = SerialNumber(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = SerialNumber(src)
    }
}

class TelephoneNumber : BaseX509AttributeTypeAndValue {
    internal constructor(value: Asn1Element) : super(Companion.oid, value)
    constructor(str: String) : super(Companion.oid, Asn1String.Printable(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor<TelephoneNumber>{
        override val oid = AttributeTypeAndValue.Descriptor.OID.telephoneNumber
        override val canonicalName = "TELEPHONENUMBER"
        override fun fromString(value: String) = TelephoneNumber(value)
        override fun fromValue(value: Asn1Element) = TelephoneNumber(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = TelephoneNumber(src)
    }
}
