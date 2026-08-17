package at.asitplus.signum.indispensable.pki.attributes

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.BaseX509AttributeTypeAndValue

/**
 * Typed X.500 [AttributeTypeAndValue]s. These live in `indispensable-pkix` (not the lean core) and
 * self-register their [AttributeTypeAndValue.Descriptor] into the core registry on class-load. The
 * registry is populated eagerly via [at.asitplus.signum.indispensable.pki.SignumPkix.install].
 * Without `indispensable-pkix` on the classpath, the core RFC 4514 codec falls back to dotted-OID
 * attribute types.
 */

class CommonName : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.3")
        override val canonicalName = "CN"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = CommonName(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = CommonName(src)
    }
}

class Country : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.Printable(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.6")
        override val canonicalName = "C"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = Country(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Country(src)
    }
}

class Locality : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.7")
        override val canonicalName = "L"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = Locality(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Locality(src)
    }
}

class StateOrProvince : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.8")
        override val canonicalName = "ST"
        override val aliases = setOf("S")
        override fun fromString(value: String) = StateOrProvince(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = StateOrProvince(src)
    }
}

class Organization : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.10")
        override val canonicalName = "O"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = Organization(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Organization(src)
    }
}

class OrganizationalUnit : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.11")
        override val canonicalName = "OU"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = OrganizationalUnit(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = OrganizationalUnit(src)
    }
}

class Title : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.12")
        override val canonicalName = "T"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = Title(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Title(src)
    }
}

class Street : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.9")
        override val canonicalName = "STREET"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = Street(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Street(src)
    }
}

class DomainComponent : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.IA5(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("0.9.2342.19200300.100.1.25")
        override val canonicalName = "DC"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = DomainComponent(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = DomainComponent(src)
    }
}

class DistinguishedNameQualifier : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.Printable(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.46")
        override val canonicalName = "DNQUALIFIER"
        override val aliases = setOf("DNQ")
        override fun fromString(value: String) = DistinguishedNameQualifier(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = DistinguishedNameQualifier(src)
    }
}

class Surname : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.4")
        override val canonicalName = "SURNAME"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = Surname(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Surname(src)
    }
}

class GivenName : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.42")
        override val canonicalName = "GIVENNAME"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = GivenName(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = GivenName(src)
    }
}

class Initials : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.43")
        override val canonicalName = "INITIALS"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = Initials(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Initials(src)
    }
}

class Generation : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.44")
        override val canonicalName = "GENERATION"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = Generation(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Generation(src)
    }
}

class EmailAddress : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.IA5(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("1.2.840.113549.1.9.1")
        override val canonicalName = "EMAILADDRESS"
        override val aliases = setOf("EMAIL")
        override fun fromString(value: String) = EmailAddress(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = EmailAddress(src)
    }
}

class UserId : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("0.9.2342.19200300.100.1.1")
        override val canonicalName = "UID"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = UserId(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = UserId(src)
    }
}

class SerialNumber : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.Printable(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.5")
        override val canonicalName = "SERIALNUMBER"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = SerialNumber(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = SerialNumber(src)
    }
}

class TelephoneNumber : BaseX509AttributeTypeAndValue {
    constructor(str: String) : super(Companion.oid, Asn1String.Printable(str))
    internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("2.5.4.20")
        override val canonicalName = "TELEPHONENUMBER"
        override val aliases = emptySet<String>()
        override fun fromString(value: String) = TelephoneNumber(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = TelephoneNumber(src)
    }
}
