package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.encoding.parse
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.realSourceRepresentation
import kotlin.jvm.JvmInline

/** Converting of ATV pairs (e.g., `cn=Alice`) to/from strings */
interface AttributeTypeAndValueProvider {
    sealed interface Key {
        companion object {
            operator fun invoke(str: String) = StringAlias(str)
            operator fun invoke(oid: ObjectIdentifier) = OID(oid)
        }
    }
    @JvmInline value class StringAlias(val str: String): Key
    @JvmInline value class OID(val oid: ObjectIdentifier): Key
    sealed interface Value {
        companion object {
            operator fun invoke(str: String) = StringValue(str)
            operator fun invoke(bytes: ByteArray) = ByteArrayValue(bytes)
        }
    }
    @JvmInline value class StringValue(val str: String): Value
    @JvmInline value class ByteArrayValue(val bytes: ByteArray): Value

    /** Decode a key=value pair from string.
     * - [key] may be either [StringAlias] or [OID] (parsed from dotted form).
     * - [value] may be either [StringValue] or [ByteArrayValue]. The byte array contains the
     *   BER-encoded ASN.1 value from the #-prefixed hex form. */
    fun decodeATV(key: Key, value: Value): AttributeTypeAndValue?

    /** Encode an ATV to a key=value pair. The result should be of a format suitable for [decodeATV]. [StringAlias] should be preferred over [OID]. */
    fun encodeATV(atv: AttributeTypeAndValue): Pair<Key, Value>?

}

/** Resolve an uppercase X.500 attribute alias from the core alias table. */
fun AttributeTypeAndValueProvider.wellKnownAttributeOidForAlias(alias: String): ObjectIdentifier? = AtvWellKnownAliasesProvider.oidForAlias(alias)

@OptIn(SignumInternals::class)
object AtvAsn1FallbackProvider : AttributeTypeAndValueProvider {
    override fun decodeATV(
        key: AttributeTypeAndValueProvider.Key,
        value: AttributeTypeAndValueProvider.Value
    ): AttributeTypeAndValue? {
        if (value !is AttributeTypeAndValueProvider.ByteArrayValue) return null
        val oid = when (key) {
            is AttributeTypeAndValueProvider.OID -> key.oid
            is AttributeTypeAndValueProvider.StringAlias -> wellKnownAttributeOidForAlias(key.str) ?: return null
        }
        return decodeAsn1Attribute(X500AttributeTypeAndValue(oid, Asn1Element.parse(value.bytes)))
    }

    override fun encodeATV(atv: AttributeTypeAndValue): Pair<AttributeTypeAndValueProvider.Key, AttributeTypeAndValueProvider.Value>? {
        val source = atv.realSourceRepresentation as? X500AttributeTypeAndValue ?: return null
        return AttributeTypeAndValueProvider.Key(atv.oid) to AttributeTypeAndValueProvider.Value(source.value.derEncoded)
    }
}

object AtvOidFallbackProvider: AttributeTypeAndValueProvider {
    override fun decodeATV(
        key: AttributeTypeAndValueProvider.Key,
        value: AttributeTypeAndValueProvider.Value
    ): AttributeTypeAndValue? {
        if (key !is AttributeTypeAndValueProvider.OID || value !is AttributeTypeAndValueProvider.StringValue) return null
        return TextAttributeTypeAndValue(key.oid, value.str)
    }

    override fun encodeATV(atv: AttributeTypeAndValue) =
        if (atv is TextAttributeTypeAndValue)
            Pair(AttributeTypeAndValueProvider.Key(atv.oid), AttributeTypeAndValueProvider.Value(atv.text))
        else null
}


internal object AtvWellKnownAliasesProvider : AttributeTypeAndValueProvider {
    private val oidToName = mapOf(
        AttributeTypeAndValue.OID.commonName to "CN",
        AttributeTypeAndValue.OID.countryName to "C",
        AttributeTypeAndValue.OID.localityName to "L",
        AttributeTypeAndValue.OID.stateOrProvinceName to "ST",
        AttributeTypeAndValue.OID.streetAddress to "STREET",
        AttributeTypeAndValue.OID.organizationName to "O",
        AttributeTypeAndValue.OID.organizationalUnitName to "OU",
        AttributeTypeAndValue.OID.title to "T",
        AttributeTypeAndValue.OID.telephoneNumber to "TELEPHONENUMBER",
        AttributeTypeAndValue.OID.surname to "SURNAME",
        AttributeTypeAndValue.OID.serialNumber to "SERIALNUMBER",
        AttributeTypeAndValue.OID.name to "NAME",
        AttributeTypeAndValue.OID.givenName to "GIVENNAME",
        AttributeTypeAndValue.OID.initials to "INITIALS",
        AttributeTypeAndValue.OID.generationQualifier to "GENERATION",
        AttributeTypeAndValue.OID.dnQualifier to "DNQUALIFIER",
        AttributeTypeAndValue.OID.domainComponent to "DC",
        AttributeTypeAndValue.OID.userId to "UID",
        AttributeTypeAndValue.OID.emailAddress to "EMAILADDRESS",
    )

    private val nameToOid = oidToName.entries.associate { (oid, name) -> name to oid } + mapOf(
        "COMMONNAME" to AttributeTypeAndValue.OID.commonName,
        "COUNTRY" to AttributeTypeAndValue.OID.countryName,
        "COUNTRYNAME" to AttributeTypeAndValue.OID.countryName,
        "LOCALITY" to AttributeTypeAndValue.OID.localityName,
        "LOCALITYNAME" to AttributeTypeAndValue.OID.localityName,
        "S" to AttributeTypeAndValue.OID.stateOrProvinceName,
        "STATEORPROVINCENAME" to AttributeTypeAndValue.OID.stateOrProvinceName,
        "STREETADDRESS" to AttributeTypeAndValue.OID.streetAddress,
        "ORGANIZATION" to AttributeTypeAndValue.OID.organizationName,
        "ORGANIZATIONNAME" to AttributeTypeAndValue.OID.organizationName,
        "ORGANIZATIONALUNIT" to AttributeTypeAndValue.OID.organizationalUnitName,
        "ORGANIZATIONALUNITNAME" to AttributeTypeAndValue.OID.organizationalUnitName,
        "TITLE" to AttributeTypeAndValue.OID.title,
        "DNQ" to AttributeTypeAndValue.OID.dnQualifier,
        "EMAIL" to AttributeTypeAndValue.OID.emailAddress,
    )

    fun oidForAlias(alias: String): ObjectIdentifier? = nameToOid[alias]

    override fun decodeATV(
        key: AttributeTypeAndValueProvider.Key,
        value: AttributeTypeAndValueProvider.Value
    ): AttributeTypeAndValue? {
        if (key !is AttributeTypeAndValueProvider.StringAlias) return null
        return AtvOidFallbackProvider.decodeATV(
            AttributeTypeAndValueProvider.Key(oidForAlias(key.str) ?: return null),
            value)
    }

    override fun encodeATV(atv: AttributeTypeAndValue): Pair<AttributeTypeAndValueProvider.Key, AttributeTypeAndValueProvider.Value>? {
        val alias = oidToName[atv.oid] ?: return null
        val value = if (atv is TextAttributeTypeAndValue) {
            AttributeTypeAndValueProvider.Value(atv.text)
        } else {
            AtvAsn1FallbackProvider.encodeATV(atv)?.second ?: return null
        }
        return AttributeTypeAndValueProvider.Key(alias) to value
    }
}
