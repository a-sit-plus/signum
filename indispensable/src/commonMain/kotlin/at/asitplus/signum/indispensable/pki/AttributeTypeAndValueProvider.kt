package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.encoding.parse
import at.asitplus.signum.indispensable.SignumEncodingHelpers
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
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
     * - [value] may be either [StringValue] or [ByteArrayValue] (parsed from #-prefixed hex form). */
    fun decodeATV(key: Key, value: Value): AttributeTypeAndValue?

    /** Encode an ATV to a key=value pair. The result should be of a format suitable for [decodeATV]. [StringAlias] should be preferred over [OID]. */
    fun encodeATV(atv: AttributeTypeAndValue): Pair<Key, Value>?
}

object AtvAsn1FallbackProvider : AttributeTypeAndValueProvider {
    override fun decodeATV(
        key: AttributeTypeAndValueProvider.Key,
        value: AttributeTypeAndValueProvider.Value
    ): AttributeTypeAndValue? {
        if (key !is AttributeTypeAndValueProvider.OID) return null
        if (value !is AttributeTypeAndValueProvider.ByteArrayValue) return null
        return AttributeTypeAndValue.fromAsn1(
            X500AttributeTypeAndValue(key.oid, Asn1Element.parse(value.bytes)))
    }

    override fun encodeATV(atv: AttributeTypeAndValue) =
        atv.asn1.toRepresentation().let {
            Pair(
                AttributeTypeAndValueProvider.Key(it.oid),
                AttributeTypeAndValueProvider.Value(it.value.derEncoded)
            )
        }
}

object AtvOidFallbackProvider: AttributeTypeAndValueProvider {
    override fun decodeATV(
        key: AttributeTypeAndValueProvider.Key,
        value: AttributeTypeAndValueProvider.Value
    ): AttributeTypeAndValue? {
        if (key !is AttributeTypeAndValueProvider.OID) return null
        return when (value) {
            is AttributeTypeAndValueProvider.StringValue ->
                TextAttributeTypeAndValue(key.oid, value.str)
            is AttributeTypeAndValueProvider.ByteArrayValue ->
                SignumEncodingHelpers.decodeFrom { src: X500AttributeTypeAndValue ->
                    AttributeAsn1Provider.decodeFromAsn1(src.oid, src.value) ?:
                        throw Asn1Exception("Unknown string-type key ${src.oid}")
                } (X500AttributeTypeAndValue(key.oid, Asn1Element.parse(value.bytes)))
        }
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

    override fun decodeATV(
        key: AttributeTypeAndValueProvider.Key,
        value: AttributeTypeAndValueProvider.Value
    ): AttributeTypeAndValue? {
        if (key !is AttributeTypeAndValueProvider.StringAlias) return null
        return AtvOidFallbackProvider.decodeATV(
            AttributeTypeAndValueProvider.Key(nameToOid[key.str] ?: return null),
            value)
    }

    override fun encodeATV(atv: AttributeTypeAndValue): Pair<AttributeTypeAndValueProvider.Key, AttributeTypeAndValueProvider.Value>? {
        return Pair(
            AttributeTypeAndValueProvider.Key(oidToName[atv.oid] ?: return null),
            when {
                atv is TextAttributeTypeAndValue -> AttributeTypeAndValueProvider.StringValue(atv.text)
                else -> AttributeTypeAndValueProvider.ByteArrayValue(atv.asn1.toRepresentation().value.derEncoded)
            }
        )
    }
}
