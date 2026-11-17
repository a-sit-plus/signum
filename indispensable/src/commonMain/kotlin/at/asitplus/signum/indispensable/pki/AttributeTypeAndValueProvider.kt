package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.ObjectIdentifier

/**
 * Semantic X.500 text construction and DN naming, independent of its wire representation.
 * Return null for unsupported OIDs or names. Provider priority and failures follow [at.asitplus.signum.ServiceLoader].
 */
interface AttributeTypeAndValueProvider {
    /** Return a text constructor for this OID, or null without interpreting an unsupported value.
     * Construction failures allow the next provider to try the same input.
     */
    fun decoderFor(oid: ObjectIdentifier): ((String) -> AttributeTypeAndValue)? = null
    /** Resolve a DN name or alias, supplied in uppercase. */
    fun oidForName(name: String): ObjectIdentifier? = null
    /** Return the canonical DN name for this OID. */
    fun nameForOid(oid: ObjectIdentifier): String? = null
}

internal object IndispensableAttributeTypeAndValueProvider : AttributeTypeAndValueProvider {
    private val names = mapOf(
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

    private val aliases = names.entries.associate { (oid, name) -> name to oid } + mapOf(
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

    override fun decoderFor(oid: ObjectIdentifier): ((String) -> AttributeTypeAndValue)? {
        if (oid !in names) return null
        return { TextAttributeTypeAndValue(oid, it) }
    }

    override fun oidForName(name: String): ObjectIdentifier? = aliases[name.uppercase()]
    override fun nameForOid(oid: ObjectIdentifier): String? = names[oid]
}
