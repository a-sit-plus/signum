package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeWith
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1

interface AttributeTypeAndValueAsn1Provider {
    fun decodeFromAsn1(value: X500AttributeTypeAndValue): AttributeTypeAndValue?
    fun encodeToAsn1(value: AttributeTypeAndValue): X500AttributeTypeAndValue?
}

interface CsrAttributeAsn1Provider {
    fun decodeFromAsn1(value: Pkcs10CsrAttribute): CsrAttribute?
    fun encodeToAsn1(value: CsrAttribute): Pkcs10CsrAttribute?
}

@OptIn(SignumInternals::class)
internal fun decodeAsn1Attribute(source: X500AttributeTypeAndValue): AttributeTypeAndValue =
    decodeWith(
        AttributeTypeAndValueAsn1Provider::decodeFromAsn1,
        { wire, failure -> AttributeTypeAndValue.Unknown(wire.oid, wire, failure) },
    )(source)

object AttributeAsn1Provider : AttributeTypeAndValueAsn1Provider {
    override fun decodeFromAsn1(value: X500AttributeTypeAndValue) =
        decodeFromAsn1(value.oid, value.value)

    fun decodeFromAsn1(oid: ObjectIdentifier, value: Asn1Element): AttributeTypeAndValue? {
        encoderFor(oid) ?: return null
        val str = Asn1String.decodeFromTlv(value.asPrimitive())
        return TextAttributeTypeAndValue(oid, str.value)
    }

    override fun encodeToAsn1(value: AttributeTypeAndValue): X500AttributeTypeAndValue? {
        if (value !is TextAttributeTypeAndValue) return null
        val encode = encoderFor(value.oid) ?: return null
        return X500AttributeTypeAndValue(value.oid, encode(value.text).encodeToTlv())
    }

    private fun encoderFor(oid: ObjectIdentifier): ((String) -> Asn1String)? = when (oid) {
        AttributeTypeAndValue.OID.domainComponent,
        AttributeTypeAndValue.OID.emailAddress -> { text -> Asn1String.IA5(text) }

        AttributeTypeAndValue.OID.countryName,
        AttributeTypeAndValue.OID.dnQualifier,
        AttributeTypeAndValue.OID.serialNumber,
        AttributeTypeAndValue.OID.telephoneNumber -> { text -> Asn1String.Printable(text) }

        AttributeTypeAndValue.OID.commonName,
        AttributeTypeAndValue.OID.localityName,
        AttributeTypeAndValue.OID.stateOrProvinceName,
        AttributeTypeAndValue.OID.streetAddress,
        AttributeTypeAndValue.OID.organizationName,
        AttributeTypeAndValue.OID.organizationalUnitName,
        AttributeTypeAndValue.OID.title,
        AttributeTypeAndValue.OID.surname,
        AttributeTypeAndValue.OID.name,
        AttributeTypeAndValue.OID.givenName,
        AttributeTypeAndValue.OID.initials,
        AttributeTypeAndValue.OID.generationQualifier,
        AttributeTypeAndValue.OID.userId -> { text -> Asn1String.UTF8(text) }

        else -> null
    }
}

object ExtensionRequestCsrProvider : CsrAttributeAsn1Provider {
    override fun decodeFromAsn1(value: Pkcs10CsrAttribute): CsrAttribute? =
        if (value.oid == CsrAttribute.EXTENSION_REQUEST_OID)
            ExtensionRequest(value.value.single().asSequence().map { CertificateExtension.fromAsn1(it) })
        else null

    override fun encodeToAsn1(value: CsrAttribute): Pkcs10CsrAttribute? = when (value) {
        is ExtensionRequest -> Pkcs10CsrAttribute.ExtensionRequest(value.extensions.map { it.asn1.toRepresentation() }, Signum.Der)
        else -> null
    }
}
