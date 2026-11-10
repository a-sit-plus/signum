package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.asn1

interface AttributeTypeAndValueAsn1Provider {
    fun decodeFromAsn1(value: X500AttributeTypeAndValue): AttributeTypeAndValue?
    fun encodeToAsn1(value: AttributeTypeAndValue): X500AttributeTypeAndValue?
}

interface CsrAttributeAsn1Provider {
    fun decodeFromAsn1(value: Pkcs10CsrAttribute): CsrAttribute?
    fun encodeToAsn1(value: CsrAttribute): Pkcs10CsrAttribute?
}

internal object AttributeAsn1Provider : AttributeTypeAndValueAsn1Provider, CsrAttributeAsn1Provider {
    override fun decodeFromAsn1(value: X500AttributeTypeAndValue): AttributeTypeAndValue? {
        val descriptor = Signum.attributeDescriptorFor(value.oid) ?: return null
        val text = Asn1String.decodeFromTlv(value.value.asPrimitive())
        require(text.isValid != false) { "Malformed attribute string ${value.oid}" }
        return descriptor.fromString(text.value)
    }

    override fun encodeToAsn1(value: AttributeTypeAndValue): X500AttributeTypeAndValue? {
        if (value !is TextAttributeTypeAndValue) return null
        val text = when (value.oid) {
            AttributeTypeAndValue.Descriptor.OID.domainComponent,
            AttributeTypeAndValue.Descriptor.OID.emailAddress -> Asn1String.IA5(value.text)
            AttributeTypeAndValue.Descriptor.OID.countryName,
            AttributeTypeAndValue.Descriptor.OID.dnQualifier,
            AttributeTypeAndValue.Descriptor.OID.serialNumber,
            AttributeTypeAndValue.Descriptor.OID.telephoneNumber -> Asn1String.Printable(value.text)
            else -> Asn1String.UTF8(value.text)
        }
        return X500AttributeTypeAndValue(value.oid, text.encodeToTlv())
    }

    override fun decodeFromAsn1(value: Pkcs10CsrAttribute): CsrAttribute? =
        if (value.oid == CsrAttribute.EXTENSION_REQUEST_OID)
            ExtensionRequest(value.value.single().asSequence().map { CertificateExtension.fromAsn1(it) })
        else null

    override fun encodeToAsn1(value: CsrAttribute): Pkcs10CsrAttribute? = when (value) {
        is ExtensionRequest -> Pkcs10CsrAttribute.ExtensionRequest(value.extensions.map { it.asn1.toRepresentation() })
        else -> null
    }
}
