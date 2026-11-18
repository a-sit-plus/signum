package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.Signum
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.UnsupportedCryptoException
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
        return try {
            ServiceLoader.load<AttributeTypeAndValueProvider>().get(value) {
                val construct = decoderFor(it.oid) ?: return@get null
                val text = Asn1String.decodeFromTlv(it.value.asPrimitive())
                require(text.isValid != false) { "Malformed attribute string ${it.oid}" }
                construct(text.value)
            }
        } catch (failure: UnsupportedCryptoException) {
            if (failure.suppressedExceptions.isNotEmpty()) throw failure
            null
        }
    }

    override fun encodeToAsn1(value: AttributeTypeAndValue): X500AttributeTypeAndValue? {
        if (value !is TextAttributeTypeAndValue) return null
        val text = when (value.oid) {
            AttributeTypeAndValue.OID.domainComponent,
            AttributeTypeAndValue.OID.emailAddress -> Asn1String.IA5(value.text)
            AttributeTypeAndValue.OID.countryName,
            AttributeTypeAndValue.OID.dnQualifier,
            AttributeTypeAndValue.OID.serialNumber,
            AttributeTypeAndValue.OID.telephoneNumber -> Asn1String.Printable(value.text)
            else -> Asn1String.UTF8(value.text)
        }
        return X500AttributeTypeAndValue(value.oid, text.encodeToTlv())
    }

    override fun decodeFromAsn1(value: Pkcs10CsrAttribute): CsrAttribute? =
        if (value.oid == CsrAttribute.EXTENSION_REQUEST_OID)
            ExtensionRequest(value.value.single().asSequence().map { CertificateExtension.fromAsn1(it) })
        else null

    override fun encodeToAsn1(value: CsrAttribute): Pkcs10CsrAttribute? = when (value) {
        is ExtensionRequest -> Pkcs10CsrAttribute.ExtensionRequest(value.extensions.map { it.asn1.toRepresentation() }, Signum.Der)
        else -> null
    }
}
