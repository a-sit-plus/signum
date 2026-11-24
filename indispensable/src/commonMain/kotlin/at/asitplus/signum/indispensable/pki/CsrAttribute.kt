package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.*

/** An open CSR attribute family, without a format-specific payload contract. */
interface CsrAttribute : Identifiable, WithSourceRepresentation {
    @SignumInternals
    class Unknown internal constructor(
        override val oid: ObjectIdentifier,
        source: Any,
        lookupResult: UnsupportedCryptoException,
    ) : CsrAttribute, ServiceLoader.UnknownShim(source, lookupResult)

    companion object {
        val EXTENSION_REQUEST_OID = ObjectIdentifier("1.2.840.113549.1.9.14")
        operator fun invoke(oid: ObjectIdentifier, value: Set<Asn1Element>): CsrAttribute =
            fromAsn1(Pkcs10CsrAttribute(oid, value))
        operator fun invoke(oid: ObjectIdentifier, value: Asn1Element): CsrAttribute = invoke(oid, setOf(value))
        operator fun invoke(asn1Representation: Pkcs10CsrAttribute): CsrAttribute = fromAsn1(asn1Representation)
    }
}

data class ExtensionRequest(val extensions: List<CertificateExtension>) : CsrAttribute {
    override val oid get() = CsrAttribute.EXTENSION_REQUEST_OID
    override val sourceRepresentation = SourceRepresentationStorage()
    init { require(extensions.isNotEmpty()) { "At least one extension is required" } }
}
