@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.*

/** An open CSR attribute family, without a format-specific payload contract. */
interface CsrAttribute : Identifiable, WithSourceRepresentation {
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
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    init { require(extensions.isNotEmpty()) { "At least one extension is required" } }
}

class OpaqueCsrAttribute(
    override val oid: ObjectIdentifier,
    val decodingFailure: UnsupportedCryptoException? = null,
) : CsrAttribute {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    @OptIn(SignumInternals::class)
    override fun equals(other: Any?): Boolean = this === other || other is OpaqueCsrAttribute &&
            oid == other.oid && (sourceRepresentation presentAndEquals other.sourceRepresentation)
    override fun hashCode(): Int = 31 * oid.hashCode() + sourceRepresentation.hashCode()
    override fun toString(): String = "OpaqueCsrAttribute($oid, $sourceRepresentation)"
}
