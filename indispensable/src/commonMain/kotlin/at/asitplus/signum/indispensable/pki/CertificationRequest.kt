package at.asitplus.signum.indispensable.pki
import at.asitplus.signum.indispensable.Encodable

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.allDistinctByOids
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension
/**
 * The meat of a Certification Request:
 * The structure that gets signed.
 *
 * @param subjectName list of subject distinguished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
class TbsCertificationRequest internal constructor(
    contentProvider: () -> ContentContainer,
    override val representations: Map<Encodable.Representation, Any>,
) : Encodable {
    private val content by lazy(contentProvider)

    internal data class ContentContainer(
        val subjectName: Name,
        val publicKey: CryptoPublicKey,
        val attributes: List<CsrAttribute>,
    )

    constructor(
        subjectName: Name,
        publicKey: CryptoPublicKey,
        attributes: List<CsrAttribute> = listOf(),
    ) : this({ ContentContainer(subjectName, publicKey, attributes) }, emptyMap()) {
        validateAttributes(attributes, allowExtensions = true)
    }

    /**
     * Convenience constructor for adding [CertificateExtension]`s` to a CSR in addition to generic attributes.
     *
     * @throws IllegalArgumentException if an empty extension list is provided
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: Name,
        publicKey: CryptoPublicKey,
        extensions: List<CertificateExtension>? = null,
        attributesWithoutExtensions: List<CsrAttribute>? = null,
    ) : this(
        subjectName = subjectName,
        publicKey = publicKey,
        attributes = mergeAttributesWithExtensions(attributesWithoutExtensions, extensions),
    )

    val subjectName: Name get() = content.subjectName
    val publicKey: CryptoPublicKey get() = content.publicKey
    val attributes: List<CsrAttribute> get() = content.attributes

    val attributesWithoutExtensions: List<CsrAttribute> by lazy { attributes.filterNot { it.oid == Pkcs10CsrAttribute.EXTENSION_REQUEST_OID } }

    val extensions: List<CertificateExtension> by lazy {
        attributes.filter { it.oid == Pkcs10CsrAttribute.EXTENSION_REQUEST_OID }.let { extensionAttributes ->
            when (extensionAttributes.size) {
                0 -> emptyList()
                1 -> requireNotNull(extensionAttributes.single().asn1Representation).value.single().asSequence().map {
                    CertificateExtension(DER.decodeFromTlv(Awesn1X509CertificateExtension.serializer(), it))
                }

                else -> throw Asn1StructuralException("Multiple extensionRequest attributes found")
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TbsCertificationRequest) return false
        return subjectName == other.subjectName &&
                publicKey == other.publicKey &&
                attributes == other.attributes
    }

    override fun hashCode(): Int {
        var result = subjectName.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + attributes.hashCode()
        return result
    }

    override fun toString(): String =
        "TbsCertificationRequest(subjectName=$subjectName, publicKey=$publicKey, attributes=$attributes)"

    companion object : Decodable<TbsCertificationRequest>
}

/**
 * Very simple implementation of a PKCS#10 Certification Request.
 */
class CertificationRequest internal constructor(
    contentProvider: () -> ContentContainer,
    override val representations: Map<Encodable.Representation, Any>,
) : Encodable {
    private val content by lazy(contentProvider)

    internal data class ContentContainer(
        val tbsCsr: TbsCertificationRequest,
        val signatureAlgorithm: SignatureAlgorithm,
        val signature: CryptoSignature,
    )

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: SignatureAlgorithm,
        signature: CryptoSignature,
    ) : this({ ContentContainer(tbsCsr, signatureAlgorithm, signature) }, emptyMap())

    val tbsCsr: TbsCertificationRequest get() = content.tbsCsr
    val signatureAlgorithm: SignatureAlgorithm get() = content.signatureAlgorithm
    val signature: CryptoSignature get() = content.signature

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CertificationRequest) return false
        return tbsCsr == other.tbsCsr &&
                signatureAlgorithm == other.signatureAlgorithm &&
                signature == other.signature
    }

    override fun hashCode(): Int {
        var result = tbsCsr.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }

    override fun toString(): String =
        "Pkcs10CertificationRequest(tbsCsr=$tbsCsr, signatureAlgorithm=$signatureAlgorithm, signature=$signature)"

    companion object : Decodable<CertificationRequest>
}

private fun validateAttributes(attributes: List<CsrAttribute>, allowExtensions: Boolean = false) {
    require(attributes.allDistinctByOids()) { "Multiple attributes with same OID found" }
    if (!allowExtensions) require(attributes.none { it.oid == Pkcs10CsrAttribute.EXTENSION_REQUEST_OID }) {
        "Certificate extension passed as part of regular attributes"
    }
}

private fun mergeAttributesWithExtensions(
    attributes: List<CsrAttribute>?,
    extensions: List<CertificateExtension>?,
): List<CsrAttribute> {
    attributes?.let(::validateAttributes)
    extensions?.let { require(it.isNotEmpty()) { "At least one extension is required" } }

    return mutableListOf<CsrAttribute>().apply {
        attributes?.let { addAll(it) }
        extensions?.let {
            add(CsrAttribute(Pkcs10CsrAttribute.ExtensionRequest(it.map { extension ->
                extension.asn1Representation
                    ?: throw Asn1Exception("Certificate extension ${extension.oid} has no X.509/DER representation")
            })))
        }
    }
}
