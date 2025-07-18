package at.asitplus.signum.indispensable.pki

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.BitString
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1BitString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.Serializable

/**
 * The meat of a PKCS#10 Certification Request:
 * The structure that gets signed
 * @param version defaults to 0
 * @param subjectName list of subject distinguished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
data class TbsCertificationRequest(
    val version: Int = 0,
    val subjectName: List<RelativeDistinguishedName>,
    val publicKey: CryptoPublicKey,
    val attributes: List<Pkcs10CertificationRequestAttribute> = listOf()
) : Asn1Encodable<Asn1Sequence> {

    /**
     * Convenience constructor for adding [X509CertificateExtension]`s` to a CSR (in addition to generic attributes
     *
     * @throws IllegalArgumentException if no extensions are provided
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        extensions: List<X509CertificateExtension>? = null,
        version: Int = 0,
        attributes: List<Pkcs10CertificationRequestAttribute>? = null,
    ) : this(version, subjectName, publicKey, mutableListOf<Pkcs10CertificationRequestAttribute>().also { attrs ->
        attributes?.let { attrs.addAll(it) }
        extensions?.let { extn ->
            attrs.add(
                Pkcs10CertificationRequestAttribute(
                    KnownOIDs.extensionRequest,
                    Asn1.Sequence { extn.forEach { +it } })
            )
        }
    })

    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(version)
        +Asn1.Sequence { subjectName.forEach { +it } }

        //subject Public Key
        +publicKey
        +ExplicitlyTagged(0u) { attributes.map { +it } }
    }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as TbsCertificationRequest

        if (version != other.version) return false
        if (subjectName != other.subjectName) return false
        if (publicKey != other.publicKey) return false
        if (attributes != other.attributes) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + (attributes.hashCode())
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsCertificationRequest> {
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence) = src.decodeRethrowing {
            val version = (next() as Asn1Primitive).decodeToInt()
            val subject = (next() as Asn1Sequence).children.map {
                RelativeDistinguishedName.decodeFromTlv(it as Asn1Set)
            }
            val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(next() as Asn1Sequence)
            val attributes = if (hasNext()) {
                (next() as Asn1ExplicitlyTagged).verifyTag(0u)
                    .map { Pkcs10CertificationRequestAttribute.decodeFromTlv(it as Asn1Sequence) }
            } else null
            TbsCertificationRequest(
                version = version,
                subjectName = subject,
                publicKey = cryptoPublicKey,
                attributes = attributes,
            )
        }
    }
}


/**
 * Very simple implementation of a PKCS#10 Certification Request
 */
data class Pkcs10CertificationRequest(
    val tbsCsr: TbsCertificationRequest,
    val signatureAlgorithm: X509SignatureAlgorithm,
    val rawSignature: Asn1Element
) : PemEncodable<Asn1Sequence> {

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: X509SignatureAlgorithm,
        signature: CryptoSignature
    ) : this(tbsCsr, signatureAlgorithm, signature.x509Encoded)

    override val canonicalPEMBoundary: String = EB_STRINGS.DEFAULT


    @Deprecated("imprecisely named", ReplaceWith("decodedSignature"), DeprecationLevel.ERROR)
    val signature: CryptoSignature? get() = decodedSignature

    val decodedSignature: CryptoSignature? by lazy {
        catchingUnwrapped {
            require(signatureAlgorithm.isKnown()) { "Unknown signature algorithm:${signatureAlgorithm.oid}" }
            CryptoSignature.fromX509Encoded(
                signatureAlgorithm,
                rawSignature.asPrimitive()
            )
        }.getOrNull()
    }

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = Asn1.Sequence {
        +tbsCsr
        +signatureAlgorithm
        +rawSignature
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Pkcs10CertificationRequest

        if (tbsCsr != other.tbsCsr) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (rawSignature != other.rawSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCsr.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + rawSignature.hashCode()
        return result
    }

    companion object : PemDecodable<Asn1Sequence, Pkcs10CertificationRequest>(
        EB_STRINGS.DEFAULT,
        EB_STRINGS.LEGACY
    ) {
        private object EB_STRINGS {
            const val DEFAULT = "CERTIFICATE REQUEST"
            const val LEGACY = "NEW CERTIFICATE REQUEST"
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): Pkcs10CertificationRequest = src.decodeRethrowing {
            val tbsCsr = TbsCertificationRequest.decodeFromTlv(next().asSequence())
            val sigAlg = X509SignatureAlgorithm.decodeFromTlv(next().asSequence())
            val signature = next().asPrimitive()
            return Pkcs10CertificationRequest(tbsCsr, sigAlg, signature)
        }
    }
}
