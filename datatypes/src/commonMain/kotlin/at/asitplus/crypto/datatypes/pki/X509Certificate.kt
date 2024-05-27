package at.asitplus.crypto.datatypes.pki

import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.asn1.DERTags.toImplicitTag
import at.asitplus.crypto.datatypes.io.BitSet
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import at.asitplus.crypto.datatypes.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.crypto.datatypes.pki.AlternativeNames.Companion.findSubjectAltNames
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed
 */
@Serializable
data class TbsCertificate
@Throws(Asn1Exception::class)
constructor(
    val version: Int = 2,
    @Serializable(with = ByteArrayBase64Serializer::class) val serialNumber: ByteArray,
    val signatureAlgorithm: CryptoAlgorithm,
    val issuerName: List<RelativeDistinguishedName>,
    val validFrom: Asn1Time,
    val validUntil: Asn1Time,
    val subjectName: List<RelativeDistinguishedName>,
    val publicKey: CryptoPublicKey,
    val issuerUniqueID: BitSet? = null,
    val subjectUniqueID: BitSet? = null,
    val extensions: List<X509CertificateExtension>? = null
) : Asn1Encodable<Asn1Sequence> {

    init {
        if (extensions?.distinctBy { it.oid }?.size != extensions?.size) throw Asn1StructuralException("Multiple extensions with the same OID found")
    }

    /**
     * Contains `SubjectAlternativeName`s parsed from extensions. This property is initialized right away.
     * This incurs *some* structural validation, but still allows for contents violating
     * [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280), e.g. all UTF-8 strings are accepted, even though
     * this is too lenient.
     */
    @Transient
    val subjectAlternativeNames: AlternativeNames? = extensions?.findSubjectAltNames()

    /**
     * Contains `IssuerAlternativeName`s parsed from extensions. This property is initialized right away.
     * This incurs *some* structural validation, but still allows for contents violating
     * [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280), e.g. all UTF-8 strings are accepted, even though
     * this is too lenient.
     */
    @Transient
    val issuerAlternativeNames: AlternativeNames? = extensions?.findIssuerAltNames()


    private fun Asn1TreeBuilder.Version(value: Int) = Asn1.Tagged(0u) { +Asn1.Int(value) }


    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = runRethrowing {
        Asn1.Sequence {
            +Version(version)
            +Asn1Primitive(BERTags.INTEGER, serialNumber)
            +signatureAlgorithm
            +Asn1.Sequence { issuerName.forEach { +it } }

            +Asn1.Sequence {
                +validFrom
                +validUntil
            }

            +Asn1.Sequence { subjectName.forEach { +it } }

            //subject public key
            +publicKey

            issuerUniqueID?.let {
                +Asn1Primitive(
                    1u.toImplicitTag(),
                    Asn1BitString(it).let { byteArrayOf(it.numPaddingBits, *it.rawBytes) })
            }
            subjectUniqueID?.let {
                +Asn1Primitive(
                    1u.toImplicitTag(),
                    Asn1BitString(it).let { byteArrayOf(it.numPaddingBits, *it.rawBytes) })

            }

            extensions?.let {
                if (it.isNotEmpty()) {
                    +Asn1.Tagged(3u) {
                        +Asn1.Sequence {
                            it.forEach { ext -> +ext }
                        }
                    }
                }
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as TbsCertificate

        if (version != other.version) return false
        if (!serialNumber.contentEquals(other.serialNumber)) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (issuerName != other.issuerName) return false
        if (validFrom != other.validFrom) return false
        if (validUntil != other.validUntil) return false
        if (subjectName != other.subjectName) return false
        if (publicKey != other.publicKey) return false
        if (issuerUniqueID != other.issuerUniqueID) return false
        if (subjectUniqueID != other.subjectUniqueID) return false
        if (extensions != other.extensions) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + serialNumber.contentHashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + issuerName.hashCode()
        result = 31 * result + validFrom.hashCode()
        result = 31 * result + validUntil.hashCode()
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + (issuerUniqueID?.hashCode() ?: 0)
        result = 31 * result + (subjectUniqueID?.hashCode() ?: 0)
        result = 31 * result + (extensions?.hashCode() ?: 0)
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsCertificate> {
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence) = runRethrowing {
            //TODO make sure to always check for superfluous data
            val version = src.nextChild().let {
                ((it as Asn1Tagged).verifyTag(0u).single() as Asn1Primitive).readInt()
            }
            val serialNumber = (src.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
            val sigAlg = CryptoAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val issuerNames = (src.nextChild() as Asn1Sequence).children.map {
                RelativeDistinguishedName.decodeFromTlv(it as Asn1Set)
            }

            val timestamps = decodeTimestamps(src.nextChild() as Asn1Sequence)
            val subject = (src.nextChild() as Asn1Sequence).children.map {
                RelativeDistinguishedName.decodeFromTlv(it as Asn1Set)
            }

            val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(src.nextChild() as Asn1Sequence)

            val issuerUniqueID = src.peek()?.let { next ->
                if (next.tag == 1u.toImplicitTag()) {
                    (src.nextChild() as Asn1Primitive).let { Asn1BitString.decodeFromTlv(it, 1u.toImplicitTag()) }
                } else null
            }

            val subjectUniqueID = src.peek()?.let { next ->
                if (next.tag == 2u.toImplicitTag()) {
                    (src.nextChild() as Asn1Primitive).let { Asn1BitString.decodeFromTlv(it, 2u.toImplicitTag()) }
                } else null
            }
            val extensions = if (src.hasMoreChildren()) {
                ((src.nextChild() as Asn1Tagged).verifyTag(3u).single() as Asn1Sequence).children.map {
                    X509CertificateExtension.decodeFromTlv(it as Asn1Sequence)
                }
            } else null

            if (src.hasMoreChildren()) throw Asn1StructuralException("Superfluous Data in Certificate Structure")

            TbsCertificate(
                version = version,
                serialNumber = serialNumber,
                signatureAlgorithm = sigAlg,
                issuerName = issuerNames,
                validFrom = timestamps.first,
                validUntil = timestamps.second,
                subjectName = subject,
                publicKey = cryptoPublicKey,
                issuerUniqueID = issuerUniqueID?.toBitSet(),
                subjectUniqueID = subjectUniqueID?.toBitSet(),
                extensions = extensions,
            )
        }

        private fun decodeTimestamps(input: Asn1Sequence): Pair<Asn1Time, Asn1Time> =
            runRethrowing {
                val firstInstant = Asn1Time.decodeFromTlv(input.nextChild() as Asn1Primitive)
                val secondInstant = Asn1Time.decodeFromTlv(input.nextChild() as Asn1Primitive)
                if (input.hasMoreChildren()) throw Asn1StructuralException("Superfluous content in Validity")
                return Pair(firstInstant, secondInstant)
            }
    }
}

/**
 * Very simple implementation of an X.509 Certificate
 */
@Serializable
data class X509Certificate @Throws(IllegalArgumentException::class) constructor(
    val tbsCertificate: TbsCertificate,
    val signatureAlgorithm: CryptoAlgorithm,
    val signature: CryptoSignature
) : Asn1Encodable<Asn1Sequence> {


    init {
        if (signature is CryptoSignature.EC.IndefiniteLength) {
            throw IllegalArgumentException("Certificate Signatures must be well-defined!")
        }
    }

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = Asn1.Sequence {
        +tbsCertificate
        +signatureAlgorithm
        +signature.encodeToTlvBitString()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X509Certificate

        if (tbsCertificate != other.tbsCertificate) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCertificate.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }

    val publicKey: CryptoPublicKey get() = tbsCertificate.publicKey

    companion object : Asn1Decodable<Asn1Sequence, X509Certificate> {

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence): X509Certificate = runRethrowing {
            val tbs = TbsCertificate.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val sigAlg = CryptoAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val signature = if (sigAlg.isEc) CryptoSignature.EC.decodeFromTlvBitString(src.nextChild() as Asn1Primitive)
                .withCurve(sigAlg.curve!!) else CryptoSignature.RSAorHMAC.decodeFromTlvBitString(src.nextChild() as Asn1Primitive)
            if (src.hasMoreChildren()) throw Asn1StructuralException("Superfluous structure in Certificate Structure")
            return X509Certificate(tbs, sigAlg, signature)
        }

        /**
         * Tries to decode [src] into an [X509Certificate], by parsing the bytes directly as ASN.1 structure,
         * or by decoding from Base64, or by decoding to a String, stripping PEM headers
         * (`-----BEGIN CERTIFICATE-----`) and then decoding from Base64.
         */
        fun decodeFromByteArray(src: ByteArray): X509Certificate? = runCatching {
            X509Certificate.decodeFromTlv(Asn1Element.parse(src) as Asn1Sequence)
        }.getOrNull() ?: runCatching {
            X509Certificate.decodeFromTlv(Asn1Element.parse(src.decodeToByteArray(Base64())) as Asn1Sequence)
        }.getOrNull() ?: runCatching {
            X509Certificate.decodeFromTlv(Asn1Element.parse(src.decodeX5c()) as Asn1Sequence)
        }.getOrNull()

        private fun ByteArray.decodeX5c() = decodeToString()
            .replace("-----BEGIN CERTIFICATE-----\n", "")
            .replace("\n-----END CERTIFICATE-----", "")
            .decodeToByteArray(Base64())

    }
}

typealias CertificateChain = List<X509Certificate>

val CertificateChain.leaf: X509Certificate get() = first()
val CertificateChain.root: X509Certificate get() = last()
