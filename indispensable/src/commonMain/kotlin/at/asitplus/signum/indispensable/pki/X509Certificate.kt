package at.asitplus.signum.indispensable.pki

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.CertificateValidityException
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findSubjectAltNames
import at.asitplus.signum.indispensable.pki.TbsCertificate.Companion.Tags.EXTENSIONS
import at.asitplus.signum.indispensable.pki.TbsCertificate.Companion.Tags.ISSUER_UID
import at.asitplus.signum.indispensable.pki.TbsCertificate.Companion.Tags.SUBJECT_UID
import at.asitplus.signum.indispensable.pki.pkiExtensions.X500Name
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlinx.serialization.Transient
import kotlinx.serialization.builtins.serializer

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed
 */
data class TbsCertificate
@Throws(Asn1Exception::class)
constructor(
    val version: Int? = 2,
    val serialNumber: ByteArray,
    val signatureAlgorithm: X509SignatureAlgorithm,
    val issuerName: X500Name,
    val validFrom: Asn1Time,
    val validUntil: Asn1Time,
    val subjectName: X500Name,
    val publicKey: CryptoPublicKey,
    val issuerUniqueID: Asn1BitString? = null,
    val subjectUniqueID: Asn1BitString? = null,
    val extensions: List<X509CertificateExtension>? = null,
) : Asn1Encodable<Asn1Sequence> {

    init {
        if (extensions?.distinctBy { it.oid }?.size != extensions?.size) throw Asn1StructuralException(
            "Multiple extensions with the same OID found"
        )

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


    private fun Asn1TreeBuilder.Version(value: Int) =
        Asn1.ExplicitlyTagged(Tags.VERSION.tagValue) { +Asn1.Int(value) }

    val keyUsage: Set<X509KeyUsage>
        get() = extensions
            ?.find { it.oid == ObjectIdentifier("2.5.29.15") }
            ?.value
            ?.asEncapsulatingOctetString()
            ?.children
            ?.getOrNull(0)
            ?.let { Asn1BitString.decodeFromTlv(it as Asn1Primitive) }
            ?.let(X509KeyUsage::decodeSet)
            ?: emptySet()


    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = runRethrowing {
        Asn1.Sequence {
            version?.let { +Version(it) }
            +Asn1Primitive(Asn1Element.Tag.INT, serialNumber)
            +signatureAlgorithm
            +issuerName

            +Asn1.Sequence {
                +validFrom
                +validUntil
            }

            +subjectName

            //subject public key
            +publicKey

            issuerUniqueID?.let { +(it withImplicitTag ISSUER_UID) }
            subjectUniqueID?.let { +(it withImplicitTag SUBJECT_UID) }

            extensions?.let {
                if (it.isNotEmpty()) {
                    +Asn1.ExplicitlyTagged(EXTENSIONS.tagValue) {
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
        var result = version?.hashCode() ?: 0
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

    override fun toString(): String {
        return "TbsCertificate(${encodeToDerOrNull()?.let { it.encodeToString(Base64UrlStrict) }})"
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsCertificate> {

        object Tags {
            val ISSUER_UID = Asn1.ImplicitTag(1uL)
            val SUBJECT_UID = Asn1.ImplicitTag(2uL)
            val EXTENSIONS = Asn1.ExplicitTag(3uL)
            val VERSION = Asn1.ExplicitTag(0uL)
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence) = runRethrowing {
            val version = src.peek().let {
                if (it is Asn1ExplicitlyTagged) {
                    (it.verifyTag(Tags.VERSION).single() as Asn1Primitive).decodeToInt()
                        .also { src.nextChild() } // actually read it, so next child is serial number
                } else {
                    null
                }
            }
            val serialNumber = (src.nextChild() as Asn1Primitive).decode(Asn1Element.Tag.INT) { it }
            val sigAlg = X509SignatureAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
//            val issuerNames = (src.nextChild() as Asn1Sequence).children.map {
//                RelativeDistinguishedName.decodeFromTlv(it as Asn1Set)
//            }
            val issuerNames = X500Name.doDecode(src.nextChild() as Asn1Sequence)

            val timestamps = decodeTimestamps(src.nextChild() as Asn1Sequence)
//            val subject = (src.nextChild() as Asn1Sequence).children.map {
//                RelativeDistinguishedName.decodeFromTlv(it as Asn1Set)
//            }
            val subject = X500Name.doDecode(src.nextChild() as Asn1Sequence)


            val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(src.nextChild() as Asn1Sequence)

            val issuerUniqueID = src.peek()?.let { next ->
                if (next.tag == ISSUER_UID) {
                    (src.nextChild() as Asn1Primitive).let {
                        Asn1BitString.decodeFromTlv(
                            it,
                            ISSUER_UID
                        )
                    }
                } else null
            }

            val subjectUniqueID = src.peek()?.let { next ->
                if (next.tag == SUBJECT_UID) {
                    (src.nextChild() as Asn1Primitive).let {
                        Asn1BitString.decodeFromTlv(
                            it,
                            SUBJECT_UID
                        )
                    }
                } else null
            }
            val extensions = if (src.hasMoreChildren()) {
                ((src.nextChild() as Asn1ExplicitlyTagged).verifyTag(EXTENSIONS.tagValue)
                    .single() as Asn1Sequence).children.map {
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
                issuerUniqueID = issuerUniqueID,
                subjectUniqueID = subjectUniqueID,
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
 * Signature encoded as per X.509:
 * - RSA remains a bit string
 * - EC is DER-encoded then wrapped in a bit string
 */
val CryptoSignature.x509Encoded
    get() = when (this) {
        is CryptoSignature.EC -> encodeToDer().encodeToAsn1BitStringPrimitive()
        is CryptoSignature.RSA -> encodeToTlv()
    }

/**
 * Decode a X.509-encoded signature
 * - RSA is encoded as a bit string
 * - EC is DER-encoded then wrapped in a bit string
 */
fun CryptoSignature.Companion.fromX509Encoded(alg: X509SignatureAlgorithm, it: Asn1Primitive) =
    when (alg.isEc) {
        true -> CryptoSignature.EC.decodeFromDer(it.asAsn1BitString().rawBytes)
        false -> CryptoSignature.RSA.decodeFromTlv(it)
    }

/**
 * Very simple implementation of an X.509 Certificate
 */
data class X509Certificate @Throws(IllegalArgumentException::class) constructor(
    val tbsCertificate: TbsCertificate,
    val signatureAlgorithm: X509SignatureAlgorithm,
    val signature: CryptoSignature,
) : PemEncodable<Asn1Sequence> {

    override val canonicalPEMBoundary: String = EB_STRINGS.DEFAULT

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = Asn1.Sequence {
        +tbsCertificate
        +signatureAlgorithm
        +signature.x509Encoded
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

    override fun toString(): String {
        return "X509Certificate(${encodeToDerOrNull()?.let { it.encodeToString(Base64UrlStrict) }})"
    }

    val publicKey: CryptoPublicKey get() = tbsCertificate.publicKey

//    //    TODO refactor
//    fun pathLenConstraint(): Int? =
//        tbsCertificate.extensions
//            ?.firstOrNull { it.oid == ObjectIdentifier(KnownOIDs.basicConstraints.toString()) }
//            ?.value
//            ?.asEncapsulatingOctetString()
//            ?.children?.firstOrNull()
//            ?.asSequence()
//            ?.children?.getOrNull(1)
//            ?.asPrimitive()
//            ?.decodeToInt()
//
//    //    TODO refactor
//    fun isCA(): Boolean =
//        tbsCertificate.extensions
//            ?.firstOrNull { it.oid == ObjectIdentifier(KnownOIDs.basicConstraints.toString()) }
//            ?.value
//            ?.asEncapsulatingOctetString()
//            ?.children?.firstOrNull()
//            ?.asSequence()
//            ?.children?.getOrNull(0)
//            ?.asPrimitive()
//            ?.decodeToBoolean()
//            ?: false

    fun hasReplayingExtensions(): Boolean =
        tbsCertificate.extensions?.size != tbsCertificate.extensions?.distinctBy { it.oid }?.size

    fun isSelfIssued(): Boolean = tbsCertificate.subjectName == tbsCertificate.issuerName

    fun findExtension(oid: ObjectIdentifier): X509CertificateExtension? =
        tbsCertificate.extensions?.firstOrNull { it.oid == oid }

    fun checkValidity(date: Instant = Clock.System.now()) {
        if (date > tbsCertificate.validUntil.instant) {
            throw CertificateValidityException(
                "certificate expired on " + tbsCertificate.validUntil.instant.toLocalDateTime(
                    TimeZone.currentSystemDefault()
                )
            )
        }

        if (date < tbsCertificate.validFrom.instant) {
            throw CertificateValidityException(
                "certificate not valid till " + tbsCertificate.validFrom.instant.toLocalDateTime(
                    TimeZone.currentSystemDefault()
                )
            )
        }
    }

    companion object :
        PemDecodable<Asn1Sequence, X509Certificate>(EB_STRINGS.DEFAULT, EB_STRINGS.LEGACY) {

        private object EB_STRINGS {
            const val DEFAULT = "CERTIFICATE"
            const val LEGACY = "TRUSTED CERTIFICATE"
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509Certificate = runRethrowing {
            val tbs = TbsCertificate.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val sigAlg = X509SignatureAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val signature =
                CryptoSignature.fromX509Encoded(sigAlg, src.nextChild() as Asn1Primitive)
            if (src.hasMoreChildren()) throw Asn1StructuralException("Superfluous structure in Certificate Structure")
            return X509Certificate(tbs, sigAlg, signature)
        }

        /**
         * Tries to decode [src] into an [X509Certificate], by parsing the bytes directly as ASN.1 structure,
         * or by decoding from Base64, or by decoding to a String, stripping PEM headers
         * (`-----BEGIN CERTIFICATE-----`) and then decoding from Base64.
         */
        fun decodeFromByteArray(src: ByteArray): X509Certificate? = catchingUnwrapped {
            X509Certificate.decodeFromTlv(Asn1Element.parse(src) as Asn1Sequence)
        }.getOrNull() ?: catchingUnwrapped {
            X509Certificate.decodeFromTlv(Asn1Element.parse(src.decodeToByteArray(Base64())) as Asn1Sequence)
        }.getOrNull() ?: X509Certificate.decodeFromPem(src.decodeToString()).getOrNull()
    }
}

typealias CertificateChain = List<X509Certificate>

val CertificateChain.leaf: X509Certificate get() = first()
val CertificateChain.root: X509Certificate get() = last()

private
/** De-/serializes Base64 strings to/from [ByteArray] */
object Asn1BitStringSerializer : TransformingSerializerTemplate<Asn1BitString?, String>(
    parent = String.serializer(),
    encodeAs = {
        if (it == null) "" else byteArrayOf(
            it.numPaddingBits,
            *it.rawBytes
        ).encodeToString(Base64Strict)
    },
    decodeAs = {
        if (it == "") null
        else Asn1BitString.decodeFromTlv(
            Asn1Primitive(
                Asn1Element.Tag.BIT_STRING,
                it.decodeToByteArray(Base64Strict)
            )
        )
    }
)