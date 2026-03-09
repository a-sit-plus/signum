package at.asitplus.signum.indispensable.pki

import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.*
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithmDescription
import at.asitplus.signum.indispensable.asn1.LabelPemDecodable
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.isSupported
import at.asitplus.awesn1.crypto.pki.GeneralNames
import at.asitplus.awesn1.crypto.pki.GeneralNames.Companion.findIssuerAltNames
import at.asitplus.awesn1.crypto.pki.GeneralNames.Companion.findSubjectAltNames
import at.asitplus.awesn1.crypto.pki.TbsCertificate as RawTbsCertificate
import at.asitplus.awesn1.crypto.pki.X509Certificate as RawX509Certificate
import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier as RawSignatureAlgorithmIdentifier
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo as RawSubjectPublicKeyInfo
import at.asitplus.signum.indispensable.Awesn1Backed
import at.asitplus.signum.indispensable.pki.TbsCertificate.Companion.Tags.EXTENSIONS
import at.asitplus.signum.indispensable.pki.TbsCertificate.Companion.Tags.ISSUER_UID
import at.asitplus.signum.indispensable.pki.TbsCertificate.Companion.Tags.SUBJECT_UID
import at.asitplus.signum.indispensable.requireSupported
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Transient
import kotlinx.serialization.builtins.serializer

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed
 */
class TbsCertificate internal constructor(
    override val raw: RawTbsCertificate,
    val version: Int? = 2,
    val serialNumber: ByteArray,
    val signatureAlgorithm: X509SignatureAlgorithmDescription,
    val issuerName: List<RelativeDistinguishedName>,
    val validFrom: Asn1Time,
    val validUntil: Asn1Time,
    val subjectName: List<RelativeDistinguishedName>,
    val rawPublicKey: Asn1Sequence,
    val issuerUniqueID: Asn1BitString? = null,
    val subjectUniqueID: Asn1BitString? = null,
    val extensions: List<X509CertificateExtension>? = null,
) : Asn1Encodable<Asn1Sequence>, Awesn1Backed<RawTbsCertificate> {

    @Throws(Asn1Exception::class)
    constructor(
        version: Int? = 2,
        serialNumber: ByteArray,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        rawPublicKey: Asn1Sequence,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        raw = RawTbsCertificate(
            version = version,
            serialNumber = serialNumber,
            signatureAlgorithm = signatureAlgorithm.toRawSignatureAlgorithmIdentifier(),
            issuerName = issuerName,
            validFrom = validFrom,
            validUntil = validUntil,
            subjectName = subjectName,
            subjectPublicKeyInfo = RawSubjectPublicKeyInfo.decodeFromTlv(rawPublicKey),
            issuerUniqueID = issuerUniqueID,
            subjectUniqueID = subjectUniqueID,
            extensions = extensions,
        ),
        version = version,
        serialNumber = serialNumber,
        signatureAlgorithm = signatureAlgorithm,
        issuerName = issuerName,
        validFrom = validFrom,
        validUntil = validUntil,
        subjectName = subjectName,
        rawPublicKey = rawPublicKey,
        issuerUniqueID = issuerUniqueID,
        subjectUniqueID = subjectUniqueID,
        extensions = extensions,
    )

    constructor(
        version: Int? = 2,
        serialNumber: ByteArray,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(version, serialNumber, signatureAlgorithm, issuerName, validFrom, validUntil, subjectName,
            publicKey.encodeToTlv(), issuerUniqueID, subjectUniqueID, extensions)

    init {
        if (extensions?.distinctBy { it.oid }?.size != extensions?.size) throw Asn1StructuralException("Multiple extensions with the same OID found")
    }

    val decodedPublicKey by lazy { catching {
        CryptoPublicKey.decodeFromTlv(rawPublicKey)
    }}

    @Deprecated("Imprecisely named and does not support unknown algorithms; use `rawPublicKey` or `decodedPublicKey`",
        level = DeprecationLevel.ERROR)
    val publicKey get() = decodedPublicKey.getOrThrow()

    /**
     * Contains `SubjectAlternativeName`s parsed from extensions. This property is initialized right away.
     * This incurs *some* structural validation, but still allows for contents violating
     * [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280), e.g. all UTF-8 strings are accepted, even though
     * this is too lenient.
     */
    @Transient
    val subjectAlternativeNames: GeneralNames? = extensions?.findSubjectAltNames()

    /**
     * Contains `IssuerAlternativeName`s parsed from extensions. This property is initialized right away.
     * This incurs *some* structural validation, but still allows for contents violating
     * [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280), e.g. all UTF-8 strings are accepted, even though
     * this is too lenient.
     */
    @Transient
    val issuerAlternativeNames: GeneralNames? = extensions?.findIssuerAltNames()


    private fun Asn1TreeBuilder.Version(value: Int) = Asn1.ExplicitlyTagged(Tags.VERSION.tagValue) { +Asn1.Int(value) }


    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = raw.encodeToTlv()

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
        if (rawPublicKey != other.rawPublicKey) return false
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
        result = 31 * result + rawPublicKey.hashCode()
        result = 31 * result + (issuerUniqueID?.hashCode() ?: 0)
        result = 31 * result + (subjectUniqueID?.hashCode() ?: 0)
        result = 31 * result + (extensions?.hashCode() ?: 0)
        return result
    }

    /**
     * Debug String representation. Uses Base64 encoded DER representation
     */
    override fun toString(): String {
        return "TbsCertificate(${encodeToDerOrNull()?.let { it.encodeToString(Base64Strict) }})"
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsCertificate> {

        object Tags {
            val ISSUER_UID = Asn1.ImplicitTag(1uL)
            val SUBJECT_UID = Asn1.ImplicitTag(2uL)
            val EXTENSIONS = Asn1.ExplicitTag(3uL)
            val VERSION = Asn1.ExplicitTag(0uL)
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence) = src.decodeRethrowing {
            val version = peek().let {
                if (it is Asn1ExplicitlyTagged) {
                    it.verifyTag(Tags.VERSION).single().asPrimitive().decodeToInt()
                        .also { next() } // actually read it, so next child is serial number
                } else {
                    null
                }
            }
            val serialNumber = next().asPrimitive().decode(Asn1Element.Tag.INT) { it }
            val sigAlg = X509SignatureAlgorithmDescription.decodeFromTlv(next().asSequence())
            val issuerNames = next().asSequence().children.map {
                RelativeDistinguishedName.decodeFromTlv(it.asSet())
            }

            val timestamps = decodeTimestamps(next().asSequence())
            val subject = (next().asSequence()).children.map {
                RelativeDistinguishedName.decodeFromTlv(it.asSet())
            }

            val publicKey = next().asSequence()

            val issuerUniqueID = peek()?.let { next ->
                if (next.tag == ISSUER_UID) {
                    next()
                        .asPrimitive().let { Asn1BitString.decodeFromTlv(it, ISSUER_UID) }
                } else null
            }

            val subjectUniqueID = peek()?.let { next ->
                if (next.tag == SUBJECT_UID) {
                    next()
                        .asPrimitive().let { Asn1BitString.decodeFromTlv(it, SUBJECT_UID) }
                } else null
            }
            val extensions = if (hasNext()) {
                next().asExplicitlyTagged().verifyTag(EXTENSIONS.tagValue)
                    .single().asSequence().children.map {
                    X509CertificateExtension.decodeFromTlv(it.asSequence())
                }
            } else null

            TbsCertificate(
                raw = RawTbsCertificate(
                    version = version,
                    serialNumber = serialNumber,
                    signatureAlgorithm = sigAlg.toRawSignatureAlgorithmIdentifier(),
                    issuerName = issuerNames,
                    validFrom = timestamps.first,
                    validUntil = timestamps.second,
                    subjectName = subject,
                    subjectPublicKeyInfo = RawSubjectPublicKeyInfo.decodeFromTlv(publicKey),
                    issuerUniqueID = issuerUniqueID,
                    subjectUniqueID = subjectUniqueID,
                    extensions = extensions,
                ),
                version = version,
                serialNumber = serialNumber,
                signatureAlgorithm = sigAlg,
                issuerName = issuerNames,
                validFrom = timestamps.first,
                validUntil = timestamps.second,
                subjectName = subject,
                rawPublicKey = publicKey,
                issuerUniqueID = issuerUniqueID,
                subjectUniqueID = subjectUniqueID,
                extensions = extensions,
            )
        }

        private fun decodeTimestamps(input: Asn1Sequence): Pair<Asn1Time, Asn1Time> =
            input.decodeRethrowing {
                val firstInstant = Asn1Time.decodeFromTlv(next() as Asn1Primitive)
                val secondInstant = Asn1Time.decodeFromTlv(next() as Asn1Primitive)
                Pair(firstInstant, secondInstant)
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
    when (alg is X509SignatureAlgorithm.ECDSA) {
        true -> CryptoSignature.EC.decodeFromDer(it.asAsn1BitString().rawBytes)
        false -> CryptoSignature.RSA.decodeFromTlv(it)
    }

/**
 * Very simple implementation of an X.509 Certificate
 */
class X509Certificate internal constructor(
    override val raw: RawX509Certificate,
    val tbsCertificate: TbsCertificate,
    val signatureAlgorithm: X509SignatureAlgorithmDescription,
    val rawSignature: Asn1Primitive,
) : Asn1PemEncodable<Asn1Sequence>, Awesn1Backed<RawX509Certificate> {

    @Throws(IllegalArgumentException::class, Asn1Exception::class)
    constructor(
        tbsCertificate: TbsCertificate,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        rawSignature: Asn1Primitive,
    ) : this(
        raw = RawX509Certificate(
            tbsCertificate = tbsCertificate.raw,
            signatureAlgorithm = signatureAlgorithm.toRawSignatureAlgorithmIdentifier(),
            signatureValue = Asn1BitString.decodeFromTlv(rawSignature),
        ),
        tbsCertificate = tbsCertificate,
        signatureAlgorithm = signatureAlgorithm,
        rawSignature = rawSignature,
    )

    constructor(
        tbsCertificate: TbsCertificate,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        signature: CryptoSignature
    ) : this(tbsCertificate, signatureAlgorithm,
        signature.x509Encoded)

    override val pemLabel: String = EB_STRINGS.DEFAULT

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = raw.encodeToTlv()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X509Certificate) return false

        if (tbsCertificate != other.tbsCertificate) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (rawSignature != other.rawSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCertificate.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + rawSignature.hashCode()
        return result
    }

    /**
     * Debug String representation. Uses Base64 encoded DER representation
     */
    override fun toString(): String {
        return "X509Certificate(${encodeToDerOrNull()?.encodeToString(Base64Strict)})"
    }

    @Deprecated("Confusingly named, and lacks support for unsupported signature algorithms; use `decodedPublicKey` or `rawPublicKey`",
        level = DeprecationLevel.ERROR)
    @Suppress("DEPRECATION_ERROR")
    val publicKey: CryptoPublicKey get() = tbsCertificate.publicKey

    val rawPublicKey get() = tbsCertificate.rawPublicKey
    val decodedPublicKey get() = tbsCertificate.decodedPublicKey

    val decodedSignature by lazy { catching {
        signatureAlgorithm.requireSupported()
        CryptoSignature.Companion.fromX509Encoded(signatureAlgorithm, rawSignature)
    }}

    @Deprecated("Confusingly named, and lacks supported for unsupported signature algorithms; use `decodedSignature` or `rawSignature`",
        level = DeprecationLevel.ERROR)
    val signature: CryptoSignature get() = decodedSignature.getOrThrow()

    companion object : LabelPemDecodable<Asn1Sequence, X509Certificate>(EB_STRINGS.DEFAULT, EB_STRINGS.LEGACY) {

        private object EB_STRINGS {
            const val DEFAULT = "CERTIFICATE"
            const val LEGACY = "TRUSTED CERTIFICATE"
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509Certificate = src.decodeRethrowing {
            val tbsSequence = next().asSequence()
            val tbsRaw = RawTbsCertificate.decodeFromTlv(tbsSequence)
            val tbs = TbsCertificate(
                raw = tbsRaw,
                version = tbsRaw.version,
                serialNumber = tbsRaw.serialNumber,
                signatureAlgorithm = X509SignatureAlgorithmDescription.decodeFromTlv(tbsRaw.signatureAlgorithm.encodeToTlv()),
                issuerName = tbsRaw.issuerName,
                validFrom = tbsRaw.validFrom,
                validUntil = tbsRaw.validUntil,
                subjectName = tbsRaw.subjectName,
                rawPublicKey = tbsRaw.subjectPublicKeyInfo.encodeToTlv(),
                issuerUniqueID = tbsRaw.issuerUniqueID,
                subjectUniqueID = tbsRaw.subjectUniqueID,
                extensions = tbsRaw.extensions,
            )
            val sigAlgRaw = RawSignatureAlgorithmIdentifier.decodeFromTlv(next().asSequence())
            val sigAlg = X509SignatureAlgorithmDescription.decodeFromTlv(sigAlgRaw.encodeToTlv())
            val signature = next().asPrimitive()
            if (hasNext()) throw Asn1StructuralException("Superfluous structure in Certificate Structure")
            X509Certificate(
                raw = RawX509Certificate(
                    tbsCertificate = tbsRaw,
                    signatureAlgorithm = sigAlgRaw,
                    signatureValue = Asn1BitString.decodeFromTlv(signature),
                ),
                tbsCertificate = tbs,
                signatureAlgorithm = sigAlg,
                rawSignature = signature,
            )
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
        }.getOrNull() ?: catchingUnwrapped { X509Certificate.decodeFromPem(src.decodeToString()).getOrThrow() }.getOrNull()
    }
}

typealias CertificateChain = List<X509Certificate>

val CertificateChain.leaf: X509Certificate get() = first()
val CertificateChain.root: X509Certificate get() = last()

private
/** De-/serializes Base64 strings to/from [ByteArray] */
object Asn1BitStringSerializer : TransformingSerializerTemplate<Asn1BitString?, String>(
    parent = String.serializer(),
    encodeAs = { if (it == null) "" else byteArrayOf(it.numPaddingBits, *it.rawBytes).encodeToString(Base64Strict) },
    decodeAs = {
        if (it == "") null
        else Asn1BitString.decodeFromTlv(Asn1Primitive(Asn1Element.Tag.BIT_STRING, it.decodeToByteArray(Base64Strict)))
    }
)

private fun X509SignatureAlgorithmDescription.toRawSignatureAlgorithmIdentifier() =
    RawSignatureAlgorithmIdentifier(oid, parameters)
