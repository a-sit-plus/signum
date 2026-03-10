package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.GeneralNames
import at.asitplus.awesn1.crypto.pki.GeneralNames.Companion.findIssuerAltNames
import at.asitplus.awesn1.crypto.pki.GeneralNames.Companion.findSubjectAltNames
import at.asitplus.awesn1.crypto.pki.RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.encoding.*
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Awesn1Backed
import at.asitplus.signum.indispensable.EcdsaSignatureMappingFamily
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.LabelPemDecodable
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.key.PublicKey
import at.asitplus.signum.indispensable.requireSignatureAlgorithm
import at.asitplus.signum.indispensable.requireSupported
import at.asitplus.signum.indispensable.signatureMappingKeyOrNull
import at.asitplus.signum.indispensable.signature.Signature
import at.asitplus.signum.indispensable.toSignatureAlgorithmIdentifier
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Transient
import kotlinx.serialization.builtins.serializer
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo as RawSubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.pki.TbsCertificate as RawTbsCertificate
import at.asitplus.awesn1.crypto.pki.X509Certificate as RawX509Certificate

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed
 */
@Deprecated(
    "Renamed to CertificateInfo.",
    ReplaceWith("CertificateInfo", "at.asitplus.signum.indispensable.pki.CertificateInfo")
)
typealias TbsCertificate = CertificateInfo

class CertificateInfo(
    override val raw: RawTbsCertificate,
) : Asn1Encodable<Asn1Sequence>, Awesn1Backed<RawTbsCertificate> {

    @Throws(Asn1Exception::class)
    constructor(
        version: Int? = 2,
        serialNumber: ByteArray,
        signatureAlgorithm: SignatureAlgorithmIdentifier,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        subjectPublicKeyInfo: RawSubjectPublicKeyInfo,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        raw = RawTbsCertificate(
            version = version,
            serialNumber = serialNumber,
            signatureAlgorithm = signatureAlgorithm,
            issuerName = issuerName,
            validFrom = validFrom,
            validUntil = validUntil,
            subjectName = subjectName,
            subjectPublicKeyInfo = subjectPublicKeyInfo,
            issuerUniqueID = issuerUniqueID,
            subjectUniqueID = subjectUniqueID,
            extensions = extensions,
        )
    )

    @Deprecated(
        "Pass awesn1 SubjectPublicKeyInfo or Signum PublicKey instead.",
        ReplaceWith(
            "CertificateInfo(version, serialNumber, signatureAlgorithm, issuerName, validFrom, validUntil, subjectName, SubjectPublicKeyInfo.decodeFromTlv(rawPublicKey), issuerUniqueID, subjectUniqueID, extensions)",
            "at.asitplus.awesn1.crypto.SubjectPublicKeyInfo"
        )
    )
    @Throws(Asn1Exception::class)
    constructor(
        version: Int? = 2,
        serialNumber: ByteArray,
        signatureAlgorithm: SignatureAlgorithmIdentifier,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        rawPublicKey: Asn1Sequence,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        version = version,
        serialNumber = serialNumber,
        signatureAlgorithm = signatureAlgorithm,
        issuerName = issuerName,
        validFrom = validFrom,
        validUntil = validUntil,
        subjectName = subjectName,
        subjectPublicKeyInfo = RawSubjectPublicKeyInfo.decodeFromTlv(rawPublicKey),
        issuerUniqueID = issuerUniqueID,
        subjectUniqueID = subjectUniqueID,
            extensions = extensions,
        )

    @Throws(Asn1Exception::class)
    constructor(
        version: Int? = 2,
        serialNumber: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        subjectPublicKeyInfo: RawSubjectPublicKeyInfo,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        version = version,
        serialNumber = serialNumber,
        signatureAlgorithm = signatureAlgorithm.toSignatureAlgorithmIdentifier().getOrThrow(),
        issuerName = issuerName,
        validFrom = validFrom,
        validUntil = validUntil,
        subjectName = subjectName,
        subjectPublicKeyInfo = subjectPublicKeyInfo,
        issuerUniqueID = issuerUniqueID,
        subjectUniqueID = subjectUniqueID,
        extensions = extensions,
    )

    @Deprecated(
        "Pass SignatureAlgorithmIdentifier directly.",
        ReplaceWith("CertificateInfo(version, serialNumber, signatureAlgorithm.raw, issuerName, validFrom, validUntil, subjectName, subjectPublicKeyInfo, issuerUniqueID, subjectUniqueID, extensions)")
    )
    constructor(
        version: Int? = 2,
        serialNumber: ByteArray,
        signatureAlgorithm: X509SignatureAlgorithm,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        subjectPublicKeyInfo: RawSubjectPublicKeyInfo,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        version = version,
        serialNumber = serialNumber,
        signatureAlgorithm = signatureAlgorithm.raw,
        issuerName = issuerName,
        validFrom = validFrom,
        validUntil = validUntil,
        subjectName = subjectName,
        subjectPublicKeyInfo = subjectPublicKeyInfo,
        issuerUniqueID = issuerUniqueID,
        subjectUniqueID = subjectUniqueID,
        extensions = extensions,
    )

    @Deprecated(
        "Pass SignatureAlgorithmIdentifier directly.",
        ReplaceWith("CertificateInfo(version, serialNumber, signatureAlgorithm.raw, issuerName, validFrom, validUntil, subjectName, publicKey, issuerUniqueID, subjectUniqueID, extensions)")
    )
    constructor(
        version: Int? = 2,
        serialNumber: ByteArray,
        signatureAlgorithm: X509SignatureAlgorithm,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        publicKey: PublicKey,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        version = version,
        serialNumber = serialNumber,
        signatureAlgorithm = signatureAlgorithm.raw,
        issuerName = issuerName,
        validFrom = validFrom,
        validUntil = validUntil,
        subjectName = subjectName,
        publicKey = publicKey,
        issuerUniqueID = issuerUniqueID,
        subjectUniqueID = subjectUniqueID,
        extensions = extensions,
    )

    constructor(
        version: Int? = 2,
        serialNumber: ByteArray,
        signatureAlgorithm: SignatureAlgorithmIdentifier,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        publicKey: PublicKey,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        version, serialNumber, signatureAlgorithm, issuerName, validFrom, validUntil, subjectName,
        publicKey.raw, issuerUniqueID, subjectUniqueID, extensions
    )

    @Throws(Asn1Exception::class)
    constructor(
        version: Int? = 2,
        serialNumber: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        publicKey: PublicKey,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        version = version,
        serialNumber = serialNumber,
        signatureAlgorithm = signatureAlgorithm.toSignatureAlgorithmIdentifier().getOrThrow(),
        issuerName = issuerName,
        validFrom = validFrom,
        validUntil = validUntil,
        subjectName = subjectName,
        publicKey = publicKey,
        issuerUniqueID = issuerUniqueID,
        subjectUniqueID = subjectUniqueID,
        extensions = extensions,
    )


    val version: Int? get() = raw.version
    val serialNumber: ByteArray get() = raw.serialNumber
    val signatureAlgorithm: SignatureAlgorithmIdentifier get() = raw.signatureAlgorithm
    val issuerName: List<RelativeDistinguishedName> get() = raw.issuerName
    val validFrom: Asn1Time get() = raw.validFrom
    val validUntil: Asn1Time get() = raw.validUntil
    val subjectName: List<RelativeDistinguishedName> get() = raw.subjectName
    val rawPublicKey: RawSubjectPublicKeyInfo get() = raw.subjectPublicKeyInfo
    val issuerUniqueID: Asn1BitString? get() = raw.issuerUniqueID
    val subjectUniqueID: Asn1BitString? get() = raw.subjectUniqueID
    val extensions: List<X509CertificateExtension>? get() = raw.extensions

    init {
        if (extensions?.distinctBy { it.oid }?.size != extensions?.size) throw Asn1StructuralException("Multiple extensions with the same OID found")
    }

    val decodedPublicKey by lazy {
        catching {
            PublicKey.fromRaw(rawPublicKey)
        }
    }

    @Deprecated(
        "Imprecisely named and does not support unknown algorithms; use `rawPublicKey` or `decodedPublicKey`",
        level = DeprecationLevel.ERROR
    )
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

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = raw.encodeToTlv()

    override fun equals(other: Any?) = other is CertificateInfo && raw == other.raw

    override fun hashCode(): Int = raw.hashCode()

    /**
     * Debug String representation. Uses Base64 encoded DER representation
     */
    override fun toString(): String {
        return "TbsCertificate(${encodeToDerOrNull()?.let { it.encodeToString(Base64Strict) }})"
    }

    companion object : Asn1Decodable<Asn1Sequence, CertificateInfo> {
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): CertificateInfo {
            val raw = RawTbsCertificate.decodeFromTlv(src)
            return CertificateInfo(raw = raw)
        }
    }
}

/**
 * Signature encoded as per X.509:
 * - RSA remains a bit string
 * - EC is DER-encoded then wrapped in a bit string
 */
val Signature.x509SignatureValue: Asn1BitString
    get() = when (this) {
        is Signature.EC -> Asn1BitString(encodeToDer())
        is Signature.RSA -> raw.bitString
    }

@Deprecated(
    "Use x509SignatureValue.",
    ReplaceWith("x509SignatureValue")
)
val Signature.x509Encoded: Asn1Primitive
    get() = x509SignatureValue.encodeToTlv()

/**
 * Decode a X.509-encoded signature
 * - RSA is encoded as a bit string
 * - EC is DER-encoded then wrapped in a bit string
 */
fun Signature.Companion.fromX509Encoded(alg: SignatureAlgorithmIdentifier, it: Asn1BitString) =
    when (alg.requireSignatureAlgorithm().signatureMappingKeyOrNull()?.family == EcdsaSignatureMappingFamily) {
        true -> Signature.EC.decodeFromDer(it.rawBytes)
        false -> Signature.RSA(it.rawBytes)
    }

@Deprecated(
    "Pass the decoded X.509 signature bit string instead.",
    ReplaceWith("fromX509Encoded(alg, Asn1BitString.decodeFromTlv(it))", "at.asitplus.awesn1.Asn1BitString")
)
fun Signature.Companion.fromX509Encoded(alg: SignatureAlgorithmIdentifier, it: Asn1Primitive) =
    fromX509Encoded(alg, it.asAsn1BitString())

/**
 * Very simple implementation of an X.509 Certificate
 */
@Deprecated(
    "Renamed to Certificate.",
    ReplaceWith("Certificate", "at.asitplus.signum.indispensable.pki.Certificate")
)
typealias X509Certificate = Certificate

class Certificate(
    override val raw: RawX509Certificate,
) : Asn1PemEncodable<Asn1Sequence>, Awesn1Backed<RawX509Certificate> {
    val tbsCertificate: CertificateInfo by lazy { CertificateInfo(raw.tbsCertificate) }
    val signatureAlgorithm: SignatureAlgorithmIdentifier get() = raw.signatureAlgorithm
    val rawSignatureValue: Asn1BitString get() = raw.signatureValue

    @Deprecated(
        "Use rawSignatureValue.",
        ReplaceWith("rawSignatureValue")
    )
    val rawSignature: Asn1Primitive get() = rawSignatureValue.encodeToTlv()

    @Throws(IllegalArgumentException::class, Asn1Exception::class)
    constructor(
        tbsCertificate: CertificateInfo,
        signatureAlgorithm: SignatureAlgorithmIdentifier,
        rawSignatureValue: Asn1BitString,
    ) : this(
        raw = RawX509Certificate(
            tbsCertificate = tbsCertificate.raw,
            signatureAlgorithm = signatureAlgorithm,
            signatureValue = rawSignatureValue,
        ),
    )

    @Deprecated(
        "Pass an awesn1 Asn1BitString or a Signum Signature instead.",
        ReplaceWith(
            "Certificate(tbsCertificate, signatureAlgorithm, Asn1BitString.decodeFromTlv(rawSignature))",
            "at.asitplus.awesn1.Asn1BitString"
        )
    )
    constructor(
        tbsCertificate: CertificateInfo,
        signatureAlgorithm: SignatureAlgorithmIdentifier,
        rawSignature: Asn1Primitive,
    ) : this(
        tbsCertificate,
        signatureAlgorithm,
        Asn1BitString.decodeFromTlv(rawSignature),
    )

    constructor(
        tbsCertificate: CertificateInfo,
        signatureAlgorithm: SignatureAlgorithmIdentifier,
        signature: Signature
    ) : this(
        tbsCertificate, signatureAlgorithm,
        signature.x509SignatureValue
    )

    @Throws(Asn1Exception::class)
    constructor(
        tbsCertificate: CertificateInfo,
        signatureAlgorithm: SignatureAlgorithm,
        rawSignatureValue: Asn1BitString,
    ) : this(
        tbsCertificate = tbsCertificate,
        signatureAlgorithm = signatureAlgorithm.toSignatureAlgorithmIdentifier().getOrThrow(),
        rawSignatureValue = rawSignatureValue,
    )

    @Throws(Asn1Exception::class)
    constructor(
        tbsCertificate: CertificateInfo,
        signatureAlgorithm: SignatureAlgorithm,
        signature: Signature,
    ) : this(
        tbsCertificate = tbsCertificate,
        signatureAlgorithm = signatureAlgorithm.toSignatureAlgorithmIdentifier().getOrThrow(),
        signature = signature,
    )

    @Deprecated(
        "Pass SignatureAlgorithmIdentifier directly.",
        ReplaceWith("Certificate(tbsCertificate, signatureAlgorithm.raw, rawSignatureValue)")
    )
    constructor(
        tbsCertificate: CertificateInfo,
        signatureAlgorithm: X509SignatureAlgorithm,
        rawSignatureValue: Asn1BitString,
    ) : this(
        tbsCertificate = tbsCertificate,
        signatureAlgorithm = signatureAlgorithm.raw,
        rawSignatureValue = rawSignatureValue,
    )

    @Deprecated(
        "Pass SignatureAlgorithmIdentifier directly.",
        ReplaceWith("Certificate(tbsCertificate, signatureAlgorithm.raw, rawSignature)")
    )
    constructor(
        tbsCertificate: CertificateInfo,
        signatureAlgorithm: X509SignatureAlgorithm,
        rawSignature: Asn1Primitive,
    ) : this(
        tbsCertificate = tbsCertificate,
        signatureAlgorithm = signatureAlgorithm.raw,
        rawSignature = rawSignature,
    )

    @Deprecated(
        "Pass SignatureAlgorithmIdentifier directly.",
        ReplaceWith("Certificate(tbsCertificate, signatureAlgorithm.raw, signature)")
    )
    constructor(
        tbsCertificate: CertificateInfo,
        signatureAlgorithm: X509SignatureAlgorithm,
        signature: Signature,
    ) : this(
        tbsCertificate = tbsCertificate,
        signatureAlgorithm = signatureAlgorithm.raw,
        signature = signature,
    )

    override val pemLabel: String = EB_STRINGS.DEFAULT

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = raw.encodeToTlv()

    override fun equals(other: Any?) = other is Certificate && raw == other.raw

    override fun hashCode(): Int = raw.hashCode()

    /**
     * Debug String representation. Uses Base64 encoded DER representation
     */
    override fun toString(): String {
        return "Certificate(${encodeToDerOrNull()?.encodeToString(Base64Strict)})"
    }

    @Deprecated(
        "Confusingly named, and lacks support for unsupported signature algorithms; use `decodedPublicKey` or `rawPublicKey`",
        level = DeprecationLevel.ERROR
    )
    @Suppress("DEPRECATION_ERROR")
    val publicKey: PublicKey get() = tbsCertificate.publicKey

    val rawPublicKey get() = tbsCertificate.rawPublicKey
    val decodedPublicKey get() = tbsCertificate.decodedPublicKey

    val decodedSignature: at.asitplus.KmmResult<Signature> by lazy {
        catching {
            Signature.fromX509Encoded(signatureAlgorithm, rawSignatureValue)
        }
    }

    @Deprecated(
        "Confusingly named, and lacks supported for unsupported signature algorithms; use `decodedSignature` or `rawSignature`",
        level = DeprecationLevel.ERROR
    )
    val signature: Signature get() = decodedSignature.getOrThrow()

    companion object : LabelPemDecodable<Asn1Sequence, Certificate>(EB_STRINGS.DEFAULT, EB_STRINGS.LEGACY) {

        private object EB_STRINGS {
            const val DEFAULT = "CERTIFICATE"
            const val LEGACY = "TRUSTED CERTIFICATE"
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): Certificate {
            return Certificate(RawX509Certificate.decodeFromTlv(src))
        }

        /**
         * Tries to decode [src] into an [Certificate], by parsing the bytes directly as ASN.1 structure,
         * or by decoding from Base64, or by decoding to a String, stripping PEM headers
         * (`-----BEGIN CERTIFICATE-----`) and then decoding from Base64.
         */
        fun decodeFromByteArray(src: ByteArray): Certificate? = catchingUnwrapped {
            Certificate(RawX509Certificate.decodeFromDer(src))
        }.getOrNull() ?: catchingUnwrapped {
            Certificate(RawX509Certificate.decodeFromDer(src.decodeToByteArray(Base64())))
        }.getOrNull() ?: catchingUnwrapped {
            Certificate.decodeFromPem(src.decodeToString()).getOrThrow()
        }.getOrNull()
    }
}

typealias CertificateChain = List<Certificate>

val CertificateChain.leaf: Certificate get() = first()
val CertificateChain.root: Certificate get() = last()

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
