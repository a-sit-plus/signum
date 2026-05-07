package at.asitplus.signum.indispensable.pki

import at.asitplus.KmmResult
import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1PrimitiveOctetString
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.PemLabelSpec
import at.asitplus.awesn1.WithPemLabel
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.encoding.decodeToAsn1Integer
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.X509Signature
import at.asitplus.signum.indispensable.X509SignatureAsn1Representation
import at.asitplus.signum.indispensable.X509SignatureAlgorithmDescription
import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findSubjectAltNames
import at.asitplus.signum.indispensable.pki.TbsCertificate.Companion.decodeFromDer
import at.asitplus.signum.internals.orLazy
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Transient
import kotlinx.serialization.builtins.serializer
import at.asitplus.awesn1.crypto.pki.X509Certificate as Awesn1X509Certificate
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

private data class TbsCertificateContent(
    val version: Int,
    val serialNumber: ByteArray,
    val signatureAlgorithm: X509SignatureAlgorithmDescription,
    val issuerName: List<RelativeDistinguishedName>,
    val validFrom: Asn1Time,
    val validUntil: Asn1Time,
    val subjectName: List<RelativeDistinguishedName>,
    val subjectPublicKeyInfo: SubjectPublicKeyInfo,
    val issuerUniqueID: Asn1BitString?,
    val subjectUniqueID: Asn1BitString?,
    val extensions: List<X509CertificateExtension>,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TbsCertificateContent) return false
        return version == other.version &&
            serialNumber.contentEquals(other.serialNumber) &&
            signatureAlgorithm == other.signatureAlgorithm &&
            issuerName == other.issuerName &&
            validFrom == other.validFrom &&
            validUntil == other.validUntil &&
            subjectName == other.subjectName &&
            subjectPublicKeyInfo == other.subjectPublicKeyInfo &&
            issuerUniqueID == other.issuerUniqueID &&
            subjectUniqueID == other.subjectUniqueID &&
            extensions == other.extensions
    }

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + serialNumber.contentHashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + issuerName.hashCode()
        result = 31 * result + validFrom.hashCode()
        result = 31 * result + validUntil.hashCode()
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + subjectPublicKeyInfo.hashCode()
        result = 31 * result + (issuerUniqueID?.hashCode() ?: 0)
        result = 31 * result + (subjectUniqueID?.hashCode() ?: 0)
        result = 31 * result + extensions.hashCode()
        return result
    }
}

private data class X509CertificateContent(
    val tbsCertificate: TbsCertificate,
    val x509Signature: X509Signature,
)

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed.
 *
 * @param version semantic certificate version; DER encodes this as version - 1.
 */
class TbsCertificate private constructor(
    providedAsn1Representation: X509TbsCertificate?,
    private val providedContent: TbsCertificateContent?,
) : DerEncodable<X509TbsCertificate> {

    @Throws(Asn1Exception::class)
    constructor(
        version: Int = 3,
        serialNumber: ByteArray,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        rawPublicKey: Asn1Sequence,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension> = emptyList(),
    ) : this(
        null,
        TbsCertificateContent(
            version = version,
            serialNumber = serialNumber,
            signatureAlgorithm = signatureAlgorithm,
            issuerName = issuerName,
            validFrom = validFrom,
            validUntil = validUntil,
            subjectName = subjectName,
            subjectPublicKeyInfo = DER.decodeFromTlv(SubjectPublicKeyInfo.serializer(), rawPublicKey),
            issuerUniqueID = issuerUniqueID,
            subjectUniqueID = subjectUniqueID,
            extensions = extensions,
        ),
    ) {
        validateExtensions(extensions)
    }

    @Throws(Asn1Exception::class)
    constructor(
        version: Int = 3,
        serialNumber: ByteArray,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension> = emptyList(),
    ) : this(
        null,
        TbsCertificateContent(
            version = version,
            serialNumber = serialNumber,
            signatureAlgorithm = signatureAlgorithm,
            issuerName = issuerName,
            validFrom = validFrom,
            validUntil = validUntil,
            subjectName = subjectName,
            subjectPublicKeyInfo = publicKey.asn1Representation,
            issuerUniqueID = issuerUniqueID,
            subjectUniqueID = subjectUniqueID,
            extensions = extensions,
        ),
    ) {
        validateExtensions(extensions)
    }

    constructor(asn1Representation: X509TbsCertificate) : this(asn1Representation, null)

    override val asn1Representation: X509TbsCertificate by providedAsn1Representation orLazy {
        X509TbsCertificate(
            version = content.version,
            serialNumber = Asn1Primitive(Asn1Element.Tag.INT, content.serialNumber).decodeToAsn1Integer(),
            signatureAlgorithm = content.signatureAlgorithm.toAlgorithmIdentifier(),
            issuerName = content.issuerName.map { it.asn1Representation },
            validFrom = content.validFrom,
            validUntil = content.validUntil,
            subjectName = content.subjectName.map { it.asn1Representation },
            subjectPublicKeyInfo = content.subjectPublicKeyInfo,
            issuerUniqueID = content.issuerUniqueID,
            subjectUniqueID = content.subjectUniqueID,
            extensions = content.extensions.map(X509CertificateExtension::toAwesn1Extension),
        )
    }

    private val content: TbsCertificateContent by providedContent orLazy {
        TbsCertificateContent(
            version = asn1Representation.version ?: 1,
            serialNumber = asn1Representation.serialNumber.encodeToTlv().content,
            signatureAlgorithm = X509SignatureAlgorithmDescription.fromAlgorithmIdentifier(asn1Representation.signatureAlgorithm),
            issuerName = asn1Representation.issuerName.map(::RelativeDistinguishedName),
            validFrom = asn1Representation.validity.validFrom,
            validUntil = asn1Representation.validity.validUntil,
            subjectName = asn1Representation.subjectName.map(::RelativeDistinguishedName),
            subjectPublicKeyInfo = asn1Representation.subjectPublicKeyInfo,
            issuerUniqueID = asn1Representation.issuerUniqueID,
            subjectUniqueID = asn1Representation.subjectUniqueID,
            extensions = asn1Representation.extensions?.map(Awesn1X509CertificateExtension::toSignumExtension).orEmpty(),
        )
    }

    val version: Int get() = content.version

    val serialNumber: ByteArray get() = content.serialNumber

    val signatureAlgorithm: X509SignatureAlgorithmDescription get() = content.signatureAlgorithm

    val issuerName: List<RelativeDistinguishedName> get() = content.issuerName

    val validFrom: Asn1Time get() = content.validFrom

    val validUntil: Asn1Time get() = content.validUntil

    val subjectName: List<RelativeDistinguishedName> get() = content.subjectName

    val subjectPublicKeyInfo: SubjectPublicKeyInfo get() = content.subjectPublicKeyInfo

    val rawPublicKey: Asn1Sequence by lazy {
        DER.encodeToTlv(SubjectPublicKeyInfo.serializer(), subjectPublicKeyInfo) as Asn1Sequence
    }

    val issuerUniqueID: Asn1BitString? get() = content.issuerUniqueID

    val subjectUniqueID: Asn1BitString? get() = content.subjectUniqueID

    val extensions: List<X509CertificateExtension> get() = content.extensions

    val decodedPublicKey: KmmResult<CryptoPublicKey> by lazy {
        catching { CryptoPublicKey.fromSubjectPublicKeyInfo(subjectPublicKeyInfo) }
    }

    @Deprecated(
        "Imprecisely named and does not support unknown algorithms; use `rawPublicKey` or `decodedPublicKey`",
        level = DeprecationLevel.ERROR,
    )
    val publicKey get() = decodedPublicKey.getOrThrow()

    /**
     * Contains `SubjectAlternativeName`s parsed from extensions. This property is initialized right away.
     */
    @Transient
    val subjectAlternativeNames: AlternativeNames? = extensions.findSubjectAltNames()

    /**
     * Contains `IssuerAlternativeName`s parsed from extensions. This property is initialized right away.
     */
    @Transient
    val issuerAlternativeNames: AlternativeNames? = extensions.findIssuerAltNames()

    private val equalitySource: Any get() = providedContent ?: asn1Representation

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TbsCertificate) return false
        return equalitySource == other.equalitySource
    }

    override fun hashCode(): Int =
        equalitySource.hashCode()

    /**
     * Debug String representation. Uses Base64 encoded DER representation
     */
    override fun toString(): String = catchingUnwrapped {
        "TbsCertificate(${encodeToDer().encodeToString(Base64Strict)})"}.getOrElse { "TbsCertificate cannot be DER-encoded. RAW representation: $content" }

    companion object : DerDecodable<X509TbsCertificate, TbsCertificate> {
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<X509TbsCertificate>,
            src: Asn1Element,
            der: Der,
        ): TbsCertificate =
            TbsCertificate(der.decodeFromTlv(serializer, src))

        @Throws(Asn1Exception::class)
        fun decodeFromTlv(src: Asn1Element): TbsCertificate =
            decodeFromTlv(X509TbsCertificate.serializer(), src, DER)

        @Throws(Asn1Exception::class)
        fun decodeFromDer(src: ByteArray): TbsCertificate =
            decodeFromTlv(Asn1Element.parse(src))

        @Throws(Asn1Exception::class)
        fun doDecode(src: Asn1Sequence): TbsCertificate =
            decodeFromTlv(src)
    }
}

/**
 * Very simple implementation of an X.509 Certificate
 */
class X509Certificate private constructor(
    providedAsn1Representation: Awesn1X509Certificate?,
    providedContent: X509CertificateContent?,
) : DerEncodable<Awesn1X509Certificate>, WithPemLabel {

    override val pemLabel: String get() = canonicalPemLabel

    @Throws(IllegalArgumentException::class)
    constructor(
        tbsCertificate: TbsCertificate,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        rawSignature: Asn1Primitive,
    ) : this(null, X509CertificateContent(tbsCertificate, X509Signature(signatureAlgorithm, rawSignature)))

    @Throws(IllegalArgumentException::class)
    constructor(
        tbsCertificate: TbsCertificate,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        signature: CryptoSignature,
    ) : this(null, X509CertificateContent(tbsCertificate, X509Signature(signatureAlgorithm, signature)))

    constructor(asn1Representation: Awesn1X509Certificate) : this(asn1Representation, null)

    override val asn1Representation: Awesn1X509Certificate by providedAsn1Representation orLazy {
        val content = requireNotNull(providedContent)
        Awesn1X509Certificate(
            tbsCertificate = content.tbsCertificate.asn1Representation,
            signatureAlgorithm = content.x509Signature.asn1Representation.algorithmIdentifier,
            signatureValue = content.x509Signature.asn1Representation.signatureValue,
        )
    }

    val tbsCertificate: TbsCertificate by providedContent?.tbsCertificate orLazy {
        TbsCertificate(asn1Representation.tbsCertificate)
    }

    val x509Signature: X509Signature by providedContent?.x509Signature orLazy {
        X509Signature(
            X509SignatureAsn1Representation(
                algorithmIdentifier = asn1Representation.signatureAlgorithm,
                signatureValue = asn1Representation.signatureValue,
            )
        )
    }

    val signatureAlgorithm: X509SignatureAlgorithmDescription get() = x509Signature.signatureAlgorithm

    val rawSignature: Asn1Primitive get() = x509Signature.rawSignature

    val rawSignatureAlgorithm: Asn1Sequence get() = x509Signature.rawSignatureAlgorithm

    // PEM disabled during awesn1 migration.

    /**
     * Debug String representation. Uses Base64 encoded DER representation
     */
    override fun toString(): String =
        "X509Certificate(${
            DER.encodeToTlv(Awesn1X509Certificate.serializer(), asn1Representation)
                .derEncoded
                .encodeToString(Base64Strict)
        })"

    @Deprecated(
        "Confusingly named, and lacks support for unsupported signature algorithms; use `decodedPublicKey` or `rawPublicKey`",
        level = DeprecationLevel.ERROR,
    )
    @Suppress("DEPRECATION_ERROR")
    val publicKey: CryptoPublicKey get() = tbsCertificate.publicKey

    val rawPublicKey get() = tbsCertificate.rawPublicKey
    val decodedPublicKey get() = tbsCertificate.decodedPublicKey

    val decodedSignature: KmmResult<CryptoSignature> get() = x509Signature.decodedSignature

    @Deprecated(
        "Confusingly named, and lacks supported for unsupported signature algorithms; use `decodedSignature` or `rawSignature`",
        level = DeprecationLevel.ERROR,
    )
    val signature: CryptoSignature get() = decodedSignature.getOrThrow()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X509Certificate) return false
        return tbsCertificate == other.tbsCertificate &&
            x509Signature == other.x509Signature
    }

    override fun hashCode(): Int {
        var result = tbsCertificate.hashCode()
        result = 31 * result + x509Signature.hashCode()
        return result
    }

    companion object : DerDecodable<Awesn1X509Certificate, X509Certificate>, PemLabelSpec<X509Certificate> {
        override val canonicalPemLabel: String = "CERTIFICATE"
        override val validPemLabels: Set<String> = setOf(canonicalPemLabel, "TRUSTED CERTIFICATE")

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<Awesn1X509Certificate>,
            src: Asn1Element,
            der: Der,
        ): X509Certificate =
            X509Certificate(der.decodeFromTlv(serializer, src))

        @Throws(Asn1Exception::class)
        fun decodeFromTlv(src: Asn1Element): X509Certificate =
            decodeFromTlv(Awesn1X509Certificate.serializer(), src, DER)

        /**
         * Tries to decode [src] into an [X509Certificate], by parsing the bytes directly as ASN.1 structure,
         * or by decoding from Base64.
         */
        fun decodeFromByteArray(src: ByteArray, der: Der=DER): X509Certificate? = catchingUnwrapped {
            X509Certificate(der.decodeFromDer<Awesn1X509Certificate>(src))
        }.getOrNull() ?: catchingUnwrapped {
            X509Certificate(der.decodeFromDer<Awesn1X509Certificate>(src.decodeToByteArray(Base64())) /*TODO PEM*/)
        }.getOrNull()
    }
}

typealias CertificateChain = List<X509Certificate>

val CertificateChain.leaf: X509Certificate get() = first()
val CertificateChain.root: X509Certificate get() = last()

private fun validateExtensions(extensions: List<X509CertificateExtension>) {
    if (extensions.distinctBy { it.oid }.size != extensions.size) {
        throw Asn1StructuralException("Multiple extensions with the same OID found")
    }
}

private fun X509CertificateExtension.toAwesn1Extension(): Awesn1X509CertificateExtension =
    Awesn1X509CertificateExtension(
        oid = oid,
        critical = critical.takeIf { it },
        value = value.asOctetString().content,
    )

private fun Awesn1X509CertificateExtension.toSignumExtension(): X509CertificateExtension =
    X509CertificateExtension(
        oid = oid,
        critical = critical ?: false,
        value = Asn1PrimitiveOctetString(value),
    )

private
/** De-/serializes Base64 strings to/from [ByteArray] */
object Asn1BitStringSerializer : TransformingSerializerTemplate<Asn1BitString?, String>(
    parent = String.serializer(),
    encodeAs = { if (it == null) "" else byteArrayOf(it.numPaddingBits, *it.rawBytes).encodeToString(Base64Strict) },
    decodeAs = {
        if (it == "") null
        else Asn1BitString.decodeFromTlv(Asn1Primitive(Asn1Element.Tag.BIT_STRING, it.decodeToByteArray(Base64Strict)))
    },
)
