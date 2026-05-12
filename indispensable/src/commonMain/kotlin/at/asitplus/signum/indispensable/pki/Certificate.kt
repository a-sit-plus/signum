package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.encoding.decodeToAsn1Integer
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findSubjectAltNames
import at.asitplus.signum.internals.orLazy
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Transient
import kotlinx.serialization.builtins.serializer
import kotlin.time.Instant
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

private data class TbsCertificateContent(
    val serialNumber: ByteArray,
    val signatureAlgorithm: SignatureAlgorithm,
    val issuerName: List<RelativeDistinguishedName>,
    val validFrom: Instant,
    val validUntil: Instant,
    val subjectName: List<RelativeDistinguishedName>,
    val publicKey: CryptoPublicKey,
    val issuerUniqueID: ByteArray?,
    val subjectUniqueID: ByteArray?,
    val extensions: List<CertificateExtension>,
) {

    constructor(asn1Representation: X509TbsCertificate) : this(
        serialNumber = asn1Representation.serialNumber.encodeToTlv().content,
        signatureAlgorithm = SignatureAlgorithm(asn1Representation.signatureAlgorithm),
        issuerName = asn1Representation.issuerName.map(::RelativeDistinguishedName),
        validFrom = asn1Representation.validity.validFrom.instant,
        validUntil = asn1Representation.validity.validUntil.instant,
        subjectName = asn1Representation.subjectName.map(::RelativeDistinguishedName),
        publicKey = CryptoPublicKey(asn1Representation.subjectPublicKeyInfo),
        issuerUniqueID = asn1Representation.issuerUniqueID?.toBitSet()?.toByteArray(),
        subjectUniqueID = asn1Representation.subjectUniqueID?.toBitSet()?.toByteArray(),
        extensions = asn1Representation.extensions?.map(Awesn1X509CertificateExtension::toSignumExtension)
            .orEmpty(),
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TbsCertificateContent) return false
        return serialNumber.contentEquals(other.serialNumber) &&
                signatureAlgorithm == other.signatureAlgorithm &&
                issuerName == other.issuerName &&
                validFrom == other.validFrom &&
                validUntil == other.validUntil &&
                subjectName == other.subjectName &&
                publicKey == other.publicKey &&
                issuerUniqueID.contentEquals(other.issuerUniqueID) &&
                subjectUniqueID.contentEquals(other.subjectUniqueID) &&
                extensions == other.extensions
    }

    override fun hashCode(): Int {
        var result = serialNumber.contentHashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + issuerName.hashCode()
        result = 31 * result + validFrom.hashCode()
        result = 31 * result + validUntil.hashCode()
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + (issuerUniqueID?.contentHashCode() ?: 0)
        result = 31 * result + (subjectUniqueID?.contentHashCode() ?: 0)
        result = 31 * result + extensions.hashCode()
        return result
    }
}

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed.
 *
 * @param version semantic certificate version; DER encodes this as version - 1.
 */
class TbsCertificate private constructor(
    providedContent: TbsCertificateContent?, /*TODO EXTENSIBILITY private val*/
    private val providedAsn1Representation: X509TbsCertificate?, /*TODO EXTENSIBILITY THIS SHOULD NOT BE A VAL but we need it for temp PFUSCH equals*/
) : DerEncodable<X509TbsCertificate> {


    @Throws(Asn1Exception::class)
    constructor(
        serialNumber: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Instant,
        validUntil: Instant,
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        issuerUniqueID: ByteArray? = null,
        subjectUniqueID: ByteArray? = null,
        extensions: List<CertificateExtension> = emptyList(),
    ) : this(
        TbsCertificateContent(
            serialNumber = serialNumber,
            signatureAlgorithm = signatureAlgorithm,
            issuerName = issuerName,
            validFrom = validFrom,
            validUntil = validUntil,
            subjectName = subjectName,
            publicKey = publicKey,
            issuerUniqueID = issuerUniqueID,
            subjectUniqueID = subjectUniqueID,
            extensions = extensions,
        ), null
    ) {
        validateExtensions(extensions)
    }

    constructor(asn1Representation: X509TbsCertificate) : this(
        null /*TODO EXTENSIBILITY TbsCertificateContent(asn1Representation)*/,
        asn1Representation
    )

    override val asn1Representation: X509TbsCertificate by providedAsn1Representation orLazy {
        requireNotNull(providedContent)
        X509TbsCertificate(
            version = 3,
            serialNumber = Asn1Primitive(Asn1Element.Tag.INT, providedContent.serialNumber).decodeToAsn1Integer(),
            signatureAlgorithm = providedContent.signatureAlgorithm.asn1Representation,
            issuerName = providedContent.issuerName.map { it.asn1Representation },
            validFrom = Asn1Time(providedContent.validFrom),
            validUntil = Asn1Time(providedContent.validUntil),
            subjectName = providedContent.subjectName.map { it.asn1Representation },
            subjectPublicKeyInfo = providedContent.publicKey.asn1Representation,
            issuerUniqueID = providedContent.issuerUniqueID?.let { Asn1BitString(BitSet(it)) },
            subjectUniqueID = providedContent.subjectUniqueID?.let { Asn1BitString(BitSet(it)) },
            extensions = providedContent.extensions.map(CertificateExtension::toAwesn1Extension),
        )
    }
    /*TODO EXTENSIBILITY delete, cuz replaced with private val in ctor*/
    private val providedContent: TbsCertificateContent by providedContent orLazy {
        TbsCertificateContent(asn1Representation)
    }

    val serialNumber: ByteArray get() = providedContent.serialNumber

    val signatureAlgorithm: SignatureAlgorithm get() = providedContent.signatureAlgorithm

    val issuerName: List<RelativeDistinguishedName> get() = providedContent.issuerName

    val validFrom: Instant get() = providedContent.validFrom

    val validUntil: Instant get() = providedContent.validUntil

    val subjectName: List<RelativeDistinguishedName> get() = providedContent.subjectName

    val issuerUniqueID: ByteArray? get() = providedContent.issuerUniqueID

    val subjectUniqueID: ByteArray? get() = providedContent.subjectUniqueID

    val extensions: List<CertificateExtension> get() = providedContent.extensions

    val publicKey get() = providedContent.publicKey

    /**
     * Contains `SubjectAlternativeName`s parsed from extensions.
     */
    @Transient
    val subjectAlternativeNames: AlternativeNames? by lazy { extensions.findSubjectAltNames() }

    /**
     * Contains `IssuerAlternativeName`s parsed from extensions.
     */
    @Transient
    val issuerAlternativeNames: AlternativeNames? by lazy { extensions.findIssuerAltNames() }

    /*TODO EXTENSIBILITY temp PFUSCH good enough for regression tests*/
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TbsCertificate) return false
        return contentEquals(other)
    }

    /*TODO EXTENSIBILITY temp PFUSCH good enough for regression tests*/
    override fun hashCode(): Int =
        runCatching { providedContent.hashCode() }.getOrElse { 0 }

    /*TODO EXTENSIBILITY temp PFUSCH good enough for regression tests*/
    private fun contentEquals(other: TbsCertificate): Boolean {
        val thisIsAsn1Backed = providedAsn1Representation != null
        val otherIsAsn1Backed = other.providedAsn1Representation != null

        if (thisIsAsn1Backed && otherIsAsn1Backed) {
            return asn1Representation == other.asn1Representation
        }

        if (!thisIsAsn1Backed && !otherIsAsn1Backed) {
            return providedContent == other.providedContent
        }

        if (asn1Representation == other.asn1Representation) return true

        return catchingUnwrapped {
            providedContent == other.providedContent
        }.getOrDefault(false)
    }

    /**
     * Debug String representation. Uses Base64 encoded DER representation
     */
    /*TODO EXTENSIBILITY temp PFUSCH good enough for regression tests*/
    override fun toString(): String = catchingUnwrapped {
        "TbsCertificate(${encodeToDer().encodeToString(Base64Strict)})"
    }.getOrElse { "TbsCertificate cannot be DER-encoded. RAW representation: $providedContent" }

    companion object : DerDecodable<X509TbsCertificate, TbsCertificate> {
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<X509TbsCertificate>,
            src: Asn1Element,
            der: Der,
        ): TbsCertificate =
            TbsCertificate(der.decodeFromTlv(serializer, src))
    }
}

/**
 * Very simple implementation of an X.509 Certificate
 */
class Certificate private constructor(
    private val providedAsn1Representation: X509Certificate?,
    providedContent: TbsCertificate?,
    providedSignature: CryptoSignature?
) : DerPemEncodable<X509Certificate> {

    override val pemLabel: String get() = canonicalPemLabel

    @Throws(IllegalArgumentException::class)
    constructor(
        tbsCertificate: TbsCertificate,
        signature: CryptoSignature,
    ) : this(null, tbsCertificate, signature)

    constructor(asn1Representation: X509Certificate) : this(
        asn1Representation.also {
            require(it.signatureAlgorithm == it.tbsCertificate.signatureAlgorithm) { "Inner TBS certificate signature algorithm ${it.tbsCertificate.signatureAlgorithm} != certificate outer signature algorithm ${it.signatureAlgorithm}, that earns the whole certificate with serial ${it.tbsCertificate.serialNumber} a spot on my naughty list!" }
        },
        null,
        null
    )

    override val asn1Representation: X509Certificate by providedAsn1Representation orLazy {
        requireNotNull(providedContent)
        X509Certificate(
            tbsCertificate = providedContent.asn1Representation,
            signatureAlgorithm = providedContent.signatureAlgorithm.asn1Representation,
            signatureValue = signature.asn1Representation
        )
    }

    val signature: CryptoSignature by providedSignature orLazy {
        CryptoSignature(asn1Representation.signatureAlgorithm.oid, asn1Representation.signatureValue)
    }

    val tbsCertificate: TbsCertificate by providedContent orLazy {
        TbsCertificate(asn1Representation.tbsCertificate)
    }


    /**
     * convenience getter for the contained [TbsCertificate.publicKey]
     */
    val publicKey: CryptoPublicKey get() = tbsCertificate.publicKey

    val signatureAlgorithm: SignatureAlgorithm get() = tbsCertificate.signatureAlgorithm

    /**
     * Debug String representation. Uses Base64 encoded DER representation
     */
    override fun toString(): String =
        "X509Certificate(${
            DER.encodeToTlv(X509Certificate.serializer(), asn1Representation)
                .derEncoded
                .encodeToString(Base64Strict)
        })"


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Certificate) return false
        return tbsCertificate == other.tbsCertificate &&
                signatureEquals(other)
    }

    override fun hashCode(): Int {
        var result = tbsCertificate.hashCode()
        result = 31 * result + runCatching { signature.hashCode() }.getOrElse { 0 }
        return result
    }

    private fun signatureEquals(other: Certificate): Boolean {
        val thisIsAsn1Backed = providedAsn1Representation != null
        val otherIsAsn1Backed = other.providedAsn1Representation != null

        if (thisIsAsn1Backed && otherIsAsn1Backed) {
            return asn1Representation.signatureValue == other.asn1Representation.signatureValue
        }

        if (!thisIsAsn1Backed && !otherIsAsn1Backed) {
            return signature == other.signature
        }

        if (asn1Representation.signatureValue == other.asn1Representation.signatureValue) return true

        return catchingUnwrapped {
            signature == other.signature
        }.getOrDefault(false)
    }

    companion object : DerPemDecodable<X509Certificate, Certificate> {
        override val canonicalPemLabel: String get() = X509Certificate.canonicalPemLabel
        override val validPemLabels: Set<String> get() = X509Certificate.validPemLabels

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<X509Certificate>,
            src: Asn1Element,
            der: Der,
        ): Certificate =
            Certificate(der.decodeFromTlv(serializer, src))

        @Throws(Asn1Exception::class)
        fun decodeFromTlv(src: Asn1Element): Certificate =
            decodeFromTlv(X509Certificate.serializer(), src, DER)

        /**
         * Tries to decode [src] into an [Certificate], by parsing the bytes directly as ASN.1 structure,
         * or by decoding from Base64.
         */
        fun decodeFromByteArray(src: ByteArray, der: Der = DER): Certificate? = catchingUnwrapped {
            Certificate(der.decodeFromDer<X509Certificate>(src))
        }.getOrNull() ?: catchingUnwrapped {
            Certificate(der.decodeFromDer<X509Certificate>(src.decodeToByteArray(Base64())))
        }.getOrNull() ?: Certificate.decodeFromPem(src.decodeToString(), der)
    }
}

typealias CertificateChain = List<Certificate>

val CertificateChain.leaf: Certificate get() = first()
val CertificateChain.root: Certificate get() = last()

private fun validateExtensions(extensions: List<CertificateExtension>) {
    if (extensions.distinctBy { it.oid }.size != extensions.size) {
        throw Asn1StructuralException("Multiple extensions with the same OID found")
    }
}

private fun CertificateExtension.toAwesn1Extension(): Awesn1X509CertificateExtension =
    Awesn1X509CertificateExtension(
        oid = oid,
        critical = critical.takeIf { it },
        value = value.asOctetString().content,
    )

private fun Awesn1X509CertificateExtension.toSignumExtension(): CertificateExtension =
    CertificateExtension(
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
