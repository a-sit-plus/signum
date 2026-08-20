package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findSubjectAltNames
import at.asitplus.signum.internals.orLazy
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Transient
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed.
 *
 * @param version semantic certificate version; DER encodes this as version - 1.
 */
class TbsCertificate private constructor(
    providedContent: ContentContainer?, /*TODO EXTENSIBILITY private val*/
    private val providedAsn1Representation: X509TbsCertificate?, /*TODO EXTENSIBILITY THIS SHOULD NOT BE A VAL but we need it for temp PFUSCH equals*/
) : DerEncodable<X509TbsCertificate> {



    private data class ContentContainer(
        val serialNumber: Asn1Integer,
        val signatureAlgorithm: SignatureAlgorithm,
        val issuerName: Name,
        val validFrom: Instant,
        val validUntil: Instant,
        val subjectName: Name,
        val publicKey: CryptoPublicKey,
        val issuerUniqueID: ByteArray?,
        val subjectUniqueID: ByteArray?,
        val extensions: List<CertificateExtension>,
    ) {

        constructor(asn1Representation: X509TbsCertificate) : this(
            serialNumber = asn1Representation.serialNumber,
            signatureAlgorithm = SignatureAlgorithm(asn1Representation.signatureAlgorithm),
            issuerName = X500Name(asn1Representation.issuerName.map(::RelativeDistinguishedName), false),
            validFrom = asn1Representation.validity.validFrom.instant,
            validUntil = asn1Representation.validity.validUntil.instant,
            subjectName = X500Name(asn1Representation.subjectName.map(::RelativeDistinguishedName), false),
            publicKey = CryptoPublicKey(asn1Representation.subjectPublicKeyInfo),
            issuerUniqueID = asn1Representation.issuerUniqueID?.toBitSet()?.toByteArray(),
            subjectUniqueID = asn1Representation.subjectUniqueID?.toBitSet()?.toByteArray(),
            extensions = asn1Representation.extensions?.map { CertificateExtension(it) }.orEmpty(),
        )

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ContentContainer) return false
            return serialNumber == other.serialNumber &&
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
            var result = serialNumber.hashCode()
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


    @Throws(Asn1Exception::class)
    constructor(
        serialNumber: Asn1Integer.Positive,
        signatureAlgorithm: SignatureAlgorithm,
        issuerName: Name,
        validFrom: Instant,
        validUntil: Instant,
        subjectName: Name,
        publicKey: CryptoPublicKey,
        issuerUniqueID: ByteArray? = null,
        subjectUniqueID: ByteArray? = null,
        extensions: List<CertificateExtension> = emptyList(),
    ) : this(
        ContentContainer(
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
        serialNumber.encodeToAsn1ContentBytes().size.let { size ->
            runRethrowing { require(size <= 20) { "Serial Number too long for X.509. Limit = 20 value octets, is: $size" } }
        }
        runRethrowing { require(!serialNumber.isZero()) { "Serial Number must not be zero" } }
        validateExtensions(extensions)
    }

    constructor(asn1Representation: X509TbsCertificate) : this(
        null /*TODO EXTENSIBILITY TbsCertificateContent(asn1Representation)*/,
        asn1Representation
    )

    override val asn1Representation: X509TbsCertificate by providedAsn1Representation orLazy {
        requireNotNull(providedContent)
        X509TbsCertificate(
            serialNumber = providedContent.serialNumber,
            signatureAlgorithm = providedContent.signatureAlgorithm.asn1Representation,
            issuerName = providedContent.issuerName.requireX509().asn1Representation,
            validFrom = Asn1Time.SecondsCapped(providedContent.validFrom),
            validUntil = Asn1Time.SecondsCapped(providedContent.validUntil),
            subjectName = providedContent.subjectName.requireX509().asn1Representation,
            subjectPublicKeyInfo = providedContent.publicKey.asn1Representation,
            issuerUniqueID = providedContent.issuerUniqueID?.let { Asn1BitString(BitSet(it)) },
            subjectUniqueID = providedContent.subjectUniqueID?.let { Asn1BitString(BitSet(it)) },
            extensions = providedContent.extensions.map { it.requireX509().asn1Representation },
        )
    }

    /*TODO EXTENSIBILITY delete, cuz replaced with private val in ctor*/
    private val providedContent: ContentContainer by providedContent orLazy {
        ContentContainer(asn1Representation)
    }

    val serialNumber: Asn1Integer get() = providedContent.serialNumber

    val signatureAlgorithm: SignatureAlgorithm get() = providedContent.signatureAlgorithm

    val issuerName: Name get() = providedContent.issuerName

    val validFrom: Instant get() = providedContent.validFrom

    val validUntil: Instant get() = providedContent.validUntil

    val subjectName: Name get() = providedContent.subjectName

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
            element: X509TbsCertificate,
            der: Der,
        ): TbsCertificate =
            TbsCertificate(element)
    }
}

/**
 * Very simple implementation of an X.509 Certificate
 */
class Certificate private constructor(
    private val providedAsn1Representation: X509Certificate?, /*TODO EXTENSIBILITY THIS SHOULD NOT BE A VAL but we need it for temp PFUSCH equals*/
    providedContent: TbsCertificate?, /*TODO EXTENSIBILITY private val*/
    providedSignature: CryptoSignature? /*TODO EXTENSIBILITY private val*/
) : DerPemEncodable<X509Certificate> {

    override val pemLabel: String get() = canonicalPemLabel

    @Throws(IllegalArgumentException::class)
    constructor(
        tbsCertificate: TbsCertificate,
        signature: CryptoSignature,
    ) : this(null, tbsCertificate, signature)

    constructor(asn1Representation: X509Certificate) : this(
        asn1Representation.also {
            require(it.signatureAlgorithm == it.tbsCertificate.signatureAlgorithm) {
                "Inner TBS certificate signature algorithm ${it.tbsCertificate.signatureAlgorithm} != certificate outer " +
                        "signature algorithm ${it.signatureAlgorithm}, that earns the whole certificate with serial " +
                        "${it.tbsCertificate.serialNumber} a spot on my naughty list!" }
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
        CryptoSignature(asn1Representation.signatureAlgorithm, asn1Representation.signatureValue)
    }

    /*TODO EXTENSIBILITY delete, cuz replaced with private val in ctor*/
    val tbsCertificate: TbsCertificate by providedContent orLazy {
        TbsCertificate(asn1Representation.tbsCertificate)
    }


    /**
     * convenience getter for the contained [TbsCertificate.publicKey]
     */
    val publicKey: CryptoPublicKey get() = tbsCertificate.publicKey

    val signatureAlgorithm: SignatureAlgorithm get() = tbsCertificate.signatureAlgorithm

    /** OIDs of all extensions marked critical. */
    val criticalExtensionOids: Set<ObjectIdentifier>
        get() = tbsCertificate.extensions.filter { it.critical }.map { it.oid }.toSet()

    /**
     * A certificate is self-issued if subject and issuer are the same (not the same as self-signed).
     */
    val isSelfIssued: Boolean
        get() = tbsCertificate.subjectName == tbsCertificate.issuerName


    init {
        require(tbsCertificate.extensions.allDistinctByOids()) { "Multiple extensions with the same OID found" }
    }

    /** Whether this certificate is expired at [date].
     *
     * RFC 5280 only allows second granularities in the validity interval, with
     * two conflicting interpretations of how to handle the validity check:
     *
     * 1. Comparisons are performed at the granularity of the encoded
     *    representation, i.e. `floor(time)`. Under this interpretation,
     *    the chain is valid, since the entire millisecond interval `[0, .999...]`
     *    is truncated to `0`.
     * 2. Comparisons are instantaneous. Under this interpretation the chain
     *    is **invalid**, since 5 milliseconds after the `notAfter` is factually
     *    after the `notAfter`.
     *
     * There is no clear "winning" interpretation here, although
     * CAs in the Web PKI have filed and handled compliance reports based on
     * interpretation (1). **Hence, we truncate to seconds precision**.
     *
     */
    fun isExpired(date: Instant = Clock.System.now()): Boolean =
        date.epochSeconds > tbsCertificate.validUntil.epochSeconds

    /** Whether this certificate is not yet valid at [date].
     *
     * RFC 5280 only allows second granularities in the validity interval, with
     * two conflicting interpretations of how to handle the validity check:
     *
     * 1. Comparisons are performed at the granularity of the encoded
     *    representation, i.e. `floor(time)`. Under this interpretation,
     *    the chain is valid, since the entire millisecond interval `[0, .999...]`
     *    is truncated to `0`.
     * 2. Comparisons are instantaneous. Under this interpretation the chain
     *    is **invalid**, since 5 milliseconds after the `notAfter` is factually
     *    after the `notAfter`.
     *
     * There is no clear "winning" interpretation here, although
     * CAs in the Web PKI have filed and handled compliance reports based on
     * interpretation (1). **Hence, we truncate to seconds precision**.
     *
     */
    fun isNotYetValid(date: Instant = Clock.System.now()): Boolean =
        date.epochSeconds < tbsCertificate.validFrom.epochSeconds

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
        override val alternativePemLabels: Set<String> get() = X509Certificate.alternativePemLabels

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            element: X509Certificate,
            der: Der,
        ): Certificate =
            Certificate(element)

        @Throws(Asn1Exception::class)
        fun decodeFromTlv(src: Asn1Element): Certificate =
            decodeFromTlv(X509Certificate.serializer(), src, DER)

        /**
         * Tries to decode [src] into an [Certificate], by parsing the bytes directly as ASN.1 structure,
         * or by decoding from Base64.
         */
        fun decodeFromByteArray(src: ByteArray, limit: Long = src.size.toLong(), der: Der = DER): Certificate? =
            catchingUnwrapped {
                Certificate(der.decodeFromDer<X509Certificate>(src))
            }.getOrNull() ?: catchingUnwrapped {
                Certificate(der.decodeFromDer<X509Certificate>(src.decodeToByteArray(Base64())))
            }.getOrNull() ?: Certificate.decodeFromPem(src.decodeToString(), limit, der)
    }
}

typealias CertificateChain = List<Certificate>

val CertificateChain.leaf: Certificate get() = first()
val CertificateChain.root: Certificate get() = last()

/** Returns the first extension of type [T] (e.g. a typed [CertificateExtension]), or `null`. */
inline fun <reified T : CertificateExtension> Certificate.findExtension(): T? =
    tbsCertificate.extensions.firstNotNullOfOrNull { it as? T }

private fun validateExtensions(extensions: List<CertificateExtension>) {
    if (!extensions.allDistinctByOids()) {
        throw Asn1StructuralException("Multiple extensions with the same OID found")
    }
}
