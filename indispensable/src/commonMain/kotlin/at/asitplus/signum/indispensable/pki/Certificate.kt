package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
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
class TbsCertificate constructor(
    val serialNumber: Asn1Integer,
    val signatureAlgorithm: SignatureAlgorithm,
    val issuerName: Name,
    validFrom: Instant,
    validUntil: Instant,
    val subjectName: Name,
    val publicKey: CryptoPublicKey,
    val issuerUniqueID: ByteArray? = null,
    val subjectUniqueID: ByteArray? = null,
    val extensions: List<CertificateExtension> = emptyList(),
    providedAsn1Representation: X509TbsCertificate? = null,
) : DerEncodable<X509TbsCertificate> {

    val validFrom = validFrom.secondsCapped()
    val validUntil = validUntil.secondsCapped()

    constructor(asn1Representation: X509TbsCertificate) : this(
        serialNumber = asn1Representation.serialNumber,
        signatureAlgorithm = SignatureAlgorithm.decodeFromTlv(asn1Representation.signatureAlgorithm),
        issuerName = X500Name(asn1Representation.issuerName.map(::RelativeDistinguishedName), false),
        validFrom = asn1Representation.validity.validFrom.instant,
        validUntil = asn1Representation.validity.validUntil.instant,
        subjectName = X500Name(asn1Representation.subjectName.map(::RelativeDistinguishedName), false),
        publicKey = CryptoPublicKey(asn1Representation.subjectPublicKeyInfo),
        issuerUniqueID = asn1Representation.issuerUniqueID?.bitCarryingBytes,
        subjectUniqueID = asn1Representation.subjectUniqueID?.bitCarryingBytes,
        extensions = asn1Representation.extensions?.map { CertificateExtension(it) }.orEmpty(),
        providedAsn1Representation = asn1Representation
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TbsCertificate) return false
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


    init {
        serialNumber.encodeToAsn1ContentBytes().size.let { size ->
            runRethrowing { require(size <= 20) { "Serial Number too long for X.509. Limit = 20 value octets, is: $size" } }
        }
        runRethrowing { require(!serialNumber.isZero()) { "Serial Number must not be zero" } }
        validateExtensions(extensions)
    }

    override val asn1Representation: X509TbsCertificate by providedAsn1Representation orLazy {
        X509TbsCertificate(
            serialNumber = serialNumber,
            signatureAlgorithm = signatureAlgorithm.asn1Representation,
            issuerName = issuerName.requireX509().asn1Representation,
            validFrom = Asn1Time.SecondsCapped(validFrom),
            validUntil = Asn1Time.SecondsCapped(validUntil),
            subjectName = subjectName.requireX509().asn1Representation,
            subjectPublicKeyInfo = publicKey.asn1Representation,
            issuerUniqueID = issuerUniqueID?.let { Asn1BitString(it) },
            subjectUniqueID = subjectUniqueID?.let { Asn1BitString(it) },
            extensions = extensions.map { it.requireX509().asn1Representation },
        )
    }

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

    /**
     * Debug String representation. Uses Base64 encoded DER representation
     */
    override fun toString(): String =
        "TbsCertificate(serialNumber=$serialNumber, signatureAlgorithm=$signatureAlgorithm, " +
                "issuerName=$issuerName, validFrom=$validFrom, validUntil=$validUntil, subjectName=$subjectName, " +
                "publicKey=$publicKey, issuerUniqueID=${issuerUniqueID.contentToString()}, subjectUniqueID=${subjectUniqueID.contentToString()}, " +
                "extensions=$extensions)"

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
class Certificate(
    val tbsCertificate: TbsCertificate,
    val signatureValue: DerEncodable<X509SignatureValue>,
    providedAsn1Representation: X509Certificate? = null,
) : DerPemEncodable<X509Certificate> {

    override val pemLabel: String get() = canonicalPemLabel

    val signature by lazy { signatureValue.withSignatureAlgorithm(tbsCertificate.signatureAlgorithm) }

    constructor(asn1Representation: X509Certificate) : this(
        TbsCertificate(asn1Representation.tbsCertificate),
        CryptoSignature.decodeFromTlv(asn1Representation.signatureValue.also {
            require (asn1Representation.signatureAlgorithm == asn1Representation.tbsCertificate.signatureAlgorithm) {
                "Inner TBS certificate signature algorithm != outer certificate signature algorithm (serial ${asn1Representation.tbsCertificate.serialNumber})"
            }
        }),
        asn1Representation
    )


    override val asn1Representation: X509Certificate by providedAsn1Representation orLazy {
        X509Certificate(
            tbsCertificate = tbsCertificate.asn1Representation,
            signatureAlgorithm = tbsCertificate.signatureAlgorithm.asn1Representation,
            signatureValue = signatureValue.asn1Representation
        )
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
        "Certificate(${
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
