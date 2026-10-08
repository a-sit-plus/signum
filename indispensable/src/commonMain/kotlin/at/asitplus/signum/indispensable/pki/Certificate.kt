package at.asitplus.signum.indispensable.pki
import at.asitplus.signum.indispensable.Encodable

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.allDistinctByOids
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import kotlin.time.Clock
import kotlin.time.Instant

/** Signed certificate contents, with the original decoded source retained separately. */
class Certificate internal constructor(
    val tbsCertificate: TbsCertificate,
    signatureProvider: () -> CryptoSignature/*defer to also parse and round-trip even unsupported sigalgs*/,
    override val sourceRepresentation: Pair<Encodable.Representation, Any>?,
) : Encodable {
    constructor(
        tbsCertificate: TbsCertificate,
        signature: CryptoSignature,
    ) : this(tbsCertificate, { signature }, null) {
        require(tbsCertificate.extensions.allDistinctByOids()) { "Multiple extensions with the same OID found" }
    }

    val signature by lazy(signatureProvider)

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

    override fun equals(other: Any?): Boolean = this === other || catchingUnwrapped {
        other is Certificate && tbsCertificate == other.tbsCertificate && signature == other.signature
    }.getOrDefault(false)

    override fun hashCode(): Int = catchingUnwrapped {
        31 * tbsCertificate.hashCode() + signature.hashCode()
    }.getOrDefault(0)

    override fun toString(): String = catchingUnwrapped {
        "Certificate(tbsCertificate=$tbsCertificate, signature=$signature)"
    }.getOrElse { "Certificate(semantic content unavailable)" }

    companion object : Decodable<Certificate>
}

typealias CertificateChain = List<Certificate>

val CertificateChain.leaf: Certificate get() = first()
val CertificateChain.root: Certificate get() = last()

/** Returns the first extension of type [T] (e.g. a typed [CertificateExtension]), or `null`. */
inline fun <reified T : CertificateExtension> Certificate.findExtension(): T? =
    tbsCertificate.extensions.firstNotNullOfOrNull { it as? T }

internal fun validateExtensions(extensions: List<CertificateExtension>) {
    if (!extensions.allDistinctByOids()) {
        throw Asn1StructuralException("Multiple extensions with the same OID found")
    }
}
