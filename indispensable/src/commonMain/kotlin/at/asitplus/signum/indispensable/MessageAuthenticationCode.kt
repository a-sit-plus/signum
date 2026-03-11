package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.Asn1.Null
import at.asitplus.awesn1.encoding.readNull
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration

interface MessageAuthenticationCode : DataIntegrityAlgorithm, Enumerable {
    val outputLength: BitLength

    @Deprecated("Use TruncatedMessageAuthenticationCode.", ReplaceWith("TruncatedMessageAuthenticationCode"))
    interface Truncated : MessageAuthenticationCode {
        val inner: MessageAuthenticationCode
    }

    companion object : Enumeration<MessageAuthenticationCode> {
        override val entries: Iterable<MessageAuthenticationCode>
            get() {
                HMAC_SHA1
                return AlgorithmRegistry.messageAuthenticationCodes
            }

        fun register(algorithm: MessageAuthenticationCode): MessageAuthenticationCode =
            AlgorithmRegistry.registerMessageAuthenticationCode(algorithm)
    }

    fun truncatedTo(length: BitLength): MessageAuthenticationCode = when {
        this is TruncatedMessageAuthenticationCode -> this.inner.truncatedTo(length)
        else -> when {
            length <= 0.bit -> throw IllegalArgumentException("Cannot truncate to $outputLength <= 0")
            length < this.outputLength -> TruncatedMessageAuthenticationCode(this, length)
            length == this.outputLength -> this
            else -> throw IllegalArgumentException("Cannot truncate $this to $outputLength bits (its own output length is only ${this.outputLength} bits")
        }
    }
}

open class TruncatedMessageAuthenticationCode internal constructor(
    override val inner: MessageAuthenticationCode,
    override val outputLength: BitLength
) : MessageAuthenticationCode, MessageAuthenticationCode.Truncated, WithDigest, WithOutputLength {
    override val digest: Digest?
        get() = (inner as? WithDigest)?.digest

    override fun equals(other: Any?): Boolean =
        other is TruncatedMessageAuthenticationCode && inner == other.inner && outputLength == other.outputLength

    override fun hashCode(): Int = 31 * inner.hashCode() + outputLength.hashCode()

    override fun toString() = "$inner (truncated to $outputLength)"
}

open class HmacAlgorithm(
    override val digest: Digest,
    override val oid: ObjectIdentifier
) : MessageAuthenticationCode, Identifiable, Asn1Encodable<Asn1Sequence>, WithDigest, WithOutputLength {
    override fun toString() = "HMAC-$digest"

    override val outputLength: BitLength get() = digest.outputLength

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +oid
        +Null()
    }

    companion object : Asn1Decodable<Asn1Sequence, HmacAlgorithm>, Enumeration<HmacAlgorithm> {
        override val entries: Iterable<HmacAlgorithm>
            get() {
                MessageAuthenticationCode.HMAC_SHA1
                return MessageAuthenticationCode.entries.filterIsInstance<HmacAlgorithm>()
            }

        fun register(algorithm: HmacAlgorithm): HmacAlgorithm =
            AlgorithmRegistry.registerMessageAuthenticationCode(algorithm) as HmacAlgorithm

        fun byOID(oid: ObjectIdentifier): HmacAlgorithm? = MessageAuthenticationCode.entries
            .filterIsInstance<HmacAlgorithm>()
            .find { it.oid == oid }

        fun byDigest(digest: Digest): HmacAlgorithm = when (digest) {
            Digest.SHA1 -> MessageAuthenticationCode.HMAC_SHA1
            Digest.SHA256 -> MessageAuthenticationCode.HMAC_SHA256
            Digest.SHA384 -> MessageAuthenticationCode.HMAC_SHA384
            Digest.SHA512 -> MessageAuthenticationCode.HMAC_SHA512
        }

        operator fun invoke(digest: Digest) = byDigest(digest)

        override fun doDecode(src: Asn1Sequence): HmacAlgorithm = src.decodeRethrowing {
            val oid = next().asPrimitive().readOid()
            next().asPrimitive().readNull()
            byOID(oid) ?: throw Asn1OidException("Unknown OID", oid)
        }
    }
}

private data object HmacSha1 : HmacAlgorithm(Digest.SHA1, KnownOIDs.hmacWithSHA1)
private data object HmacSha256 : HmacAlgorithm(Digest.SHA256, KnownOIDs.hmacWithSHA256)
private data object HmacSha384 : HmacAlgorithm(Digest.SHA384, KnownOIDs.hmacWithSHA384)
private data object HmacSha512 : HmacAlgorithm(Digest.SHA512, KnownOIDs.hmacWithSHA512)

val MessageAuthenticationCode.Companion.HMAC_SHA1: HmacAlgorithm
    get() = AlgorithmRegistry.registerMessageAuthenticationCode(HmacSha1,ensure = false)
val MessageAuthenticationCode.Companion.HMAC_SHA256: HmacAlgorithm
    get() = AlgorithmRegistry.registerMessageAuthenticationCode(HmacSha256,ensure = false)
val MessageAuthenticationCode.Companion.HMAC_SHA384: HmacAlgorithm
    get() = AlgorithmRegistry.registerMessageAuthenticationCode(HmacSha384,ensure = false)
val MessageAuthenticationCode.Companion.HMAC_SHA512: HmacAlgorithm
    get() = AlgorithmRegistry.registerMessageAuthenticationCode(HmacSha512,ensure = false)

@Deprecated(
    "Use MessageAuthenticationCode.HMAC_SHA1 and HmacAlgorithm.",
    ReplaceWith("MessageAuthenticationCode.HMAC_SHA1", "at.asitplus.signum.indispensable.MessageAuthenticationCode")
)
object HMAC {
    val SHA1: HmacAlgorithm get() = MessageAuthenticationCode.HMAC_SHA1
    val SHA256: HmacAlgorithm get() = MessageAuthenticationCode.HMAC_SHA256
    val SHA384: HmacAlgorithm get() = MessageAuthenticationCode.HMAC_SHA384
    val SHA512: HmacAlgorithm get() = MessageAuthenticationCode.HMAC_SHA512

    val entries: Iterable<HmacAlgorithm>
        get() = listOf(SHA1, SHA256, SHA384, SHA512)

    fun byOID(oid: ObjectIdentifier): HmacAlgorithm? = HmacAlgorithm.byOID(oid)
    fun byDigest(digest: Digest): HmacAlgorithm = HmacAlgorithm.byDigest(digest)
    operator fun invoke(digest: Digest): HmacAlgorithm = HmacAlgorithm(digest)
}

interface SpecializedMessageAuthenticationCode : SpecializedDataIntegrityAlgorithm {
    override val algorithm: MessageAuthenticationCode
}
