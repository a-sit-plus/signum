package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Null
import at.asitplus.signum.indispensable.asn1.encoding.readNull
import at.asitplus.signum.indispensable.asn1.serialization.Asn1Serializer
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import kotlinx.serialization.Serializable

sealed interface MessageAuthenticationCode : DataIntegrityAlgorithm {
    /** output size of MAC */
    val outputLength: BitLength

    companion object {
        val entries: Iterable<MessageAuthenticationCode> = HMAC.entries
    }

    @ConsistentCopyVisibility
    data class Truncated
        internal constructor(val inner: MessageAuthenticationCode, override val outputLength: BitLength)
        : MessageAuthenticationCode
    {
        override fun toString() = "$inner (truncated to $outputLength)"
    }

    fun truncatedTo(length: BitLength): MessageAuthenticationCode = when {
        this is Truncated -> this.inner.truncatedTo(length)
        else -> when {
            length <= 0.bit -> throw IllegalArgumentException("Cannot truncate to $outputLength <= 0")
            length < this.outputLength -> Truncated(this, length)
            length == this.outputLength -> this
            else -> throw IllegalArgumentException("Cannot truncate $this to $outputLength bits (its own output length is only ${this.outputLength} bits")
        }
    }
}

interface SpecializedMessageAuthenticationCode : SpecializedDataIntegrityAlgorithm {
    override val algorithm: MessageAuthenticationCode
}

/**
 * RFC 2104 HMAC
 */
@Serializable(with = HMAC.Companion::class)
enum class HMAC(val digest: Digest, override val oid: ObjectIdentifier) : MessageAuthenticationCode, Identifiable,
    Asn1Encodable<Asn1Sequence> {
    SHA1(Digest.SHA1, KnownOIDs.hmacWithSHA1),
    SHA256(Digest.SHA256, KnownOIDs.hmacWithSHA256),
    SHA384(Digest.SHA384, KnownOIDs.hmacWithSHA384),
    SHA512(Digest.SHA512, KnownOIDs.hmacWithSHA512),
    ;

    override fun toString() = "HMAC-$digest"

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +oid
        +Null()
    }


    companion object : Asn1Decodable<Asn1Sequence, HMAC>, Asn1Serializer<Asn1Sequence, HMAC> {

        fun byOID(oid: ObjectIdentifier): HMAC? = entries.find { it.oid == oid }

        fun byDigest(digest: Digest): HMAC = entries.find { it.digest == digest }!!

        operator fun invoke(digest: Digest) = when (digest) {
            Digest.SHA1 -> SHA1
            Digest.SHA256 -> SHA256
            Digest.SHA384 -> SHA384
            Digest.SHA512 -> SHA512
        }

        override fun doDecode(src: Asn1Sequence): HMAC {
            val oid = src.nextChild().asPrimitive().readOid()
            src.nextChild().asPrimitive().readNull()
            require(!src.hasMoreChildren()) { "Superfluous ANS.1 data in HMAC" }
            return byOID(oid) ?: throw Asn1OidException("Unknown OID", oid)
        }
    }

    override val outputLength: BitLength get() = digest.outputLength
}
