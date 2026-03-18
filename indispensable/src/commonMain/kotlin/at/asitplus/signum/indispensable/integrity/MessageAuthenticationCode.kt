package at.asitplus.signum.indispensable.integrity

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Null
import at.asitplus.signum.indispensable.asn1.encoding.readNull
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.DigestProvider
import at.asitplus.signum.internals.ServiceLoader

sealed interface MessageAuthenticationCode : DataIntegrityAlgorithm, Enumerable {
    /** output size of MAC */
    val outputLength: BitLength

    companion object : Enumeration<MessageAuthenticationCode> {
        // lazy due to https://youtrack.jetbrains.com/issue/KT-79161
        override val entries: Iterable<MessageAuthenticationCode> by lazy { HMAC.entries }
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
class HMAC(val digest: Digest) : MessageAuthenticationCode, Identifiable,
    Asn1Encodable<Asn1Sequence> {

    override val oid = ServiceLoader.load<DigestProvider>().also {
        if (it.none()) throw UnsupportedCryptoException("No Digest providers are loaded")
    }.firstNotNullOfOrNull {
        it.getRFC2104HMACOID(digest)
    } ?: throw UnsupportedCryptoException("$digest does not support RFC2014-style HMAC composition")

    override fun toString() = "HMAC-$digest"

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +oid
        +Null()
    }

    companion object : Asn1Decodable<Asn1Sequence, HMAC>, Enumeration<HMAC> {

        val SHA1 = HMAC(Digest.SHA1)
        val SHA256 = HMAC(Digest.SHA256)
        val SHA384 = HMAC(Digest.SHA384)
        val SHA512 = HMAC(Digest.SHA512)

        fun byOID(oid: ObjectIdentifier): HMAC? = entries.find { it.oid == oid }

        @Deprecated("Use the HMAC() constructor directly", replaceWith = ReplaceWith("HMAC(digest)"))
        fun byDigest(digest: Digest): HMAC = HMAC(digest)

        override fun doDecode(src: Asn1Sequence): HMAC = src.decodeRethrowing {
            val oid = next().asPrimitive().readOid()
            next().asPrimitive().readNull()
            byOID(oid) ?: throw Asn1OidException("Unknown OID", oid)
        }

        override val entries: Iterable<HMAC> get() = Digest.entries.asSequence().mapNotNull {
            try { HMAC(it) } catch (_: UnsupportedCryptoException) { null }
        }.asIterable()
    }

    override val outputLength: BitLength get() = digest.outputLength
}
