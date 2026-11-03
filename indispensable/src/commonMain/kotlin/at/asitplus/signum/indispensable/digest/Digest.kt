package at.asitplus.signum.indispensable.digest

import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.runRethrowing
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.installIndispensable
import at.asitplus.signum.indispensable.misc.BitLength

interface Digest : Encodable {
    val name: String
    /** The hash function operates by repeatedly ingesting blocks of this length. Used by RFC 9380 et al. */
    val inputBlockSize: BitLength
    /** The length of the hash function's fixed-length digest values */
    val outputLength: BitLength

    @OptIn(SignumInternals::class)
    private class Unknown(
        override val asn1Representation: X509AlgorithmIdentifier,
        override val lookupResult: UnsupportedCryptoException
    ) : Digest, ServiceLoader.UnknownShim {
        override fun toString() = "Unknown Digest ($asn1Representation)"
        override val name get() = throw lookupResult
        override val inputBlockSize get() = throw lookupResult
        override val outputLength get() = throw lookupResult
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Unknown) return false
            return asn1Representation == other.asn1Representation
        }
        override fun hashCode() = asn1Representation.hashCode()
    }

    companion object : Decodable<Digest> {
        init { Signum.installIndispensable() }
        val SHA1 inline get() = WellKnownDigest.SHA1
        val SHA256 inline get() = WellKnownDigest.SHA256
        val SHA384 inline get() = WellKnownDigest.SHA384
        val SHA512 inline get() = WellKnownDigest.SHA512

        fun fromAsn1Representation(element: X509AlgorithmIdentifier): Digest = runRethrowing {
            Signum.load<DigestProvider>().getWithUnknown(element, ::Unknown, DigestProvider::getDigest)
        }
    }
}

// @Service
interface DigestProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: Digest): X509AlgorithmIdentifier? = null

    /** Parse a [Digest] from its [X509AlgorithmIdentifier] form */
    fun getDigest(algorithmIdentifier: X509AlgorithmIdentifier): Digest?
}
// @Service
interface DigestOperationProvider {
    /** If the Digest in question is supported by this provider, return the digest value; otherwise, return null or throw */
    suspend fun doDigest(digest: Digest, data: Sequence<ByteArray>): ByteArray?
}

suspend fun Digest.digest(data: Sequence<ByteArray>): ByteArray =
    Signum.load<DigestOperationProvider>().get(this) { doDigest(it, data) }
suspend fun Digest.digest(data: ByteArray) = digest(sequenceOf(data))
