package at.asitplus.signum.indispensable.digest

import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.WithSourceRepresentation
import at.asitplus.signum.indispensable.installIndispensable
import at.asitplus.signum.indispensable.misc.BitLength

interface Digest : WithSourceRepresentation {
    val name: String
    /** The hash function operates by repeatedly ingesting blocks of this length. Used by RFC 9380 et al. */
    val inputBlockSize: BitLength
    /** The length of the hash function's fixed-length digest values */
    val outputLength: BitLength

    @SignumInternals
    class Unknown(lookupResult: UnsupportedCryptoException)
        : Digest, ServiceLoader.UnknownShim(lookupResult)
    {
        override val name get() = fails
        override val inputBlockSize get() = fails
        override val outputLength get() = fails
    }

    companion object {
        init { Signum.installIndispensable() }
        val SHA1 inline get() = WellKnownDigest.SHA1
        val SHA256 inline get() = WellKnownDigest.SHA256
        val SHA384 inline get() = WellKnownDigest.SHA384
        val SHA512 inline get() = WellKnownDigest.SHA512
    }
}

// @Service
interface Asn1DigestAlgorithmProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: Digest): X509AlgorithmIdentifier? = null

    /** Parse a [Digest] from its [X509AlgorithmIdentifier] form */
    fun decodeFromAsn1(algorithmIdentifier: X509AlgorithmIdentifier): Digest?
}
// @Service
interface DigestOperationProvider {
    /** If the Digest in question is supported by this provider, return the digest value; otherwise, return null or throw */
    suspend fun doDigest(digest: Digest, data: Sequence<ByteArray>): ByteArray?
}

suspend fun Digest.digest(data: Sequence<ByteArray>): ByteArray =
    ServiceLoader.load<DigestOperationProvider>().get(this) { doDigest(it, data) }
suspend fun Digest.digest(data: ByteArray) = digest(sequenceOf(data))
