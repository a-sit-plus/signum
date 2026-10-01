package at.asitplus.signum.indispensable.digest

import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.runRethrowing
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.Indispensable
import at.asitplus.signum.indispensable.misc.BitLength

interface Digest : Encodable {
    val name: String
    /** The hash function operates by repeatedly ingesting blocks of this length. Used by RFC 9380 et al. */
    val inputBlockSize: BitLength
    /** The length of the hash function's fixed-length digest values */
    val outputLength: BitLength

    companion object : Decodable<Digest> {
        init { Indispensable.init() }
        val SHA1 inline get() = WellKnownDigest.SHA1
        val SHA256 inline get() = WellKnownDigest.SHA256
        val SHA384 inline get() = WellKnownDigest.SHA384
        val SHA512 inline get() = WellKnownDigest.SHA512

        fun fromAsn1Representation(element: X509AlgorithmIdentifier): Digest = runRethrowing {
            ServiceLoader.load<DigestProvider>().get(element, DigestProvider::getDigest)
        }
    }
}

// @Service
interface DigestProvider {
    /** Parse a [Digest] from its [X509AlgorithmIdentifier] form */
    fun getDigest(algorithmIdentifier: X509AlgorithmIdentifier): Digest?
}
// @Service
interface DigestOperationProvider {
    /** If the Digest in question is supported by this provider, return the digest value; otherwise, return null or throw */
    suspend fun doDigest(digest: Digest, data: Sequence<ByteArray>): ByteArray?
}

suspend fun Digest.digest(data: Sequence<ByteArray>): ByteArray =
    ServiceLoader.load<DigestOperationProvider>().get(this) { doDigest(it, data) }
suspend fun Digest.digest(data: ByteArray) = digest(sequenceOf(data))
