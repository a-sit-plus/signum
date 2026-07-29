package at.asitplus.signum.indispensable.digest

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.Indispensable
import kotlinx.serialization.KSerializer

interface Digest : Identifiable, Enumerable, DerEncodable<X509AlgorithmIdentifier> {
    val name: String
    /** The hash function operates by repeatedly ingesting blocks of this length. Used by RFC 9380 et al. */
    val inputBlockSize: BitLength
    /** The length of the hash function's fixed-length digest values */
    val outputLength: BitLength

    companion object : Enumeration<Digest>, DerDecodable<X509AlgorithmIdentifier, Digest> {
        init { Indispensable.init() }
        override val entries: Iterable<Digest> get() =
            ServiceLoader.load<DigestProvider>().asSequence().flatMap(DigestProvider::getDigests).toList()
        val SHA1 inline get() = WellKnownDigest.SHA1
        val SHA256 inline get() = WellKnownDigest.SHA256
        val SHA384 inline get() = WellKnownDigest.SHA384
        val SHA512 inline get() = WellKnownDigest.SHA512

        override fun decodeFromTlv(element: X509AlgorithmIdentifier, der: Der): Digest = runRethrowing {
            ServiceLoader.load<DigestProvider>().get(element, DigestProvider::getDigest)
        }
    }
}

// @Service
interface DigestProvider {
    /** A best-effort attempt at a list of digests supported by this provider. May be incomplete for, e.g., parametrized digests. */
    fun getDigests(): Iterable<Digest>
    /** Parse a [Digest] from its [X509AlgorithmIdentifier] form */
    fun getDigest(algorithmIdentifier: X509AlgorithmIdentifier): Digest?
    /** If the digest supports use in a RFC2104-style HMAC, the OID for this construction */
    fun getRFC2104HMACOID(digest: Digest): ObjectIdentifier? { return null }
}
// @Service
interface DigestOperationProvider {
    /** If the Digest in question is supported by this provider, return the digest value; otherwise, return null or throw */
    suspend fun digest(digest: Digest, data: Sequence<ByteArray>): ByteArray?
}

suspend fun Digest.digest(data: Sequence<ByteArray>): ByteArray =
    ServiceLoader.load<DigestOperationProvider>().get(this) { digest(it, data) }
suspend fun Digest.digest(data: ByteArray) = digest(sequenceOf(data))
