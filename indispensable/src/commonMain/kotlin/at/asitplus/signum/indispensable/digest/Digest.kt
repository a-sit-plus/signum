package at.asitplus.signum.indispensable.digest

import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.internals.ServiceLoader

interface Digest : Identifiable, Enumerable {
    val name: String
    /** The hash function operates by repeatedly ingesting blocks of this length. Used by RFC 9380 et al. */
    val inputBlockSize: BitLength
    /** The length of the hash function's fixed-length digest values */
    val outputLength: BitLength

    companion object : Enumeration<Digest> {
        override val entries: Iterable<Digest> get() =
            ServiceLoader.load<DigestProvider>().asSequence().flatMap(DigestProvider::getDigests).toList()
        val SHA1 inline get() = WellKnownDigest.SHA1
        val SHA256 inline get() = WellKnownDigest.SHA256
        val SHA384 inline get() = WellKnownDigest.SHA384
        val SHA512 inline get() = WellKnownDigest.SHA512
    }
}

// @Service
interface DigestProvider {
    /** The list of digests supported by this provider */
    fun getDigests(): Iterable<Digest>
    /** If the digest supports use in a RFC2104-style HMAC, the OID for this construction */
    fun getRFC2104HMACOID(digest: Digest): ObjectIdentifier? { return null }
}
// @Service
interface DigestOperationProvider {
    /** If the Digest in question is supported by this provider, return the operator to use; otherwise, return null */
    fun getDigestOperator(digest: Digest): ((Sequence<ByteArray>)->ByteArray)?
}

fun Digest.digest(data: Sequence<ByteArray>): ByteArray =
    (ServiceLoader.load<DigestOperationProvider>().also {
        if (it.none()) throw UnsupportedCryptoException("No digest providers are loaded")
    }.firstNotNullOfOrNull {
        it.getDigestOperator(this@digest)
    } ?: throw UnsupportedCryptoException("No loaded digest provider supports ${this@digest}"))(data)
fun Digest.digest(data: ByteArray) = digest(sequenceOf(data))
