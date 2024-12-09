package at.asitplus.signum.indispensable.kdf

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.mac.HMAC


sealed interface KDF {
    /** output size of Extract */
    val outputLength: Int

    companion object {
        val entries: Iterable<KDF> = HKDF.entries
    }
}

/** RFC 5869 HKDF */
enum class HKDF(private val digest: Digest) : KDF {
    SHA1(Digest.SHA1),
    SHA256(Digest.SHA256),
    SHA384(Digest.SHA384),
    SHA512(Digest.SHA512);

    companion object {
        operator fun invoke(digest: Digest) = when (digest) {
            Digest.SHA1 -> SHA1
            Digest.SHA256 -> SHA256
            Digest.SHA384 -> SHA384
            Digest.SHA512 -> SHA512
        }
    }

    val hmac = HMAC.entries.first { it.digest == digest }

    override val outputLength: Int get() = digest.outputLength.bytes.toInt()
}
