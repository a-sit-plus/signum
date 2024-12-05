package at.asitplus.signum.indispensable.mac

import at.asitplus.signum.indispensable.Digest

sealed interface MAC {
    /** output size of MAC */
    val outputLength: Int

    companion object {
        val entries: Iterable<MAC> = HMAC.entries
    }
}

/**
 * RFC 2104 HMAC
 */
enum class HMAC(val digest: Digest) : MAC {
    SHA1(Digest.SHA1),
    SHA256(Digest.SHA256),
    SHA384(Digest.SHA384),
    SHA512(Digest.SHA512);

    override fun toString()= "HMAC-$digest"

    companion object {
        operator fun invoke(digest: Digest) = when (digest) {
            Digest.SHA1 -> SHA1
            Digest.SHA256 -> SHA256
            Digest.SHA384 -> SHA384
            Digest.SHA512 -> SHA512
        }
    }

    override val outputLength: Int get() = digest.outputLength.bytes.toInt()
}
