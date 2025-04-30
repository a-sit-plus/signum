package at.asitplus.signum.indispensable.kdf

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.HMAC


sealed interface KDF {

    companion object {
        val entries: Iterable<KDF> = (HKDF.entries.toList() + PBKDF2.entries.toList())
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

    val outputLength: Int get() = digest.outputLength.bytes.toInt()
}


enum class PBKDF2(val prf: HMAC) : KDF {
    HMAC_SHA1(HMAC.SHA1),
    HMAC_SHA256(HMAC.SHA256),
    HMAC_SHA384(HMAC.SHA384),
    HMAC_SHA512(HMAC.SHA512);

    companion object {
        operator fun invoke(prf: HMAC) = when (prf) {
            HMAC.SHA1 -> HMAC_SHA1
            HMAC.SHA256 -> HMAC_SHA256
            HMAC.SHA384 -> HMAC_SHA384
            HMAC.SHA512 -> HMAC_SHA512
        }

        operator fun invoke(digest: Digest) = invoke(HMAC(digest))
    }
}