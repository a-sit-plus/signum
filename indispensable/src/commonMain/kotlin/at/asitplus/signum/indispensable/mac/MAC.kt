package at.asitplus.signum.indispensable.mac

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.misc.BitLength

sealed interface MAC {
    /** output size of MAC */
    val outputLength: BitLength

    companion object {
        val entries: Iterable<MAC> = HMAC.entries
    }
}

/**
 * RFC 2104 HMAC
 */
enum class HMAC(val digest: Digest, override val oid: ObjectIdentifier) : MAC, Identifiable {
    SHA1(Digest.SHA1, KnownOIDs.hmacWithSHA1),
    SHA256(Digest.SHA256, KnownOIDs.hmacWithSHA256),
    SHA384(Digest.SHA384, KnownOIDs.hmacWithSHA384),
    SHA512(Digest.SHA512, KnownOIDs.hmacWithSHA512),
    ;

    override fun toString() = "HMAC-$digest"

    companion object {
        operator fun invoke(digest: Digest) = when (digest) {
            Digest.SHA1 -> SHA1
            Digest.SHA256 -> SHA256
            Digest.SHA384 -> SHA384
            Digest.SHA512 -> SHA512
        }
    }

    override val outputLength: BitLength get() = digest.outputLength
}
