package at.asitplus.signum.indispensable.mac

import at.asitplus.awesn1.*
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.installIndispensable
import at.asitplus.signum.indispensable.misc.BitLength

/** RFC 2104 HMAC */
class HMAC(val digest: Digest, val oid: ObjectIdentifier)
    : MessageAuthenticationCode
{

    override val sourceRepresentation = SourceRepresentationStorage()

    override fun toString() = "HMAC-$digest"
    override fun hashCode() = digest.hashCode()
    override fun equals(other: Any?) = (other is HMAC) && (digest == other.digest)

    companion object {
        init { Signum.installIndispensable() }
        val SHA1 = HMAC(Digest.SHA1, KnownOIDs.hmacWithSHA1)
        val SHA256 = HMAC(Digest.SHA256, KnownOIDs.hmacWithSHA256)
        val SHA384 = HMAC(Digest.SHA384, KnownOIDs.hmacWithSHA384)
        val SHA512 = HMAC(Digest.SHA512, KnownOIDs.hmacWithSHA512)

        fun byDigest(digest: WellKnownDigest) = when (digest) {
            is WellKnownDigest.SHA1 -> HMAC(digest, KnownOIDs.hmacWithSHA1)
            is WellKnownDigest.SHA256 -> HMAC(digest, KnownOIDs.hmacWithSHA256)
            is WellKnownDigest.SHA384 -> HMAC(digest, KnownOIDs.hmacWithSHA384)
            is WellKnownDigest.SHA512 -> HMAC(digest, KnownOIDs.hmacWithSHA512)
        }
    }

    override val outputLength: BitLength get() = digest.outputLength
}
