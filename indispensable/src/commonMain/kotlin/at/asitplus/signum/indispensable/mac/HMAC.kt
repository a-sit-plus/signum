package at.asitplus.signum.indispensable.mac
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.indispensable.Encodable

import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.hmacWithSHA1
import at.asitplus.awesn1.hmacWithSHA256
import at.asitplus.awesn1.hmacWithSHA384
import at.asitplus.awesn1.hmacWithSHA512
import at.asitplus.signum.indispensable.Indispensable
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.misc.BitLength

/** RFC 2104 HMAC */
data class HMAC(val digest: Digest, val oid: ObjectIdentifier)
    : MessageAuthenticationCode
{

    override fun toString() = "HMAC-$digest"

    override val representations: Map<Encodable.Representation, Any>

        get() = mapOf(X509 to x509Model)

    internal val x509Model: X509AlgorithmIdentifier
        get() = X509AlgorithmIdentifier(oid, Asn1Null)

    companion object {
        init { Indispensable.init() }
        val SHA1 = HMAC(Digest.SHA1, KnownOIDs.hmacWithSHA1)
        val SHA256 = HMAC(Digest.SHA256, KnownOIDs.hmacWithSHA256)
        val SHA384 = HMAC(Digest.SHA384, KnownOIDs.hmacWithSHA384)
        val SHA512 = HMAC(Digest.SHA512, KnownOIDs.hmacWithSHA512)

        fun byDigest(digest: WellKnownDigest) = when (digest) {
            WellKnownDigest.SHA1 -> SHA1
            WellKnownDigest.SHA256 -> SHA256
            WellKnownDigest.SHA384 -> SHA384
            WellKnownDigest.SHA512 -> SHA512
        }
    }

    override val outputLength: BitLength get() = digest.outputLength
}
