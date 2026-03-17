package at.asitplus.signum.indispensable.digest

import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.hmacWithSHA1
import at.asitplus.signum.indispensable.asn1.hmacWithSHA256
import at.asitplus.signum.indispensable.asn1.hmacWithSHA384
import at.asitplus.signum.indispensable.asn1.hmacWithSHA512
import at.asitplus.signum.indispensable.asn1.sha1
import at.asitplus.signum.indispensable.asn1.sha_256
import at.asitplus.signum.indispensable.asn1.sha_384
import at.asitplus.signum.indispensable.asn1.sha_512
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit

sealed class WellKnownDigest(
    override val name: String,
    override val inputBlockSize: BitLength, override val outputLength: BitLength,
    override val oid: ObjectIdentifier) : Digest, Enumerable {

    data object SHA1 : WellKnownDigest("SHA1", 512.bit, 160.bit, KnownOIDs.sha1)
    data object SHA256 : WellKnownDigest("SHA256", 512.bit, 256.bit, KnownOIDs.sha_256)
    data object SHA384 : WellKnownDigest("SHA384", 1024.bit, 384.bit, KnownOIDs.sha_384)
    data object SHA512 : WellKnownDigest("SHA512", 1024.bit, 512.bit, KnownOIDs.sha_512)

    companion object : Enumeration<WellKnownDigest> {
        override val entries: Iterable<WellKnownDigest> by lazy { setOf(SHA1, SHA256, SHA384, SHA512) }
    }
}

object IndispensableDigestsProvider: DigestProvider {
    override fun getDigests(): Iterable<Digest> = WellKnownDigest.entries
    override fun getRFC2104HMACOID(digest: Digest): ObjectIdentifier? = when(digest) {
        WellKnownDigest.SHA1 -> KnownOIDs.hmacWithSHA1
        WellKnownDigest.SHA256 -> KnownOIDs.hmacWithSHA256
        WellKnownDigest.SHA384 -> KnownOIDs.hmacWithSHA384
        WellKnownDigest.SHA512 -> KnownOIDs.hmacWithSHA512
        else -> null
    }
}