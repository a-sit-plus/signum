package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit

enum class Digest(val outputLength: BitLength, override val oid: ObjectIdentifier) : Identifiable {
    SHA1(160.bit, KnownOIDs.sha1),
    SHA256(256.bit, KnownOIDs.sha_256),
    SHA384(384.bit, KnownOIDs.sha_384),
    SHA512(512.bit, KnownOIDs.sha_512);
}

/** A digest well-suited to operations on this curve, with output length near the curve's coordinate length. */
val ECCurve.nativeDigest get() = when (this) {
    ECCurve.SECP_256_R_1 -> Digest.SHA256
    ECCurve.SECP_384_R_1 -> Digest.SHA384
    ECCurve.SECP_521_R_1 -> Digest.SHA512
}
