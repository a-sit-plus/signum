package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Identifiable
import at.asitplus.crypto.datatypes.asn1.KnownOIDs
import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
import at.asitplus.crypto.datatypes.misc.BitLength
import at.asitplus.crypto.datatypes.misc.bit

enum class Digest(val outputLength: BitLength, override val oid: ObjectIdentifier) : Identifiable {
    SHA1(160.bit, KnownOIDs.sha1),
    SHA256(256.bit, KnownOIDs.sha_256),
    SHA384(384.bit, KnownOIDs.sha_384),
    SHA512(512.bit, KnownOIDs.sha_512);
}

enum class RSAPadding {
    PKCS1,
    PSS;
}

sealed interface SignatureAlgorithm {

    data class HMAC(
        /** The digest to use */
        val digest: Digest
    ) : SignatureAlgorithm

    data class ECDSA(
        /** The digest to apply to the data, or `null` to directly process the raw data. */
        val digest: Digest?,
        /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
        val requiredCurve: ECCurve?
    ) : SignatureAlgorithm

    data class RSA(
        /** The digest to apply to the data. */
        val digest: Digest,
        /** The padding to apply to the data. */
        val padding: RSAPadding
    ) : SignatureAlgorithm
}
