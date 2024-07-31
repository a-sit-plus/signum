package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit

enum class Digest(val outputLength: BitLength, override val oid: ObjectIdentifier) : Identifiable {
    SHA1(160.bit, at.asitplus.signum.indispensable.asn1.KnownOIDs.sha1),
    SHA256(256.bit, at.asitplus.signum.indispensable.asn1.KnownOIDs.sha_256),
    SHA384(384.bit, at.asitplus.signum.indispensable.asn1.KnownOIDs.sha_384),
    SHA512(512.bit, at.asitplus.signum.indispensable.asn1.KnownOIDs.sha_512);
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

    companion object {
        val ECDSAwithSHA256 = ECDSA(Digest.SHA256, null)
        val ECDSAwithSHA384 = ECDSA(Digest.SHA384, null)
        val ECDSAwithSHA512 = ECDSA(Digest.SHA512, null)

        val RSAwithSHA256andPKCS1Padding = RSA(Digest.SHA256, RSAPadding.PKCS1)
        val RSAwithSHA384andPKCS1Padding = RSA(Digest.SHA384, RSAPadding.PKCS1)
        val RSAwithSHA512andPKCS1Padding = RSA(Digest.SHA512, RSAPadding.PKCS1)

        val RSAwithSHA256andPSSPadding = RSA(Digest.SHA256, RSAPadding.PSS)
        val RSAwithSHA384andPSSPadding = RSA(Digest.SHA384, RSAPadding.PSS)
        val RSAwithSHA512andPSSPadding = RSA(Digest.SHA512, RSAPadding.PSS)

        @Deprecated("Not yet implemented", level = DeprecationLevel.ERROR)
        val HMACwithSHA256 = HMAC(Digest.SHA256)
        @Deprecated("Not yet implemented", level = DeprecationLevel.ERROR)
        val HMACwithSHA384 = HMAC(Digest.SHA384)
        @Deprecated("Not yet implemented", level = DeprecationLevel.ERROR)
        val HMACwithSHA512 = HMAC(Digest.SHA512)
    }
}

interface SpecializedSignatureAlgorithm {
    val algorithm: SignatureAlgorithm
}
