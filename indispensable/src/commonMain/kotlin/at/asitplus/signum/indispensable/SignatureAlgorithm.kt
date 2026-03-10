package at.asitplus.signum.indispensable

import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration

interface RsaSignaturePadding : Enumerable {
    companion object : Enumeration<RsaSignaturePadding> {
        private val builtIns = listOf(
            AlgorithmRegistry.registerSignatureRsaPadding(Pkcs1RsaSignaturePadding),
            AlgorithmRegistry.registerSignatureRsaPadding(PssRsaSignaturePadding),
        )

        override val entries: Iterable<RsaSignaturePadding>
            get() {
                builtIns
                return AlgorithmRegistry.signatureRsaPaddings
            }
    }
}

data object Pkcs1RsaSignaturePadding : RsaSignaturePadding {
    override fun toString() = "PKCS1"
}

data object PssRsaSignaturePadding : RsaSignaturePadding {
    override fun toString() = "PSS"
}

interface SignatureAlgorithm : DataIntegrityAlgorithm {
    @Deprecated("Use EcdsaSignatureAlgorithm.", ReplaceWith("EcdsaSignatureAlgorithm"))
    interface ECDSA : SignatureAlgorithm {
        val digest: Digest?
        val requiredCurve: ECCurve?
    }

    @Deprecated("Use RsaSignatureAlgorithm.", ReplaceWith("RsaSignatureAlgorithm"))
    interface RSA : SignatureAlgorithm {
        val digest: Digest
        val padding: RsaSignaturePadding
    }

    companion object : Enumeration<SignatureAlgorithm> {
        private val builtIns = listOf(
            ECDSA_SHA256,
            ECDSA_SHA384,
            ECDSA_SHA512,
            RSA_SHA256_PKCS1,
            RSA_SHA384_PKCS1,
            RSA_SHA512_PKCS1,
            RSA_SHA256_PSS,
            RSA_SHA384_PSS,
            RSA_SHA512_PSS,
        )

        override val entries: Iterable<SignatureAlgorithm>
            get() {
                builtIns
                return AlgorithmRegistry.signatureAlgorithms
            }

        fun register(algorithm: SignatureAlgorithm): SignatureAlgorithm {
            builtIns
            return AlgorithmRegistry.registerSignatureAlgorithm(algorithm)
        }

        @Deprecated(
            "Use EcdsaSignatureAlgorithm(...).",
            ReplaceWith("EcdsaSignatureAlgorithm(digest, requiredCurve)")
        )
        fun ECDSA(digest: Digest?, requiredCurve: ECCurve?) =
            EcdsaSignatureAlgorithm(digest, requiredCurve)

        @Deprecated(
            "Use RsaSignatureAlgorithm(...).",
            ReplaceWith("RsaSignatureAlgorithm(digest, padding)")
        )
        fun RSA(digest: Digest, padding: RsaSignaturePadding) =
            RsaSignatureAlgorithm(digest, padding)

        @Deprecated(
            "Use SignatureAlgorithm.ECDSA_SHA256.",
            ReplaceWith("SignatureAlgorithm.ECDSA_SHA256")
        )
        val ECDSAwithSHA256: SignatureAlgorithm get() = ECDSA_SHA256

        @Deprecated(
            "Use SignatureAlgorithm.ECDSA_SHA384.",
            ReplaceWith("SignatureAlgorithm.ECDSA_SHA384")
        )
        val ECDSAwithSHA384: SignatureAlgorithm get() = ECDSA_SHA384

        @Deprecated(
            "Use SignatureAlgorithm.ECDSA_SHA512.",
            ReplaceWith("SignatureAlgorithm.ECDSA_SHA512")
        )
        val ECDSAwithSHA512: SignatureAlgorithm get() = ECDSA_SHA512

        @Deprecated(
            "Use SignatureAlgorithm.RSA_SHA256_PKCS1.",
            ReplaceWith("SignatureAlgorithm.RSA_SHA256_PKCS1")
        )
        val RSAwithSHA256andPKCS1Padding: SignatureAlgorithm get() = RSA_SHA256_PKCS1

        @Deprecated(
            "Use SignatureAlgorithm.RSA_SHA384_PKCS1.",
            ReplaceWith("SignatureAlgorithm.RSA_SHA384_PKCS1")
        )
        val RSAwithSHA384andPKCS1Padding: SignatureAlgorithm get() = RSA_SHA384_PKCS1

        @Deprecated(
            "Use SignatureAlgorithm.RSA_SHA512_PKCS1.",
            ReplaceWith("SignatureAlgorithm.RSA_SHA512_PKCS1")
        )
        val RSAwithSHA512andPKCS1Padding: SignatureAlgorithm get() = RSA_SHA512_PKCS1

        @Deprecated(
            "Use SignatureAlgorithm.RSA_SHA256_PSS.",
            ReplaceWith("SignatureAlgorithm.RSA_SHA256_PSS")
        )
        val RSAwithSHA256andPSSPadding: SignatureAlgorithm get() = RSA_SHA256_PSS

        @Deprecated(
            "Use SignatureAlgorithm.RSA_SHA384_PSS.",
            ReplaceWith("SignatureAlgorithm.RSA_SHA384_PSS")
        )
        val RSAwithSHA384andPSSPadding: SignatureAlgorithm get() = RSA_SHA384_PSS

        @Deprecated(
            "Use SignatureAlgorithm.RSA_SHA512_PSS.",
            ReplaceWith("SignatureAlgorithm.RSA_SHA512_PSS")
        )
        val RSAwithSHA512andPSSPadding: SignatureAlgorithm get() = RSA_SHA512_PSS
    }
}

open class EcdsaSignatureAlgorithm(
    /** The digest to apply to the data, or `null` to directly process the raw data. */
    override val digest: Digest?,
    /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
    override val requiredCurve: ECCurve?
) : SignatureAlgorithm.ECDSA, WithDigest, WithCurveConstraint {
    override fun toString(): String = buildString {
        append("ECDSA")
        digest?.let { append("with").append(it) }
        requiredCurve?.let { append("@").append(it) }
    }
}

open class RsaSignatureAlgorithm(
    /** The digest to apply to the data. */
    override val digest: Digest,
    /** The padding to apply to the data. */
    override val padding: RsaSignaturePadding
) : SignatureAlgorithm.RSA, WithDigest, WithRsaSignaturePadding {
    override fun toString(): String = "RSAwith${digest}and$padding"
}

private val signatureEcdsaSha256 =
    AlgorithmRegistry.registerSignatureAlgorithm(EcdsaSignatureAlgorithm(Digest.SHA256, null))
private val signatureEcdsaSha384 =
    AlgorithmRegistry.registerSignatureAlgorithm(EcdsaSignatureAlgorithm(Digest.SHA384, null))
private val signatureEcdsaSha512 =
    AlgorithmRegistry.registerSignatureAlgorithm(EcdsaSignatureAlgorithm(Digest.SHA512, null))
private val signatureRsaSha256Pkcs1 =
    AlgorithmRegistry.registerSignatureAlgorithm(RsaSignatureAlgorithm(Digest.SHA256, RsaSignaturePadding.PKCS1))
private val signatureRsaSha384Pkcs1 =
    AlgorithmRegistry.registerSignatureAlgorithm(RsaSignatureAlgorithm(Digest.SHA384, RsaSignaturePadding.PKCS1))
private val signatureRsaSha512Pkcs1 =
    AlgorithmRegistry.registerSignatureAlgorithm(RsaSignatureAlgorithm(Digest.SHA512, RsaSignaturePadding.PKCS1))
private val signatureRsaSha256Pss =
    AlgorithmRegistry.registerSignatureAlgorithm(RsaSignatureAlgorithm(Digest.SHA256, RsaSignaturePadding.PSS))
private val signatureRsaSha384Pss =
    AlgorithmRegistry.registerSignatureAlgorithm(RsaSignatureAlgorithm(Digest.SHA384, RsaSignaturePadding.PSS))
private val signatureRsaSha512Pss =
    AlgorithmRegistry.registerSignatureAlgorithm(RsaSignatureAlgorithm(Digest.SHA512, RsaSignaturePadding.PSS))

val SignatureAlgorithm.Companion.ECDSA_SHA256: EcdsaSignatureAlgorithm get() = signatureEcdsaSha256 as EcdsaSignatureAlgorithm
val SignatureAlgorithm.Companion.ECDSA_SHA384: EcdsaSignatureAlgorithm get() = signatureEcdsaSha384 as EcdsaSignatureAlgorithm
val SignatureAlgorithm.Companion.ECDSA_SHA512: EcdsaSignatureAlgorithm get() = signatureEcdsaSha512 as EcdsaSignatureAlgorithm
val SignatureAlgorithm.Companion.RSA_SHA256_PKCS1: RsaSignatureAlgorithm get() = signatureRsaSha256Pkcs1 as RsaSignatureAlgorithm
val SignatureAlgorithm.Companion.RSA_SHA384_PKCS1: RsaSignatureAlgorithm get() = signatureRsaSha384Pkcs1 as RsaSignatureAlgorithm
val SignatureAlgorithm.Companion.RSA_SHA512_PKCS1: RsaSignatureAlgorithm get() = signatureRsaSha512Pkcs1 as RsaSignatureAlgorithm
val SignatureAlgorithm.Companion.RSA_SHA256_PSS: RsaSignatureAlgorithm get() = signatureRsaSha256Pss as RsaSignatureAlgorithm
val SignatureAlgorithm.Companion.RSA_SHA384_PSS: RsaSignatureAlgorithm get() = signatureRsaSha384Pss as RsaSignatureAlgorithm
val SignatureAlgorithm.Companion.RSA_SHA512_PSS: RsaSignatureAlgorithm get() = signatureRsaSha512Pss as RsaSignatureAlgorithm

val RsaSignaturePadding.Companion.PKCS1: RsaSignaturePadding get() = Pkcs1RsaSignaturePadding
val RsaSignaturePadding.Companion.PSS: RsaSignaturePadding get() = PssRsaSignaturePadding

@Deprecated(
    "Use RsaSignaturePadding.",
    ReplaceWith("RsaSignaturePadding")
)
typealias RSAPadding = RsaSignaturePadding

interface SpecializedSignatureAlgorithm : SpecializedDataIntegrityAlgorithm {
    override val algorithm: SignatureAlgorithm
}
