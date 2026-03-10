package at.asitplus.signum.indispensable

import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration

interface RSAPadding : Enumerable {
    object PKCS1 : RSAPadding {
        override fun toString() = "PKCS1"
    }

    object PSS : RSAPadding {
        override fun toString() = "PSS"
    }

    companion object : Enumeration<RSAPadding> {
        private val builtIns = listOf(
            AlgorithmRegistry.registerSignatureRsaPadding(PKCS1),
            AlgorithmRegistry.registerSignatureRsaPadding(PSS),
        )

        override val entries: Iterable<RSAPadding>
            get() {
                builtIns
                return AlgorithmRegistry.signatureRsaPaddings
            }
    }
}

interface SignatureAlgorithm: DataIntegrityAlgorithm {

    open class ECDSA(
        /** The digest to apply to the data, or `null` to directly process the raw data. */
        val digest: Digest?,
        /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
        val requiredCurve: ECCurve?
    ) : SignatureAlgorithm {
        override fun equals(other: Any?): Boolean =
            other is ECDSA && digest == other.digest && requiredCurve == other.requiredCurve

        override fun hashCode(): Int = 31 * (digest?.hashCode() ?: 0) + (requiredCurve?.hashCode() ?: 0)

        override fun toString(): String = buildString {
            append("ECDSA")
            digest?.let { append("with").append(it) }
            requiredCurve?.let { append("@").append(it) }
        }

        companion object : Enumeration<ECDSA> {
            override val entries: Set<ECDSA>
                get() = SignatureAlgorithm.entries.filterIsInstance<ECDSA>().toSet()
        }
    }

    open class RSA(
        /** The digest to apply to the data. */
        val digest: Digest,
        /** The padding to apply to the data. */
        val padding: RSAPadding
    ) : SignatureAlgorithm {
        override fun equals(other: Any?): Boolean =
            other is RSA && digest == other.digest && padding == other.padding

        override fun hashCode(): Int = 31 * digest.hashCode() + padding.hashCode()

        override fun toString(): String = "RSAwith${digest}and$padding"

        companion object : Enumeration<RSA> {
            override val entries: Set<RSA>
                get() = SignatureAlgorithm.entries.filterIsInstance<RSA>().toSet()

        }
    }

    companion object : Enumeration<SignatureAlgorithm> {
        val ECDSAwithSHA256 = AlgorithmRegistry.registerSignatureAlgorithm(ECDSA(Digest.SHA256, null))
        val ECDSAwithSHA384 = AlgorithmRegistry.registerSignatureAlgorithm(ECDSA(Digest.SHA384, null))
        val ECDSAwithSHA512 = AlgorithmRegistry.registerSignatureAlgorithm(ECDSA(Digest.SHA512, null))

        val RSAwithSHA256andPKCS1Padding = AlgorithmRegistry.registerSignatureAlgorithm(RSA(Digest.SHA256, RSAPadding.PKCS1))
        val RSAwithSHA384andPKCS1Padding = AlgorithmRegistry.registerSignatureAlgorithm(RSA(Digest.SHA384, RSAPadding.PKCS1))
        val RSAwithSHA512andPKCS1Padding = AlgorithmRegistry.registerSignatureAlgorithm(RSA(Digest.SHA512, RSAPadding.PKCS1))

        val RSAwithSHA256andPSSPadding = AlgorithmRegistry.registerSignatureAlgorithm(RSA(Digest.SHA256, RSAPadding.PSS))
        val RSAwithSHA384andPSSPadding = AlgorithmRegistry.registerSignatureAlgorithm(RSA(Digest.SHA384, RSAPadding.PSS))
        val RSAwithSHA512andPSSPadding = AlgorithmRegistry.registerSignatureAlgorithm(RSA(Digest.SHA512, RSAPadding.PSS))

        private val builtIns = listOf(
            ECDSAwithSHA256,
            ECDSAwithSHA384,
            ECDSAwithSHA512,
            RSAwithSHA256andPKCS1Padding,
            RSAwithSHA384andPKCS1Padding,
            RSAwithSHA512andPKCS1Padding,
            RSAwithSHA256andPSSPadding,
            RSAwithSHA384andPSSPadding,
            RSAwithSHA512andPSSPadding,
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
    }
}

interface SpecializedSignatureAlgorithm: SpecializedDataIntegrityAlgorithm {
    override val algorithm: SignatureAlgorithm
}
