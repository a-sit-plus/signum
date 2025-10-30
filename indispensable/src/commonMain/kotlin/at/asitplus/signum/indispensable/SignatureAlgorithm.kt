package at.asitplus.signum.indispensable

import at.asitplus.signum.Enumeration

enum class RSAPadding {
    PKCS1,
    PSS;
}

sealed interface SignatureAlgorithm: DataIntegrityAlgorithm {

    data class ECDSA(
        /** The digest to apply to the data, or `null` to directly process the raw data. */
        val digest: Digest?,
        /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
        val requiredCurve: ECCurve?
    ) : SignatureAlgorithm {

        companion object : Enumeration<ECDSA> {
            override val entries: Set<ECDSA> by lazy {
                setOf(
                    ECDSAwithSHA256,
                    ECDSAwithSHA384,
                    ECDSAwithSHA512
                )
            }
        }
    }

    data class RSA(
        /** The digest to apply to the data. */
        val digest: Digest,
        /** The padding to apply to the data. */
        val padding: RSAPadding
    ) : SignatureAlgorithm {

        companion object : Enumeration<RSA> {
            override val entries: Set<RSA> by lazy {
                setOf(
                    RSAwithSHA256andPSSPadding,
                    RSAwithSHA384andPSSPadding,
                    RSAwithSHA512andPSSPadding,

                    RSAwithSHA256andPKCS1Padding,
                    RSAwithSHA384andPKCS1Padding,
                    RSAwithSHA512andPKCS1Padding
                )
            }

        }
    }

    companion object : Enumeration<SignatureAlgorithm> {
        val ECDSAwithSHA256 = ECDSA(Digest.SHA256, null)
        val ECDSAwithSHA384 = ECDSA(Digest.SHA384, null)
        val ECDSAwithSHA512 = ECDSA(Digest.SHA512, null)

        val RSAwithSHA256andPKCS1Padding = RSA(Digest.SHA256, RSAPadding.PKCS1)
        val RSAwithSHA384andPKCS1Padding = RSA(Digest.SHA384, RSAPadding.PKCS1)
        val RSAwithSHA512andPKCS1Padding = RSA(Digest.SHA512, RSAPadding.PKCS1)

        val RSAwithSHA256andPSSPadding = RSA(Digest.SHA256, RSAPadding.PSS)
        val RSAwithSHA384andPSSPadding = RSA(Digest.SHA384, RSAPadding.PSS)
        val RSAwithSHA512andPSSPadding = RSA(Digest.SHA512, RSAPadding.PSS)

        override val entries: Set<SignatureAlgorithm> by lazy {
            ECDSA.entries + RSA.entries
        }

    }
}

interface SpecializedSignatureAlgorithm: SpecializedDataIntegrityAlgorithm {
    override val algorithm: SignatureAlgorithm
}
