package at.asitplus.signum.indispensable

import java.security.Signature

internal actual fun RsaSignatureAlgorithm.getRSAPlatformSignatureInstance(provider: String?): Signature =
    when (this.padding) {
        RsaSignaturePadding.PKCS1 ->
            sigGetInstance("${this.digest.jcaAlgorithmComponent}withRSA", provider)

        RsaSignaturePadding.PSS -> sigGetInstance("RSASSA-PSS", provider).also {
            it.setParameter(this.digest.jcaPSSParams)
        }

        else -> error("Unsupported RSA signature padding ${this.padding}")
    }
