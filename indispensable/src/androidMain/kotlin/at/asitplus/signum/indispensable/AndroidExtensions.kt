package at.asitplus.signum.indispensable

import java.security.Signature

internal actual fun RsaSignatureAlgorithm.getRSAPlatformSignatureInstance(provider: String?): Signature =
    when (this.padding) {
        RsaSignaturePadding.PKCS1 ->
            sigGetInstance("${this.digest.jcaAlgorithmComponent}withRSA", provider)

        RsaSignaturePadding.PSS ->
            sigGetInstance("${this.digest.jcaAlgorithmComponent}withRSA/PSS", provider)
    }
