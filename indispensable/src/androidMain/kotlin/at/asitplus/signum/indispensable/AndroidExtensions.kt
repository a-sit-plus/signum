package at.asitplus.signum.indispensable

import java.security.Signature


internal actual fun SignatureAlgorithm.RSA.getRSAPlatformSignatureInstance(provider: String?): Signature =
    when (this.padding) {
        SignatureAlgorithm.RSA.Padding.PKCS1 ->
            sigGetInstance("${this.digest.jcaAlgorithmComponent}withRSA", provider)

        SignatureAlgorithm.RSA.Padding.PSS ->
            sigGetInstance("${this.digest.jcaAlgorithmComponent}withRSA/PSS", provider)
    }

