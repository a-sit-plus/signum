package at.asitplus.signum.indispensable

import java.security.Signature


internal actual fun SignatureAlgorithm.RSA.getPlatformSignatureInstance(provider: String?): Signature =
    when (this.padding) {
        RSAPadding.PKCS1 ->
            sigGetInstance("${this.digest.jcaAlgorithmComponent}withRSA", provider)

        RSAPadding.PSS -> sigGetInstance("RSASSA-PSS", provider).also {
            it.setParameter(this.digest.jcaPSSParams)
        }
    }

