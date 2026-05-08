package at.asitplus.signum.indispensable

import java.security.Signature


internal actual fun SignatureAlgorithm.RSA.getRSAPlatformSignatureInstance(provider: String?): Signature =
    when (this.parameters) {
        is SignatureAlgorithm.RSA.Parameters.Pkcs1Padded ->
            sigGetInstance("${this.digest.jcaAlgorithmComponent}withRSA", provider)

        is SignatureAlgorithm.RSA.Parameters.PssPadded -> sigGetInstance("RSASSA-PSS", provider).also {
            it.setParameter(this.digest.jcaPSSParams)
        }
    }
