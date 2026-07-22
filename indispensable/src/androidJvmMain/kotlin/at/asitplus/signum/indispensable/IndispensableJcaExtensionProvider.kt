package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import java.security.Signature

object IndispensableJcaExtensionProvider : JcaMappingProvider {
    override fun getJCASignatureInstance(algorithm: SignatureAlgorithm, jcaProvider: String?) = when (algorithm) {
        is SignatureAlgorithm.ECDSA -> when (val digest = algorithm.digest) {
            is WellKnownDigest? -> sigGetInstance("${digest.jcaAlgorithmComponent}withECDSA", jcaProvider)
            else -> null
        }
        is SignatureAlgorithm.RSA -> getRSAPlatformSignatureInstance(algorithm, jcaProvider)
        else -> null
    }

    override fun getJCASignatureInstancePreHashed(algorithm: SignatureAlgorithm, jcaProvider: String?) = when (algorithm) {
        is SignatureAlgorithm.ECDSA ->
            sigGetInstance("NONEwithECDSA", jcaProvider)
        else -> null
    }
}

internal expect fun getRSAPlatformSignatureInstance(algorithm: SignatureAlgorithm.RSA, jcaProvider: String?): Signature?
