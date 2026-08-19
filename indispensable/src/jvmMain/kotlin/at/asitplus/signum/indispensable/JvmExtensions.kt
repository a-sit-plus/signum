package at.asitplus.signum.indispensable

import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.RSAAlgorithm


internal actual fun getRSAPlatformSignatureInstance(algorithm: RSAAlgorithm, jcaProvider: String?) =
    when (val params = algorithm.parameters) {
        is RSAAlgorithm.Parameters.Pkcs1Padded -> when (val digest = params.digest) {
            is WellKnownDigest -> sigGetInstance("${digest.jcaAlgorithmComponent}withRSA", jcaProvider)
            else -> null
        }

        is RSAAlgorithm.Parameters.PssPadded -> {
            val params = try { params.jcaPSSParams } catch (_: UnsupportedCryptoException) { null }
            if (params != null) {
                sigGetInstance("RSASSA-PSS", jcaProvider).also { it.setParameter(params) }
            } else null
        }
    }
