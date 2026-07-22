package at.asitplus.signum.indispensable

import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm

private fun isAndroidStandardMGF(params: SignatureAlgorithm.RSA.Parameters.PssPadded): Boolean {
    val mgf = params.mgfAlgorithm
    if (mgf !is SignatureAlgorithm.RSA.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1) return false
    if (params.digest != mgf.digest) return false
    if (params.saltLength != params.digest.outputLength.bytes) return false
    if (params.trailerField != 1) return false
    return true
}

internal actual fun getRSAPlatformSignatureInstance(algorithm: SignatureAlgorithm.RSA, jcaProvider: String?) =
    when (val params = algorithm.parameters) {
        is SignatureAlgorithm.RSA.Parameters.Pkcs1Padded -> when (val digest = algorithm.digest) {
            is WellKnownDigest -> sigGetInstance("${digest.jcaAlgorithmComponent}withRSA", jcaProvider)
            else -> null
        }

        is SignatureAlgorithm.RSA.Parameters.PssPadded -> {
            val jcaParams = try { params.jcaPSSParams } catch (_: UnsupportedCryptoException) { null }
            if (jcaParams != null) {
                sigGetInstance("${jcaParams.digestAlgorithm}withRSA/PSS", jcaProvider).apply {
                    if (!isAndroidStandardMGF(params)) {
                        setParameter(params.jcaPSSParams)
                    }
                }
            } else null
        }
    }

