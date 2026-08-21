package at.asitplus.signum.indispensable

import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.JCAProviderRefO
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.internals.ImplementationError
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey

object IndispensableJcaExtensionProvider : JcaMappingProvider {
    override fun getJCAMessageDigestInstance(digest: Digest, jcaProviderRef: JCAProviderRef): MessageDigest? {
        if (digest !is WellKnownDigest) return null
        return when (jcaProviderRef) {
            is JCAProviderRef.ByName -> MessageDigest.getInstance(digest.jcaName, jcaProviderRef.provider)
            is JCAProviderRefO -> MessageDigest.getInstance(digest.jcaName, jcaProviderRef.provider)
            is JCAProviderRef.None -> MessageDigest.getInstance(digest.jcaName)
            else -> throw ImplementationError("invalid JCAProvider ref")
        }
    }

    override fun getJCASignatureInstance(algorithm: SignatureAlgorithm, jcaProviderRef: JCAProviderRef) = when (algorithm) {
        is ECDSAAlgorithm -> when (val digest = algorithm.digest) {
            is WellKnownDigest? -> sigGetInstance("${digest.jcaAlgorithmComponent}withECDSA", jcaProviderRef)
            else -> null
        }
        is RSAAlgorithm -> when (val params = algorithm.parameters) {
            is RSAAlgorithm.Parameters.Pkcs1Padded -> when (val digest = params.digest) {
                is WellKnownDigest -> sigGetInstance("${digest.jcaAlgorithmComponent}withRSA", jcaProviderRef)
                else -> null
            }

            is RSAAlgorithm.Parameters.PssPadded -> {
                val jcaParams = params.jcaPSSParams
                try {
                    sigGetInstance("RSASSA-PSS", jcaProviderRef)
                } catch (x: NoSuchAlgorithmException) {
                    try {
                        sigGetInstance("${(params.digest as WellKnownDigest).jcaAlgorithmComponent}withRSA/PSS", jcaProviderRef)
                    } catch (x2: NoSuchAlgorithmException) {
                        throw NoSuchAlgorithmException("${x.message}; ${x2.message}.")
                    }
                }.also { it.setParameter(jcaParams) }
            }
        }
        else -> null
    }

    override fun getJCASignatureInstancePreHashed(algorithm: SignatureAlgorithm, jcaProviderRef: JCAProviderRef) = when (algorithm) {
        is ECDSAAlgorithm ->
            sigGetInstance("NONEwithECDSA", jcaProviderRef)
        else -> null
    }

    override fun cryptoPublicKeyToJcaPublicKey(publicKey: CryptoPublicKey) = when(publicKey) {
        is ECDSAPublicKey -> publicKey.toJcaPublicKey()
        is RSAPublicKey -> publicKey.toJcaPublicKey()
        else -> null
    }

    override fun jcaPublicKeyToCryptoPublicKey(publicKey: PublicKey) = when(publicKey) {
        is java.security.interfaces.RSAPublicKey -> publicKey.toCryptoPublicKey()
        is java.security.interfaces.ECPublicKey -> publicKey.toCryptoPublicKey()
        else -> null
    }

    override fun cryptoPrivateKeyToJcaPrivateKey(privateKey: CryptoPrivateKey) =
        when (privateKey) {
            is RSAPrivateKey -> privateKey.toJcaPrivateKey()
            is ECDSAPrivateKey -> privateKey.toJcaPrivateKey()
            else -> null
        }

    override fun jcaPrivateKeyToCryptoPrivateKey(privateKey: PrivateKey) =
        when (privateKey) {
            is java.security.interfaces.RSAPrivateKey -> privateKey.toCryptoPrivateKey()
            is java.security.interfaces.ECPrivateKey -> privateKey.toCryptoPrivateKey()
            else -> null
        }
}

