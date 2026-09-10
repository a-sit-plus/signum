package at.asitplus.signum.indispensable

import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.JCAProviderRefO
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.RsaPrivateKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaSignature
import at.asitplus.signum.internals.ImplementationError
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey

/** This is not semantics-aware, but allows fallback for public key/private key parsing based on DER formats */
object FallbackToDERFormat : JcaMappingProvider {
    override fun jcaPublicKeyToCryptoPublicKey(publicKey: PublicKey): CryptoPublicKey? =
        if (publicKey.format?.equals("X.509", ignoreCase = true) == true)
            CryptoPublicKey.decodeFromDer(publicKey.encoded)
        else null

    override fun jcaPrivateKeyToCryptoPrivateKey(privateKey: PrivateKey): CryptoPrivateKey.WithPublicKey? =
        if (privateKey.format?.equals("PKCS#8", ignoreCase = true) == true)
            CryptoPrivateKey.decodeFromDer(privateKey.encoded) as CryptoPrivateKey.WithPublicKey
        else null
}

/** This provides semantics-aware operations for types supported by Indispensable */
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
        is EcdsaAlgorithm -> when (val digest = algorithm.digest) {
            is WellKnownDigest? -> sigGetInstance("${digest.jcaAlgorithmComponent}withECDSA", jcaProviderRef)
            else -> null
        }
        is RsaAlgorithm -> when (val params = algorithm.parameters) {
            is RsaAlgorithm.Parameters.Pkcs1Padded -> when (val digest = params.digest) {
                is WellKnownDigest -> sigGetInstance("${digest.jcaAlgorithmComponent}withRSA", jcaProviderRef)
                else -> null
            }

            is RsaAlgorithm.Parameters.PssPadded -> {
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
        is EcdsaAlgorithm ->
            sigGetInstance("NONEwithECDSA", jcaProviderRef)
        else -> null
    }

    override fun parseJCASignatureBytes(algorithm: SignatureAlgorithm, sigBytes: ByteArray): CryptoSignature? = when (algorithm) {
        is EcdsaAlgorithm -> EcdsaSignature.fromRawSignatureValue(sigBytes)
        is RsaAlgorithm -> RsaSignature.fromRawSignatureValue(sigBytes)
        else -> null
    }

    override fun getJCASignatureBytes(signature: CryptoSignature): ByteArray? = when (signature) {
        is EcdsaSignature, is RsaSignature -> signature.asn1Representation.rawBytes
        else -> null
    }

    override fun cryptoPublicKeyToJcaPublicKey(publicKey: CryptoPublicKey) = when(publicKey) {
        is EcdsaPublicKey -> publicKey.toJcaPublicKey()
        is RsaPublicKey -> publicKey.toJcaPublicKey()
        else -> null
    }

    override fun jcaPublicKeyToCryptoPublicKey(publicKey: PublicKey) = when(publicKey) {
        is java.security.interfaces.RSAPublicKey -> publicKey.toCryptoPublicKey()
        is java.security.interfaces.ECPublicKey -> publicKey.toCryptoPublicKey()
        else -> null
    }

    override fun cryptoPrivateKeyToJcaPrivateKey(privateKey: CryptoPrivateKey) =
        when (privateKey) {
            is RsaPrivateKey -> privateKey.toJcaPrivateKey()
            is EcdsaPrivateKey -> privateKey.toJcaPrivateKey()
            else -> null
        }

    override fun jcaPrivateKeyToCryptoPrivateKey(privateKey: PrivateKey) =
        when (privateKey) {
            is java.security.interfaces.RSAPrivateKey -> privateKey.toCryptoPrivateKey()
            is java.security.interfaces.ECPrivateKey -> privateKey.toCryptoPrivateKey()
            else -> null
        }
}

