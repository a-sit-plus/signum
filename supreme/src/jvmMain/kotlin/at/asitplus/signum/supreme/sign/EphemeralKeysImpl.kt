package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.fromJcaPublicKey
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.getJCASignatureInstancePreHashed
import at.asitplus.signum.indispensable.jcaName
import at.asitplus.signum.indispensable.parseFromJca
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

actual class EphemeralSigningKeyConfiguration internal actual constructor(): EphemeralSigningKeyConfigurationBase() {
    var provider: String? = null
}
interface JvmEphemeralSignerCompatibleConfiguration {
    var provider: String?
}
actual class EphemeralSignerConfiguration internal actual constructor(): EphemeralSignerConfigurationBase(), JvmEphemeralSignerCompatibleConfiguration {
    override var provider: String? = null
}

sealed class EphemeralSigner (internal val privateKey: PrivateKey, private val provider: String?) : Signer {
    override val mayRequireUserUnlock = false
    override suspend fun sign(data: SignatureInput) = catching {
        val preHashed = (data.format != null)
        if (preHashed) {
            require (data.format == when (val alg = signatureAlgorithm) {
                is SignatureAlgorithm.ECDSA -> alg.digest
                is SignatureAlgorithm.RSA -> alg.digest
                else -> TODO("HMAC is unsupported")
            }) { "Pre-hashed data (format ${data.format}) unsupported for algorithm $signatureAlgorithm" }
        }
        (if (preHashed)
            signatureAlgorithm.getJCASignatureInstancePreHashed(provider = provider).getOrThrow()
        else
            signatureAlgorithm.getJCASignatureInstance(provider = provider).getOrThrow())
        .run {
            initSign(privateKey)
            data.data.forEach { update(it) }
            sign().let {
                CryptoSignature.parseFromJca(it, signatureAlgorithm)
            }
        }
    }
    open class EC internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
              override val publicKey: CryptoPublicKey.EC, override val signatureAlgorithm: SignatureAlgorithm.ECDSA)
        : EphemeralSigner(privateKey, config.provider), Signer.ECDSA

    open class RSA internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
               override val publicKey: CryptoPublicKey.Rsa, override val signatureAlgorithm: SignatureAlgorithm.RSA)
        : EphemeralSigner(privateKey, config.provider), Signer.RSA
}

internal fun getKPGInstance(alg: String, provider: String? = null) =
    when (provider) {
        null -> KeyPairGenerator.getInstance(alg)
        else -> KeyPairGenerator.getInstance(alg, provider)
    }

internal actual fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey =
    when (val alg = configuration._algSpecific.v) {
        is SigningKeyConfiguration.ECConfiguration -> {
            getKPGInstance("EC", configuration.provider).run {
                initialize(ECGenParameterSpec(alg.curve.jcaName))
                generateKeyPair()
            }.let { pair ->
                EphemeralKeyBase.EC(EphemeralSigner::EC,
                    pair.private, CryptoPublicKey.fromJcaPublicKey(pair.public).getOrThrow() as CryptoPublicKey.EC,
                    digests = alg.digests)
            }
        }
        is SigningKeyConfiguration.RSAConfiguration -> {
            getKPGInstance("RSA", configuration.provider).run {
                initialize(RSAKeyGenParameterSpec(alg.bits, alg.publicExponent.toJavaBigInteger()))
                generateKeyPair()
            }.let { pair ->
                EphemeralKeyBase.RSA(EphemeralSigner::RSA,
                    pair.private, CryptoPublicKey.fromJcaPublicKey(pair.public).getOrThrow() as CryptoPublicKey.Rsa,
                    digests = alg.digests, paddings = alg.paddings)
            }
        }
    }
