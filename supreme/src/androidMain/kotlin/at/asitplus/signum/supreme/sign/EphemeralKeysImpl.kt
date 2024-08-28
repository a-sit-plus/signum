package at.asitplus.signum.supreme.sign

import android.security.keystore.KeyProperties
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.fromJcaPublicKey
import at.asitplus.signum.indispensable.getJCASignatureInstancePreHashed
import at.asitplus.signum.indispensable.jcaName
import at.asitplus.signum.indispensable.parseFromJca
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

actual class EphemeralSigningKeyConfiguration internal actual constructor(): EphemeralSigningKeyConfigurationBase()
actual class EphemeralSignerConfiguration internal actual constructor(): EphemeralSignerConfigurationBase()

sealed class AndroidEphemeralSigner (internal val privateKey: PrivateKey) : Signer {
    override val mayRequireUserUnlock = false
    override suspend fun sign(data: SignatureInput) = catching {
        val inputData = data.convertTo(when (val alg = signatureAlgorithm) {
            is SignatureAlgorithm.RSA -> alg.digest
            is SignatureAlgorithm.ECDSA -> alg.digest
            else -> TODO("hmac unsupported")
        }).getOrThrow()
        signatureAlgorithm.getJCASignatureInstancePreHashed(provider = null, isAndroid = true).getOrThrow().run {
            initSign(privateKey)
            inputData.data.forEach { update(it) }
            sign().let {
                CryptoSignature.parseFromJca(it, signatureAlgorithm)
            }
        }
    }
    class EC (config: EphemeralSignerConfiguration, privateKey: PrivateKey,
              override val publicKey: CryptoPublicKey.EC, override val signatureAlgorithm: SignatureAlgorithm.ECDSA)
        : AndroidEphemeralSigner(privateKey), Signer.ECDSA

    class RSA (config: EphemeralSignerConfiguration, privateKey: PrivateKey,
               override val publicKey: CryptoPublicKey.Rsa, override val signatureAlgorithm: SignatureAlgorithm.RSA)
        : AndroidEphemeralSigner(privateKey), Signer.RSA
}

internal actual fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey =
    when (val alg = configuration._algSpecific.v) {
        is SigningKeyConfiguration.ECConfiguration -> {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC).run {
                initialize(ECGenParameterSpec(alg.curve.jcaName))
                generateKeyPair()
            }.let { pair ->
                EphemeralKeyBase.EC(AndroidEphemeralSigner::EC,
                    pair.private, CryptoPublicKey.fromJcaPublicKey(pair.public).getOrThrow() as CryptoPublicKey.EC,
                    digests = alg.digests)
            }
        }
        is SigningKeyConfiguration.RSAConfiguration -> {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA).run {
                initialize(RSAKeyGenParameterSpec(alg.bits, alg.publicExponent.toJavaBigInteger()))
                generateKeyPair()
            }.let { pair ->
                EphemeralKeyBase.RSA(AndroidEphemeralSigner::RSA,
                    pair.private, CryptoPublicKey.fromJcaPublicKey(pair.public) as CryptoPublicKey.Rsa,
                    digests = alg.digests, paddings = alg.paddings)
            }
        }
    }
