package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.fromJcaPublicKey
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.jcaName
import at.asitplus.signum.indispensable.parseFromJca
import at.asitplus.signum.supreme.os.SignerConfiguration
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

sealed class AndroidEphemeralSigner (private val privateKey: PrivateKey) : Signer {
    override val mayRequireUserUnlock = false
    override suspend fun sign(data: SignatureInput) = catching {
        val alg = if (data.format != null) {
            (signatureAlgorithm as? SignatureAlgorithm.ECDSA).let {
                require (it != null && it.digest == data.format)
                { "Pre-hashed data (format ${data.format}) unsupported for algorithm $signatureAlgorithm" }
            }
            SignatureAlgorithm.ECDSA(digest = null, requiredCurve = null)
        } else signatureAlgorithm
        alg.getJCASignatureInstance(provider = null, isAndroid = false).getOrThrow().run {
            initSign(privateKey)
            data.data.forEach { update(it) }
            sign().let {
                CryptoSignature.parseFromJca(it, alg)
            }
        }
    }
    class EC (privateKey: PrivateKey, override val publicKey: CryptoPublicKey.EC, override val signatureAlgorithm: SignatureAlgorithm.ECDSA)
        : AndroidEphemeralSigner(privateKey), Signer.ECDSA

    class RSA (privateKey: PrivateKey, override val publicKey: CryptoPublicKey.Rsa, override val signatureAlgorithm: SignatureAlgorithm.RSA)
        : AndroidEphemeralSigner(privateKey), Signer.RSA
}

internal actual fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey =
    when (val alg = configuration._algSpecific.v) {
        is SigningKeyConfiguration.ECConfiguration -> {
            KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec(alg.curve.jcaName))
                generateKeyPair()
            }.let { pair ->
                EphemeralKeyBase.EC(AndroidEphemeralSigner::EC,
                    pair.private, CryptoPublicKey.fromJcaPublicKey(pair.public).getOrThrow() as CryptoPublicKey.EC,
                    digests = alg.digests)
            }
        }
        is SigningKeyConfiguration.RSAConfiguration -> {
            KeyPairGenerator.getInstance("RSA").run {
                initialize(RSAKeyGenParameterSpec(alg.bits, alg.publicExponent.toJavaBigInteger()))
                generateKeyPair()
            }.let { pair ->
                EphemeralKeyBase.RSA(AndroidEphemeralSigner::RSA,
                    pair.private, CryptoPublicKey.fromJcaPublicKey(pair.public).getOrThrow() as CryptoPublicKey.Rsa,
                    digests = alg.digests, paddings = alg.paddings)
            }
        }
    }
