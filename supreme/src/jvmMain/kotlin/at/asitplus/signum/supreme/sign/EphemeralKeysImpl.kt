package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.fromJcaPublicKey
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.jcaAlgorithmComponent
import at.asitplus.signum.indispensable.jcaName
import at.asitplus.signum.indispensable.parseFromJca
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.os.SignerConfiguration
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

actual class EphemeralSigningKeyConfiguration internal actual constructor(): SigningKeyConfiguration()
actual class EphemeralSignerConfiguration internal actual constructor(): SignerConfiguration()

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

sealed class AndroidKeyHolder (val privateKey: PrivateKey) {

    class EC internal constructor (privateKey: PrivateKey, publicKey: ECPublicKey,
                                   val digests: Set<Digest?>)
        : AndroidKeyHolder(privateKey), EphemeralKey.EC {
        override val publicKey = CryptoPublicKey.fromJcaPublicKey(publicKey).getOrThrow() as CryptoPublicKey.EC
        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): Signer.ECDSA {
            val config = DSL.resolve(::EphemeralSignerConfiguration, configure).ec.v
            val digest = resolveOption("digest", digests, Digest.entries.asSequence() + sequenceOf<Digest?>(null), config.digestSpecified, config.digest) { it.jcaAlgorithmComponent }
            return AndroidEphemeralSigner.EC(privateKey, publicKey, SignatureAlgorithm.ECDSA(digest, publicKey.curve))
        }
    }
    class RSA internal constructor (privateKey: PrivateKey, publicKey: RSAPublicKey,
                                    val digests: Set<Digest>, val paddings: Set<RSAPadding>)
        : AndroidKeyHolder(privateKey), EphemeralKey.RSA {
        override val publicKey = CryptoPublicKey.fromJcaPublicKey(publicKey).getOrThrow() as CryptoPublicKey.Rsa
        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): Signer.RSA {
            val config = DSL.resolve(::EphemeralSignerConfiguration, configure).rsa.v
            val digest = resolveOption<Digest>("digest", digests, Digest.entries.asSequence(), config.digestSpecified, config.digest, Digest::jcaName)
            val padding = resolveOption<RSAPadding>("padding", paddings, RSAPadding.entries.asSequence(), config.paddingSpecified, config.padding) {
                when (it) {
                    RSAPadding.PKCS1 -> "PKCS1"
                    RSAPadding.PSS -> "PSS"
                }
            }

            return AndroidEphemeralSigner.RSA(privateKey, publicKey, SignatureAlgorithm.RSA(digest, padding))
        }
    }
}

internal actual fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey =
    when (val alg = configuration._algSpecific.v) {
        is SigningKeyConfiguration.ECConfiguration -> {
            KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec(alg.curve.jcaName))
                generateKeyPair()
            }.let { pair ->
                AndroidKeyHolder.EC(
                    pair.private, pair.public as ECPublicKey,
                    digests = alg.digests)
            }
        }
        is SigningKeyConfiguration.RSAConfiguration -> {
            KeyPairGenerator.getInstance("RSA").run {
                initialize(RSAKeyGenParameterSpec(alg.bits, alg.publicExponent.toJavaBigInteger()))
                generateKeyPair()
            }.let { pair ->
                AndroidKeyHolder.RSA(
                    pair.private, pair.public as RSAPublicKey,
                    digests = alg.digests, paddings = alg.paddings)
            }
        }
    }
