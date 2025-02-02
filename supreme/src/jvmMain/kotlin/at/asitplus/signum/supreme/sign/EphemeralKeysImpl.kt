package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.fromJcaPublicKey
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.getJCASignatureInstancePreHashed
import at.asitplus.signum.indispensable.jcaName
import at.asitplus.signum.indispensable.parseFromJca
import at.asitplus.signum.supreme.SecretExposure
import at.asitplus.signum.supreme.signCatching
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec


@SecretExposure
internal actual fun EphemeralKeyBase<*>.exportPrivate(): CryptoPrivateKey.WithPublicKey<*> =
    CryptoPrivateKey.decodeFromDer((privateKey as PrivateKey).encoded) as CryptoPrivateKey.WithPublicKey<*>


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
    override suspend fun sign(data: SignatureInput) = signCatching {
        val preHashed = (data.format != null)
        if (preHashed) {
            require (data.format == signatureAlgorithm.preHashedSignatureFormat)
            { "Pre-hashed data (format ${data.format}) unsupported for algorithm $signatureAlgorithm" }
        }
        (if (preHashed)
            signatureAlgorithm.getJCASignatureInstancePreHashed(provider = provider).getOrThrow()
        else
            signatureAlgorithm.getJCASignatureInstance(provider = provider).getOrThrow())
        .run {
            initSign(privateKey)
            data.data.forEach { update(it) }
            sign().let(::parseFromJca)
        }
    }

    @SecretExposure
    override fun exportPrivateKey(): KmmResult<CryptoPrivateKey.WithPublicKey<*>> = catching { CryptoPrivateKey.decodeFromDer(
        privateKey.encoded) as CryptoPrivateKey.WithPublicKey<*> }

    protected abstract fun parseFromJca(bytes: ByteArray): CryptoSignature.RawByteEncodable

    open class EC internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
              override val publicKey: CryptoPublicKey.EC, override val signatureAlgorithm: SignatureAlgorithm.ECDSA)
        : EphemeralSigner(privateKey, config.provider), Signer.ECDSA {

        override fun parseFromJca(bytes: ByteArray) = CryptoSignature.EC.parseFromJca(bytes).withCurve(publicKey.curve)
    }

    open class RSA internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
                                         override val publicKey: CryptoPublicKey.RSA, override val signatureAlgorithm: SignatureAlgorithm.RSA)
        : EphemeralSigner(privateKey, config.provider), Signer.RSA {

        override fun parseFromJca(bytes: ByteArray) = CryptoSignature.RSA.parseFromJca(bytes)
    }
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
                    pair.private, CryptoPublicKey.fromJcaPublicKey(pair.public).getOrThrow() as CryptoPublicKey.RSA,
                    digests = alg.digests, paddings = alg.paddings)
            }
        }
    }
