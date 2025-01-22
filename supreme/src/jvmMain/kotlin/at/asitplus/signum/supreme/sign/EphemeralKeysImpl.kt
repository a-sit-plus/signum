package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.SecretExposure
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import at.asitplus.signum.supreme.signCatching
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.KeyAgreement


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

    protected abstract fun parseFromJca(bytes: ByteArray): CryptoSignature.RawByteEncodable

    final override suspend fun keyAgreement(publicKey: CryptoPublicKey) = catching {
        KeyAgreement.getInstance(when (this) {
            is EC -> "ECDH"
            is RSA -> "DH"
        }).also {
            it.init(privateKey)
            it.doPhase(publicKey.toJcaPublicKey().getOrThrow(), true)
        }.generateSecret()
    }

    open class EC internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
              override val publicKey: CryptoPublicKey.EC, override val signatureAlgorithm: SignatureAlgorithm.ECDSA)
        : EphemeralSigner(privateKey, config.provider), Signer.ECDSA {

        override fun parseFromJca(bytes: ByteArray) = CryptoSignature.EC.parseFromJca(bytes).withCurve(publicKey.curve)

        @SecretExposure
        final override fun exportPrivateKey() = CryptoPrivateKey.fromJcaPrivateKey(privateKey as ECPrivateKey)
    }

    open class RSA internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
                                         override val publicKey: CryptoPublicKey.RSA, override val signatureAlgorithm: SignatureAlgorithm.RSA)
        : EphemeralSigner(privateKey, config.provider), Signer.RSA {

        override fun parseFromJca(bytes: ByteArray) = CryptoSignature.RSAorHMAC.parseFromJca(bytes)

        @SecretExposure
        final override fun exportPrivateKey() = CryptoPrivateKey.fromJcaPrivateKey(privateKey as RSAPrivateKey)
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
