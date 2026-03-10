package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.supreme.signCatching
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.KeyAgreement

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

    protected abstract fun parseFromJca(bytes: ByteArray): Signature.RawByteEncodable

    open class EC internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
              override val publicKey: PublicKey.EC, override val signatureAlgorithm: SignatureAlgorithm.ECDSA)
        : EphemeralSigner(privateKey, config.provider), Signer.ECDSA {

        override fun parseFromJca(bytes: ByteArray) = Signature.EC.parseFromJca(bytes).withCurve(publicKey.curve)

        @SecretExposure
        final override fun exportPrivateKey() = (privateKey as ECPrivateKey).toPrivateKey()

        override suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH) = catching {
            KeyAgreement.getInstance("ECDH").let {
                it.init(privateKey)
                it.doPhase(publicValue.asPublicKey().toJcaPublicKey().getOrThrow(), true)
                it.generateSecret()
            }
        }
    }

    open class RSA internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
                                         override val publicKey: PublicKey.RSA, override val signatureAlgorithm: SignatureAlgorithm.RSA)
        : EphemeralSigner(privateKey, config.provider), Signer.RSA {

        override fun parseFromJca(bytes: ByteArray) = Signature.RSA.parseFromJca(bytes)

        @SecretExposure
        final override fun exportPrivateKey() = (privateKey as RSAPrivateKey).toPrivateKey()
    }
}

internal fun getKPGInstance(alg: String, provider: String? = null) =
    when (provider) {
        null -> KeyPairGenerator.getInstance(alg)
        else -> KeyPairGenerator.getInstance(alg, provider)
    }

internal sealed interface JVMEphemeralKey {
    class EC(pair: KeyPair, digests: Set<Digest?>)
        : EphemeralKeyBase.EC<ECPrivateKey, EphemeralSigner.EC>(EphemeralSigner::EC,
        pair.private as ECPrivateKey, pair.public.toPublicKey().getOrThrow() as PublicKey.EC,
        digests = digests)
    {
        @SecretExposure
        override fun exportPrivateKey() = privateKey.toPrivateKey()
    }

    class RSA(pair: KeyPair, digests: Set<Digest>, paddings: Set<RSAPadding>)
        : EphemeralKeyBase.RSA<RSAPrivateKey, EphemeralSigner.RSA>(EphemeralSigner::RSA,
        pair.private as RSAPrivateKey, pair.public.toPublicKey().getOrThrow() as PublicKey.RSA,
        digests = digests, paddings = paddings)
    {
        @SecretExposure
        override fun exportPrivateKey() = privateKey.toPrivateKey()
    }
}

internal actual fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey =
    when (val alg = configuration._algSpecific.v) {
        is SigningKeyConfiguration.ECConfiguration -> {
            getKPGInstance("EC", configuration.provider).run {
                initialize(ECGenParameterSpec(alg.curve.jcaName))
                generateKeyPair()
            }.let { pair -> JVMEphemeralKey.EC(pair, digests = alg.digests) }
        }
        is SigningKeyConfiguration.RSAConfiguration -> {
            getKPGInstance("RSA", configuration.provider).run {
                initialize(RSAKeyGenParameterSpec(alg.bits, alg.publicExponent.toJavaBigInteger()))
                generateKeyPair()
            }.let { pair -> JVMEphemeralKey.RSA(pair, digests = alg.digests, paddings = alg.paddings) }
        }
    }
