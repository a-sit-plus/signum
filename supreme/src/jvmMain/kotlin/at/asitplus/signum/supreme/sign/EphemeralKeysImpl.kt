package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.EphemeralSigningKeyConfiguration
import at.asitplus.signum.dsl.EphemeralSigningKeyConfigurationBase
import at.asitplus.signum.dsl.JvmEphemeralSignerCompatibleConfiguration
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.supreme.dsl.DSL
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

sealed class EphemeralSigner (internal val privateKey: PrivateKey, private val provider: String?) : Signer {
    override val mayRequireUserUnlock = false
    override suspend fun sign(data: SignatureInput) = signCatching {
        val preHashed = (data.format != null)
        if (preHashed) {
            require (data.format == signatureAlgorithm.preHashedSignatureFormat)
            { "Pre-hashed data (format ${data.format}) unsupported for algorithm $signatureAlgorithm" }
        }
        (if (preHashed)
            signatureAlgorithm.getJCASignatureInstancePreHashed(provider = provider)
        else
            signatureAlgorithm.getJCASignatureInstance(provider = provider))
        .run {
            initSign(privateKey)
            data.data.forEach { update(it) }
            sign().let(::parseFromJca)
        }
    }

    protected abstract fun parseFromJca(bytes: ByteArray): CryptoSignature.RawByteEncodable

    open class EC internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
                                        override val publicKey: CryptoPublicKey.EC, override val signatureAlgorithm: SignatureAlgorithm.ECDSA)
        : EphemeralSigner(privateKey, config.provider), Signer.ECDSA {

        override fun parseFromJca(bytes: ByteArray) = CryptoSignature.EC.parseFromJca(bytes).withCurve(publicKey.curve)

        @SecretExposure
        final override suspend fun exportPrivateKey() = (privateKey as ECPrivateKey).toCryptoPrivateKey()

        override suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH) = catching {
            KeyAgreement.getInstance("ECDH").let {
                it.init(privateKey)
                it.doPhase(publicValue.asCryptoPublicKey().toJcaPublicKey(), true)
                it.generateSecret()
            }
        }
    }

    open class RSA internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
                                         override val publicKey: CryptoPublicKey.RSA, override val signatureAlgorithm: SignatureAlgorithm.RSA)
        : EphemeralSigner(privateKey, config.provider), Signer.RSA {

        override fun parseFromJca(bytes: ByteArray) = CryptoSignature.RSA.parseFromJca(bytes)

        @SecretExposure
        final override suspend fun exportPrivateKey() = (privateKey as RSAPrivateKey).toCryptoPrivateKey()
    }
}

internal fun getKPGInstance(alg: String, provider: String? = null) =
    when (provider) {
        null -> KeyPairGenerator.getInstance(alg)
        else -> KeyPairGenerator.getInstance(alg, provider)
    }

internal sealed interface JVMEphemeralKey {
    class ECDSA(pair: KeyPair, digests: Set<Digest?>)
        : EphemeralKeyBase.ECDSA<ECPrivateKey, EphemeralSigner.EC>(EphemeralSigner::EC,
        pair.private as ECPrivateKey, pair.public.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC,
        digests = digests)
    {
        @SecretExposure
        override suspend fun exportPrivateKey() = privateKey.toCryptoPrivateKey()
    }

    class RSA(pair: KeyPair, digests: Set<Digest>, paddings: Set<RSAAlgorithm.Padding>)
        : EphemeralKeyBase.RSA<RSAPrivateKey, EphemeralSigner.RSA>(EphemeralSigner::RSA,
        pair.private as RSAPrivateKey, pair.public.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.RSA,
        digests = digests, paddings = paddings)
    {
        @SecretExposure
        override suspend fun exportPrivateKey() = privateKey.toCryptoPrivateKey()
    }
}

internal actual suspend fun makeEphemeralKeyImpl(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey? {
    return when (val alg = DSL.options(configuration.ec, configuration.rsa)) {
        is EphemeralSigningKeyConfigurationBase.ECConfiguration ->
            getKPGInstance("EC", configuration.provider).run {
                initialize(ECGenParameterSpec(alg.curve.jcaName))
                generateKeyPair()
            }.let { pair -> JVMEphemeralKey.ECDSA(pair, digests = alg.digests) }
        is EphemeralSigningKeyConfigurationBase.RSAConfiguration ->
            getKPGInstance("RSA", configuration.provider).run {
                initialize(RSAKeyGenParameterSpec(alg.bits, alg.publicExponent.toJavaBigInteger()))
                generateKeyPair()
            }.let { pair -> JVMEphemeralKey.RSA(pair, digests = alg.digests, paddings = alg.paddings) }
        else -> null
    }
}
