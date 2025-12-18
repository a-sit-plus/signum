package at.asitplus.signum.supreme.sign

import android.security.keystore.KeyProperties
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.getJCASignatureInstancePreHashed
import at.asitplus.signum.indispensable.jcaName
import at.asitplus.signum.indispensable.parseFromJca
import at.asitplus.signum.indispensable.toCryptoPrivateKey
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.supreme.signCatching
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

actual class EphemeralSigningKeyConfiguration internal actual constructor(): EphemeralSigningKeyConfigurationBase()
actual class EphemeralSignerConfiguration internal actual constructor(): EphemeralSignerConfigurationBase()

sealed class AndroidEphemeralSigner (internal val privateKey: PrivateKey) : Signer {
    override val mayRequireUserUnlock = false
    override suspend fun sign(data: SignatureInput) = signCatching {
        when {
            (data.format == null) -> signatureAlgorithm.getJCASignatureInstance(provider = null)
            (data.format == signatureAlgorithm.preHashedSignatureFormat) -> signatureAlgorithm.getJCASignatureInstancePreHashed(provider = null)
            else -> throw IllegalArgumentException("Input format mismatch: ${data.format} != ${signatureAlgorithm.preHashedSignatureFormat}")
        }.getOrThrow().run {
            initSign(privateKey)
            data.data.forEach(this::update)
            sign().let(::parseFromJca)
        }
    }

    protected abstract fun parseFromJca(bytes: ByteArray): CryptoSignature.RawByteEncodable

    class EC (config: EphemeralSignerConfiguration, privateKey: PrivateKey,
              override val publicKey: CryptoPublicKey.EC, override val signatureAlgorithm: SignatureAlgorithm.ECDSA)
        : AndroidEphemeralSigner(privateKey), Signer.ECDSA {

        override fun parseFromJca(bytes: ByteArray) = CryptoSignature.EC.parseFromJca(bytes).withCurve(publicKey.curve)

        @SecretExposure
        override suspend fun exportPrivateKey() =
            catching { privateKey as ECPrivateKey }.transform(ECPrivateKey::toCryptoPrivateKey)

        override suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH) = catching {
            javax.crypto.KeyAgreement.getInstance("ECDH").also {
                it.init(this.privateKey)
                it.doPhase(publicValue.asCryptoPublicKey().toJcaPublicKey().getOrThrow(), true)
            }.generateSecret()
        }
    }

    class RSA (config: EphemeralSignerConfiguration, privateKey: PrivateKey,
               override val publicKey: CryptoPublicKey.RSA, override val signatureAlgorithm: SignatureAlgorithm.RSA)
        : AndroidEphemeralSigner(privateKey), Signer.RSA {

        override fun parseFromJca(bytes: ByteArray) = CryptoSignature.RSA.parseFromJca(bytes)

        @SecretExposure
        override suspend fun exportPrivateKey() =
            catching { privateKey as RSAPrivateKey }.transform(RSAPrivateKey::toCryptoPrivateKey)
    }
}

internal sealed interface AndroidEphemeralKey {
    class EC(pair: KeyPair, digests: Set<Digest?>)
        : EphemeralKeyBase.EC<ECPrivateKey, AndroidEphemeralSigner.EC>(AndroidEphemeralSigner::EC,
        pair.private as ECPrivateKey, pair.public.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC,
        digests = digests)
    {
        @SecretExposure
        override suspend fun exportPrivateKey() = privateKey.toCryptoPrivateKey()
    }

    class RSA(pair: KeyPair, digests: Set<Digest>, paddings: Set<RSAPadding>)
        : EphemeralKeyBase.RSA<RSAPrivateKey, AndroidEphemeralSigner.RSA>(AndroidEphemeralSigner::RSA,
        pair.private as RSAPrivateKey, pair.public.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.RSA,
        digests = digests, paddings = paddings)
    {
        @SecretExposure
        override suspend fun exportPrivateKey() = privateKey.toCryptoPrivateKey()
    }
}

internal actual suspend fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey =
    when (val alg = configuration._algSpecific.v) {
        is SigningKeyConfiguration.ECConfiguration -> {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC).run {
                initialize(ECGenParameterSpec(alg.curve.jcaName))
                generateKeyPair()
            }.let { pair ->
                AndroidEphemeralKey.EC(pair, alg.digests)
            }
        }
        is SigningKeyConfiguration.RSAConfiguration -> {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA).run {
                initialize(RSAKeyGenParameterSpec(alg.bits, alg.publicExponent.toJavaBigInteger()))
                generateKeyPair()
            }.let { pair ->
                AndroidEphemeralKey.RSA(pair, alg.digests, alg.paddings)
            }
        }
    }
