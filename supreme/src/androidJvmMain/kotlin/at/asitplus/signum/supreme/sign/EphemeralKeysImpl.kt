package at.asitplus.signum.supreme.sign

import at.asitplus.signum.dsl.EphemeralECDSAConfiguration
import at.asitplus.signum.dsl.EphemeralRSAConfiguration
import at.asitplus.signum.dsl.EphemeralSignerConfiguration
import at.asitplus.signum.dsl.InMemorySignerConfiguration
import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.JCAProviderRefO
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.jvm
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.internals.ImplementationError
import at.asitplus.signum.dsl.DSL
import at.asitplus.signum.indispensable.agree.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.sign.ExportableECDSASigner
import at.asitplus.signum.indispensable.sign.ECDSASignature
import at.asitplus.signum.indispensable.sign.InMemoryKeysProvider
import at.asitplus.signum.indispensable.sign.RSASignature
import at.asitplus.signum.indispensable.sign.SignatureResult
import at.asitplus.signum.indispensable.sign.Signer
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.KeyAgreement

abstract class SupremeEphemeralJvmSigner (internal val privateKey: PrivateKey, protected val provider: JCAProviderRef) : Signer.WithExportableKey {
    override val mayRequireUserUnlock = false
    override suspend fun sign(data: SignatureInput) = SignatureResult.make {
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

    protected abstract fun parseFromJca(bytes: ByteArray): CryptoSignature

    open class EC internal constructor (privateKey: PrivateKey, provider: JCAProviderRef,
                                        override val publicKey: ECDSAPublicKey, override val signatureAlgorithm: ECDSAAlgorithm
    )
        : SupremeEphemeralJvmSigner(privateKey, provider), ExportableECDSASigner {

        override fun parseFromJca(bytes: ByteArray) =
            ECDSASignature.fromRawSignatureValue(bytes).withCurve(publicKey.curve)

        @SecretExposure
        final override suspend fun exportPrivateKey() = (privateKey as ECPrivateKey).toCryptoPrivateKey()

        override suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH): ByteArray =
            when (provider) {
                is JCAProviderRef.ByName -> KeyAgreement.getInstance("ECDH", provider.provider)
                is JCAProviderRefO -> KeyAgreement.getInstance("ECDH", provider.provider)
                is JCAProviderRef.None -> KeyAgreement.getInstance("ECDH")
                else -> throw ImplementationError("invalid JCAProvider ref")
            }.run {
                init(privateKey)
                doPhase(publicValue.asCryptoPublicKey().toJcaPublicKey(), true)
                generateSecret()
            }
    }

    open class RSA internal constructor (privateKey: PrivateKey, provider: JCAProviderRef,
                                         override val publicKey: RSAPublicKey, override val signatureAlgorithm: RSAAlgorithm
    )
        : SupremeEphemeralJvmSigner(privateKey, provider), at.asitplus.signum.indispensable.sign.ExportableRSASigner {

        override fun parseFromJca(bytes: ByteArray) = RSASignature.fromRawSignatureValue(bytes)

        @SecretExposure
        final override suspend fun exportPrivateKey() = (privateKey as RSAPrivateKey).toCryptoPrivateKey()
    }
}

internal fun getKPGInstance(alg: String, provider: JCAProviderRef) =
    when (provider) {
        is JCAProviderRef.ByName -> KeyPairGenerator.getInstance(alg, provider.provider)
        is JCAProviderRefO -> KeyPairGenerator.getInstance(alg, provider.provider)
        is JCAProviderRef.None -> KeyPairGenerator.getInstance(alg)
        else -> throw ImplementationError("invalid JCAProvider ref")
    }

object SupremeJVMInMemoryKeysProvider : InMemoryKeysProvider {
    override suspend fun makeEphemeralSigner(config: EphemeralSignerConfiguration) : SupremeEphemeralJvmSigner? =
        when (val alg = DSL.options(config.ec, config.rsa)) {
            is EphemeralECDSAConfiguration ->
                getKPGInstance("EC", config.jvm.v.provider).run {
                    initialize(ECGenParameterSpec(alg.curve.jcaName))
                    generateKeyPair()
                }.let { pair ->
                    SupremeEphemeralJvmSigner.EC(
                        privateKey = pair.private, provider = config.jvm.v.provider,
                        publicKey = pair.public.toCryptoPublicKey() as ECDSAPublicKey,
                        signatureAlgorithm = ECDSAAlgorithm(alg.digest, alg.curve))
                }
            is EphemeralRSAConfiguration ->
                getKPGInstance("RSA", config.jvm.v.provider).run {
                    initialize(RSAKeyGenParameterSpec(alg.bits, RSAKeyGenParameterSpec.F4))
                    generateKeyPair()
                }.let { pair ->
                    SupremeEphemeralJvmSigner.RSA(
                        privateKey = pair.private, provider = config.jvm.v.provider,
                        publicKey = pair.public.toCryptoPublicKey() as RSAPublicKey,
                        signatureAlgorithm = RSAAlgorithm(alg.padding, alg.digest))
                }
            else -> null
        }

    override fun createSignerForKey(
        algorithm: SignatureAlgorithm,
        privateKey: CryptoPrivateKey.WithPublicKey,
        config: InMemorySignerConfiguration
    ): Signer.WithExportableKey? =
        when (algorithm) {
            is RSAAlgorithm -> {
                require(privateKey is at.asitplus.signum.indispensable.sign.RSAPrivateKey)
                    { "Trying to use a non-RSA private key (${privateKey::class.simpleName}) with $algorithm" }
                return SupremeEphemeralJvmSigner.RSA(
                    privateKey.toJcaPrivateKey(), config.jvm.v.provider, privateKey.publicKey, algorithm)
            }
            is ECDSAAlgorithm -> {
                require(privateKey is ECDSAPrivateKey.WithPublicKey)
                    { "Trying to use a non-ECDSA private key (${privateKey::class.simpleName}) with $algorithm" }
                return SupremeEphemeralJvmSigner.EC(
                    privateKey.toJcaPrivateKey(), config.jvm.v.provider, privateKey.publicKey, algorithm)
            }
            else -> null
        }
}
