@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.key.EcPrivateKey
import at.asitplus.signum.indispensable.key.EcPublicKey
import at.asitplus.signum.indispensable.key.RsaPrivateKey
import at.asitplus.signum.indispensable.key.RsaPublicKey
import at.asitplus.signum.indispensable.signature.EcSignature
import at.asitplus.signum.indispensable.signature.RsaSignature
import at.asitplus.signum.indispensable.PrivateKey as CryptoPrivateKey
import at.asitplus.signum.indispensable.PublicKey as CryptoPublicKey
import at.asitplus.signum.indispensable.Signature as CryptoSignature
import at.asitplus.signum.internals.*
import at.asitplus.signum.supreme.*
import kotlinx.cinterop.*
import platform.CoreFoundation.CFRelease
import platform.Foundation.NSData
import platform.Security.*

actual class EphemeralSigningKeyConfiguration internal actual constructor() : EphemeralSigningKeyConfigurationBase()
actual class EphemeralSignerConfiguration internal actual constructor() : EphemeralSignerConfigurationBase()

internal fun performKeyAgreement(privateKey: SecKeyRef?, publicValue: KeyAgreementPublicValue.ECDH) =
    corecall {
        platform.Security.SecKeyCopyKeyExchangeResult(
            privateKey,
            platform.Security.kSecKeyAlgorithmECDHKeyExchangeStandard,
            publicValue.asCryptoPublicKey().toSecKey().getOrThrow().value,
            parameters = null,
            error
        )
    }.takeFromCF<NSData>().toByteArray()

sealed class EphemeralSigner(internal val privateKey: OwnedCFValue<SecKeyRef>) : Signer {
    final override val mayRequireUserUnlock: Boolean get() = false
    final override suspend fun sign(data: SignatureInput) = signCatching {
        val inputData = data.convertTo(signatureAlgorithm.preHashedSignatureFormat).getOrThrow()
        val algorithm = signatureAlgorithm.secKeyAlgorithmPreHashed
        val input = inputData.data.single().toNSData()
        val signatureBytes = corecall {
            SecKeyCreateSignature(privateKey.value, algorithm, input.let(::giveToCF), error)
        }.takeFromCF<NSData>().toByteArray()
        return@signCatching when (val pubkey = publicKey) {
            is EcPublicKey -> EcSignature.decodeFromDer(signatureBytes).withCurve(pubkey.curve)
            is RsaPublicKey -> RsaSignature(signatureBytes)
            else -> throw UnsupportedCryptoException("Unsupported public key $pubkey")
        }
    }

    class EC internal constructor(
        config: EphemeralSignerConfiguration, privateKey: OwnedCFValue<SecKeyRef>,
        override val publicKey: EcPublicKey, override val signatureAlgorithm: SignatureAlgorithm.ECDSA
    ) : EphemeralSigner(privateKey), Signer.ECDSA {
        @SecretExposure
        override fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey().mapCatching { it as EcPrivateKey.WithPublicKey }

        override suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH) = catching {
            performKeyAgreement(privateKey.value, publicValue)
        }
    }

    class RSA internal constructor(
        config: EphemeralSignerConfiguration, privateKey: OwnedCFValue<SecKeyRef>,
        override val publicKey: RsaPublicKey, override val signatureAlgorithm: RsaSignatureAlgorithm
    ) : EphemeralSigner(privateKey), Signer.RSA {
        @SecretExposure
        override fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey().mapCatching { it as RsaPrivateKey }
    }
}

internal sealed interface IosEphemeralKey {
    class EC(privateKey: OwnedCFValue<SecKeyRef>, publicKey: EcPublicKey, digests: Set<Digest?>)
        : EphemeralKeyBase.EC<OwnedCFValue<SecKeyRef>, EphemeralSigner.EC>(EphemeralSigner::EC, privateKey, publicKey, digests)
    {
        @SecretExposure
        override fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey().mapCatching { it as EcPrivateKey.WithPublicKey }
    }

    class RSA(privateKey: OwnedCFValue<SecKeyRef>, publicKey: RsaPublicKey, digests: Set<Digest>, paddings: Set<RSAPadding>)
        : EphemeralKeyBase.RSA<OwnedCFValue<SecKeyRef>, EphemeralSigner.RSA>(EphemeralSigner::RSA, privateKey, publicKey, digests, paddings)
    {
        @SecretExposure
        override fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey().mapCatching { it as RsaPrivateKey }
    }
}

internal actual fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration): EphemeralKey {
    memScoped {
        val attr = createCFDictionary {
            when (val alg = configuration._algSpecific.v) {
                is SigningKeyConfiguration.ECConfiguration -> {
                    kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
                    kSecAttrKeySizeInBits mapsTo alg.curve.coordinateLength.bits.toInt()
                }

                is SigningKeyConfiguration.RSAConfiguration -> {
                    kSecAttrKeyType mapsTo kSecAttrKeyTypeRSA
                    kSecAttrKeySizeInBits mapsTo alg.bits
                }
            }
            kSecPrivateKeyAttrs mapsTo cfDictionaryOf(kSecAttrIsPermanent to false)
            kSecPublicKeyAttrs mapsTo cfDictionaryOf(kSecAttrIsPermanent to false)
        }
        val privateKey = corecall {
            SecKeyCreateRandomKey(attr, error)
        }.manage()
        val pubkeyBytes = SecKeyCopyPublicKey(privateKey.value).also { defer { CFRelease(it) } }
        .let {
            corecall {
                SecKeyCopyExternalRepresentation(it, error)
            }
        }.takeFromCF<NSData>().toByteArray()

        return when (val alg = configuration._algSpecific.v) {
            is SigningKeyConfiguration.ECConfiguration ->
                IosEphemeralKey.EC(
                    privateKey,
                    EcPublicKey.fromAnsiX963Bytes(alg.curve, pubkeyBytes),
                    alg.digests
                )

            is SigningKeyConfiguration.RSAConfiguration ->
                IosEphemeralKey.RSA(
                    privateKey,
                    RsaPublicKey.fromPKCS1encoded(pubkeyBytes),
                    alg.digests,
                    alg.paddings
                )
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
actual fun makePrivateKeySigner(
    key: RsaPrivateKey,
    algorithm: RsaSignatureAlgorithm
): Signer.RSA =
    key.toSecKey().mapCatching { EphemeralSigner.RSA(EphemeralSignerConfiguration(), it, key.publicKey, algorithm) }.getOrThrow()

@OptIn(ExperimentalForeignApi::class)
actual fun makePrivateKeySigner(
    key: EcPrivateKey.WithPublicKey,
    algorithm: EcdsaSignatureAlgorithm
): Signer.ECDSA =
    key.toSecKey().mapCatching { EphemeralSigner.EC(EphemeralSignerConfiguration(), it, key.publicKey, algorithm) }.getOrThrow()
