@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.*
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
            is CryptoPublicKey.EC -> CryptoSignature.EC.decodeFromDer(signatureBytes).withCurve(pubkey.curve)
            is CryptoPublicKey.RSA -> CryptoSignature.RSA(signatureBytes)
        }
    }

    class EC internal constructor(
        config: EphemeralSignerConfiguration, privateKey: OwnedCFValue<SecKeyRef>,
        override val publicKey: CryptoPublicKey.EC, override val signatureAlgorithm: SignatureAlgorithm.ECDSA
    ) : EphemeralSigner(privateKey), Signer.ECDSA {
        @SecretExposure
        override suspend fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey().mapCatching { it as CryptoPrivateKey.EC.WithPublicKey }

        override suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH) = catching {
            performKeyAgreement(privateKey.value, publicValue)
        }
    }

    class RSA internal constructor(
        config: EphemeralSignerConfiguration, privateKey: OwnedCFValue<SecKeyRef>,
        override val publicKey: CryptoPublicKey.RSA, override val signatureAlgorithm: SignatureAlgorithm.RSA
    ) : EphemeralSigner(privateKey), Signer.RSA {
        @SecretExposure
        override suspend fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey().mapCatching { it as CryptoPrivateKey.RSA }
    }
}

internal sealed interface IosEphemeralKey {
    class EC(privateKey: OwnedCFValue<SecKeyRef>, publicKey: CryptoPublicKey.EC, digests: Set<Digest?>)
        : EphemeralKeyBase.EC<OwnedCFValue<SecKeyRef>, EphemeralSigner.EC>(EphemeralSigner::EC, privateKey, publicKey, digests)
    {
        @SecretExposure
        override suspend fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey().mapCatching { it as CryptoPrivateKey.EC.WithPublicKey }
    }

    class RSA(privateKey: OwnedCFValue<SecKeyRef>, publicKey: CryptoPublicKey.RSA, digests: Set<Digest>, paddings: Set<RSAPadding>)
        : EphemeralKeyBase.RSA<OwnedCFValue<SecKeyRef>, EphemeralSigner.RSA>(EphemeralSigner::RSA, privateKey, publicKey, digests, paddings)
    {
        @SecretExposure
        override suspend fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey().mapCatching { it as CryptoPrivateKey.RSA }
    }
}

internal actual suspend fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration): EphemeralKey {
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
                    CryptoPublicKey.EC.fromAnsiX963Bytes(alg.curve, pubkeyBytes),
                    alg.digests
                )

            is SigningKeyConfiguration.RSAConfiguration ->
                IosEphemeralKey.RSA(
                    privateKey,
                    CryptoPublicKey.RSA.fromPKCS1encoded(pubkeyBytes),
                    alg.digests,
                    alg.paddings
                )
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
actual suspend fun makePrivateKeySigner(
    key: CryptoPrivateKey.RSA,
    algorithm: SignatureAlgorithm.RSA
): Signer.RSA =
    key.toSecKey().mapCatching { EphemeralSigner.RSA(EphemeralSignerConfiguration(), it, key.publicKey, algorithm) }.getOrThrow()

@OptIn(ExperimentalForeignApi::class)
actual suspend fun makePrivateKeySigner(
    key: CryptoPrivateKey.EC.WithPublicKey,
    algorithm: SignatureAlgorithm.ECDSA
): Signer.ECDSA =
    key.toSecKey().mapCatching { EphemeralSigner.EC(EphemeralSignerConfiguration(), it, key.publicKey, algorithm) }.getOrThrow()
