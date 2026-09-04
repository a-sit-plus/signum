@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.supreme.sign

import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.signum.dsl.EphemeralECDSAConfiguration
import at.asitplus.signum.dsl.EphemeralRSAConfiguration
import at.asitplus.signum.dsl.EphemeralSignerConfiguration
import at.asitplus.signum.dsl.InMemorySignerConfiguration
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.ECDSASignature
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.indispensable.sign.RSASignature
import at.asitplus.signum.internals.*
import at.asitplus.signum.dsl.DSL
import at.asitplus.signum.indispensable.agree.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.sign.InMemoryKeysProvider
import at.asitplus.signum.indispensable.sign.SignatureResult
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.toSecKey
import at.asitplus.signum.internals.corecall
import at.asitplus.signum.internals.takeFromCF
import at.asitplus.signum.internals.toByteArray
import kotlinx.cinterop.*
import platform.CoreFoundation.CFRelease
import platform.Foundation.NSData
import platform.Security.*
import platform.Security.SecKeyCopyKeyExchangeResult
import platform.Security.kSecKeyAlgorithmECDHKeyExchangeStandard

sealed class SupremeIosEphemeralSigner(internal val privateKey: OwnedCFValue<SecKeyRef>) : Signer.WithExportableKey {
    final override val mayRequireUserUnlock: Boolean get() = false
    final override suspend fun sign(data: SignatureInput) = SignatureResult.make {
        val (algorithm, format) = signatureAlgorithm.suitableSecKeyAlgAndFormat
        val input = data.convertTo(format).collapsed().data.single().toNSData()
        val signatureBytes = corecall {
            SecKeyCreateSignature(privateKey.value, algorithm, input.giveToCF(), error)
        }.takeFromCF<NSData>().toByteArray()
        return@make parseSignature(signatureBytes)
    }

    protected abstract fun parseSignature(signatureBytes: ByteArray): CryptoSignature

    class EC internal constructor(
        privateKey: OwnedCFValue<SecKeyRef>, override val publicKey: ECDSAPublicKey,
        override val signatureAlgorithm: ECDSAAlgorithm
    ) : SupremeIosEphemeralSigner(privateKey), Signer.WithExportableKey.ECDSA {
        @SecretExposure
        override suspend fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey() as ECDSAPrivateKey.WithPublicKey

        override fun parseSignature(signatureBytes: ByteArray) =
            ECDSASignature.decodeFromTlv(X509SignatureValue(signatureBytes)).withCurve(publicKey.curve)

        override suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH): ByteArray =
            corecall {
                SecKeyCopyKeyExchangeResult(
                    privateKey.value,
                    kSecKeyAlgorithmECDHKeyExchangeStandard,
                    publicValue.asCryptoPublicKey().toSecKey().value,
                    parameters = null,
                    error
                )
            }.takeFromCF<NSData>().toByteArray()
    }

    class RSA internal constructor(
        privateKey: OwnedCFValue<SecKeyRef>, override val publicKey: RSAPublicKey,
        override val signatureAlgorithm: RSAAlgorithm
    ) : SupremeIosEphemeralSigner(privateKey), Signer.WithExportableKey.RSA {
        @SecretExposure
        override suspend fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey() as RSAPrivateKey

        override fun parseSignature(signatureBytes: ByteArray) =
            RSASignature.decodeFromTlv(X509SignatureValue(signatureBytes))
    }
}

object SupremeIosInMemoryKeysProvider : InMemoryKeysProvider {
    override suspend fun makeEphemeralSigner(config: EphemeralSignerConfiguration): Signer.WithExportableKey? {
        val alg = DSL.options(config.ec, config.rsa) ?: return null
        memScoped {
            val attr = createCFDictionary {
                when (alg) {
                    is EphemeralECDSAConfiguration -> {
                        kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
                        kSecAttrKeySizeInBits mapsTo alg.curve.coordinateLength.bits.toInt()
                    }

                    is EphemeralRSAConfiguration -> {
                        kSecAttrKeyType mapsTo kSecAttrKeyTypeRSA
                        kSecAttrKeySizeInBits mapsTo alg.bits
                    }
                }
                kSecPrivateKeyAttrs mapsTo cfDictionaryOf(kSecAttrIsPermanent to false)
                kSecPublicKeyAttrs mapsTo cfDictionaryOf(kSecAttrIsPermanent to false)
            }
            val privateKey = corecall {
                SecKeyCreateRandomKey(attr, error)
            }.adopt()
            val pubkeyBytes = SecKeyCopyPublicKey(privateKey.value).also { defer { CFRelease(it) } }
                .let {
                    corecall {
                        SecKeyCopyExternalRepresentation(it, error)
                    }
                }.takeFromCF<NSData>().toByteArray()

            return when (alg) {
                is EphemeralECDSAConfiguration ->
                    SupremeIosEphemeralSigner.EC(
                        privateKey = privateKey,
                        publicKey = ECDSAPublicKey.fromAnsiX963Bytes(alg.curve, pubkeyBytes),
                        signatureAlgorithm = ECDSAAlgorithm(alg.digest, alg.curve)
                    )

                is EphemeralRSAConfiguration ->
                    SupremeIosEphemeralSigner.RSA(
                        privateKey = privateKey,
                        publicKey = RSAPublicKey.fromPKCS1encoded(pubkeyBytes),
                        signatureAlgorithm = RSAAlgorithm(alg.padding, alg.digest)
                    )

                else -> error("unreachable")
            }
        }
    }

    override fun createSignerForKey(
        algorithm: SignatureAlgorithm,
        privateKey: CryptoPrivateKey.WithPublicKey,
        config: InMemorySignerConfiguration
    ): Signer.WithExportableKey? =
        when (algorithm) {
            is ECDSAAlgorithm -> {
                require(privateKey is ECDSAPrivateKey.WithPublicKey)
                    { "Trying to use a non-ECDSA private key (${privateKey::class.simpleName}) with $algorithm" }
                SupremeIosEphemeralSigner.EC(privateKey.toSecKey(), privateKey.publicKey, algorithm)
            }
            is RSAAlgorithm -> {
                require(privateKey is RSAPrivateKey)
                    { "Trying to use a non-RSA private key (${privateKey::class.simpleName}) with $algorithm" }
                SupremeIosEphemeralSigner.RSA(privateKey.toSecKey(), privateKey.publicKey, algorithm)
            }
            else -> null
        }
}
