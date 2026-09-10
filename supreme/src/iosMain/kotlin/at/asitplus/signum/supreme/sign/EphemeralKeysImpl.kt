@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.supreme.sign

import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.signum.dsl.EphemeralEcdsaConfiguration
import at.asitplus.signum.dsl.EphemeralRsaConfiguration
import at.asitplus.signum.dsl.EphemeralSignerConfiguration
import at.asitplus.signum.dsl.InMemorySignerConfiguration
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.RsaPrivateKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaSignature
import at.asitplus.signum.internals.*
import at.asitplus.signum.dsl.DSL
import at.asitplus.signum.indispensable.agree.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.sign.ExportableECDSASigner
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
        privateKey: OwnedCFValue<SecKeyRef>, override val publicKey: EcdsaPublicKey,
        override val signatureAlgorithm: EcdsaAlgorithm
    ) : SupremeIosEphemeralSigner(privateKey), ExportableECDSASigner {
        @SecretExposure
        override suspend fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey() as EcdsaPrivateKey.WithPublicKey

        override fun parseSignature(signatureBytes: ByteArray) =
            EcdsaSignature.decodeFromTlv(X509SignatureValue(signatureBytes)).withCurve(publicKey.curve)

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
        privateKey: OwnedCFValue<SecKeyRef>, override val publicKey: RsaPublicKey,
        override val signatureAlgorithm: RsaAlgorithm
    ) : SupremeIosEphemeralSigner(privateKey), at.asitplus.signum.indispensable.sign.ExportableRSASigner {
        @SecretExposure
        override suspend fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey() as RsaPrivateKey

        override fun parseSignature(signatureBytes: ByteArray) =
            RsaSignature.decodeFromTlv(X509SignatureValue(signatureBytes))
    }
}

object SupremeIosInMemoryKeysProvider : InMemoryKeysProvider {
    override suspend fun makeEphemeralSigner(config: EphemeralSignerConfiguration): Signer.WithExportableKey? {
        val alg = DSL.options(config.ec, config.rsa) ?: return null
        memScoped {
            val attr = createCFDictionary {
                when (alg) {
                    is EphemeralEcdsaConfiguration -> {
                        kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
                        kSecAttrKeySizeInBits mapsTo alg.curve.coordinateLength.bits.toInt()
                    }

                    is EphemeralRsaConfiguration -> {
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
                is EphemeralEcdsaConfiguration ->
                    SupremeIosEphemeralSigner.EC(
                        privateKey = privateKey,
                        publicKey = EcdsaPublicKey.fromAnsiX963Bytes(alg.curve, pubkeyBytes),
                        signatureAlgorithm = EcdsaAlgorithm(alg.digest, alg.curve)
                    )

                is EphemeralRsaConfiguration ->
                    SupremeIosEphemeralSigner.RSA(
                        privateKey = privateKey,
                        publicKey = RsaPublicKey.fromPKCS1encoded(pubkeyBytes),
                        signatureAlgorithm = RsaAlgorithm(alg.padding, alg.digest)
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
            is EcdsaAlgorithm -> {
                require(privateKey is EcdsaPrivateKey.WithPublicKey)
                    { "Trying to use a non-ECDSA private key (${privateKey::class.simpleName}) with $algorithm" }
                SupremeIosEphemeralSigner.EC(privateKey.toSecKey(), privateKey.publicKey, algorithm)
            }
            is RsaAlgorithm -> {
                require(privateKey is RsaPrivateKey)
                    { "Trying to use a non-RSA private key (${privateKey::class.simpleName}) with $algorithm" }
                SupremeIosEphemeralSigner.RSA(privateKey.toSecKey(), privateKey.publicKey, algorithm)
            }
            else -> null
        }
}
