@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.dsl.EphemeralECDSAConfiguration
import at.asitplus.signum.dsl.EphemeralRSAConfiguration
import at.asitplus.signum.dsl.EphemeralSignerConfiguration
import at.asitplus.signum.dsl.InMemorySignerConfiguration
import at.asitplus.signum.dsl.SigningKeyConfiguration
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.ECDSASignature
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.indispensable.sign.RSASignature
import at.asitplus.signum.internals.*
import at.asitplus.signum.supreme.*
import at.asitplus.signum.dsl.DSL
import kotlinx.cinterop.*
import platform.CoreFoundation.CFRelease
import platform.Foundation.NSData
import platform.Security.*

internal fun performKeyAgreement(privateKey: SecKeyRef?, publicValue: KeyAgreementPublicValue.ECDH) =
    corecall {
        SecKeyCopyKeyExchangeResult(
            privateKey,
            platform.Security.kSecKeyAlgorithmECDHKeyExchangeStandard,
            publicValue.asCryptoPublicKey().toSecKey().getOrThrow().value,
            parameters = null,
            error
        )
    }.takeFromCF<NSData>().toByteArray()

sealed class SupremeIosEphemeralSigner(internal val privateKey: OwnedCFValue<SecKeyRef>) : Signer.WithExportableKey {
    final override val mayRequireUserUnlock: Boolean get() = false
    final override suspend fun sign(data: SignatureInput) = signCatching {
        /** We always pre-hash on iOS because the digest methods take a sequence well, while the signature methods do not */
        val inputData = data.convertTo(signatureAlgorithm.preHashedSignatureFormat).getOrThrow()
        val algorithm = signatureAlgorithm.secKeyAlgorithmPreHashed
        val input = inputData.data.single().toNSData()
        val signatureBytes = corecall {
            SecKeyCreateSignature(privateKey.value, algorithm, input.let(::giveToCF), error)
        }.takeFromCF<NSData>().toByteArray()
        return@signCatching parseSignature(signatureBytes)
    }

    protected abstract fun parseSignature(signatureBytes: ByteArray): CryptoSignature.RawByteEncodable

    class EC internal constructor(
        privateKey: OwnedCFValue<SecKeyRef>, override val publicKey: ECDSAPublicKey,
        override val signatureAlgorithm: ECDSAAlgorithm
    ) : SupremeIosEphemeralSigner(privateKey), Signer.WithExportableKey.ECDSA {
        @SecretExposure
        override suspend fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey().mapCatching { it as ECDSAPrivateKey.WithPublicKey }.getOrThrow()

        override fun parseSignature(signatureBytes: ByteArray) =
            ECDSASignature.decodeFromDer(signatureBytes).withCurve(publicKey.curve)

        override suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH) = catching {
            performKeyAgreement(privateKey.value, publicValue)
        }
    }

    class RSA internal constructor(
        privateKey: OwnedCFValue<SecKeyRef>, override val publicKey: RSAPublicKey,
        override val signatureAlgorithm: RSAAlgorithm
    ) : SupremeIosEphemeralSigner(privateKey), Signer.WithExportableKey.RSA {
        @SecretExposure
        override suspend fun exportPrivateKey() =
            privateKey.value.toCryptoPrivateKey().mapCatching { it as RSAPrivateKey }.getOrThrow()

        override fun parseSignature(signatureBytes: ByteArray) =
            RSASignature(signatureBytes)
    }
}

object SupremeIosInMemoryKeysProvider : InMemoryKeysProvider {
    override suspend fun makeEphemeralSigner(configuration: EphemeralSignerConfiguration): Signer.WithExportableKey? {
        val alg = DSL.options(configuration.ec, configuration.rsa) ?: return null
        memScoped {
            val attr = createCFDictionary {
                when (alg) {
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
            }
        }
    }

    override fun createSignerForKey(
        algorithm: SignatureAlgorithm,
        privateKey: CryptoPrivateKey.WithPublicKey,
        configuration: InMemorySignerConfiguration
    ): Signer.WithExportableKey? =
        when (algorithm) {
            is ECDSAAlgorithm -> {
                require(privateKey is ECDSAPrivateKey.WithPublicKey)
                    { "Trying to use a non-ECDSA private key (${privateKey::class.simpleName}) with $algorithm" }
                SupremeIosEphemeralSigner.EC(privateKey.toSecKey().getOrThrow(), privateKey.publicKey, algorithm)
            }
            is RSAAlgorithm -> {
                require(privateKey is RSAPrivateKey)
                    { "Trying to use a non-RSA private key (${privateKey::class.simpleName}) with $algorithm" }
                SupremeIosEphemeralSigner.RSA(privateKey.toSecKey().getOrThrow(), privateKey.publicKey, algorithm)
            }
            else -> null
        }
    }
}
