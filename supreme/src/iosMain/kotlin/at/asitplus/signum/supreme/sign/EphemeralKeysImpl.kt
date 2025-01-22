@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.internals.*
import at.asitplus.signum.supreme.*
import at.asitplus.signum.supreme.AutofreeVariable
import at.asitplus.signum.supreme.agreement.performKeyAgreement
import kotlinx.cinterop.*
import platform.Foundation.NSData
import platform.Security.*

actual class EphemeralSigningKeyConfiguration internal actual constructor() : EphemeralSigningKeyConfigurationBase()
actual class EphemeralSignerConfiguration internal actual constructor() : EphemeralSignerConfigurationBase()

private typealias EphemeralKeyRef = AutofreeVariable<SecKeyRef>

@SecretExposure
internal actual fun EphemeralKeyBase<*>.exportPrivate(): CryptoPrivateKey.WithPublicKey<*> =
    (privateKey as EphemeralKeyRef).export(this is EphemeralKeyBase.EC<*, *>)


private fun EphemeralKeyRef.export(isEC: Boolean): CryptoPrivateKey.WithPublicKey<*> {
    val privKeyBytes = corecall {
        SecKeyCopyExternalRepresentation(value, error)
    }.let { it.takeFromCF<NSData>() }.toByteArray()
    return CryptoPrivateKey.fromIosEncoded(privKeyBytes).getOrThrow()
}


sealed class EphemeralSigner(internal val privateKey: EphemeralKeyRef) : Signer {
    final override val mayRequireUserUnlock: Boolean get() = false
    final override suspend fun sign(data: SignatureInput) = signCatching {
        val inputData = data.convertTo(signatureAlgorithm.preHashedSignatureFormat).getOrThrow()
        val algorithm = signatureAlgorithm.secKeyAlgorithmPreHashed
        val input = inputData.data.single().toNSData()
        val signatureBytes = corecall {
            SecKeyCreateSignature(privateKey.value, algorithm, input.giveToCF(), error)
        }.let { it.takeFromCF<NSData>().toByteArray() }
        return@signCatching when (val pubkey = publicKey) {
            is CryptoPublicKey.EC -> CryptoSignature.EC.decodeFromDer(signatureBytes).withCurve(pubkey.curve)
            is CryptoPublicKey.RSA -> CryptoSignature.RSAorHMAC(signatureBytes)
        }
    }

    @SecretExposure
    override fun exportPrivateKey(): KmmResult<CryptoPrivateKey.WithPublicKey<*>> =catching{
        privateKey.export(this is EC)
    }

    override suspend fun keyAgreement(publicKey: CryptoPublicKey) = catching {
        if (this !is Signer.ECDSA)
            throw UnsupportedCryptoException("iOS does not support non-EC Diffie-Hellman.")

        performKeyAgreement(privateKey.value, publicKey)
    }

    class EC(
        config: EphemeralSignerConfiguration, privateKey: EphemeralKeyRef,
        override val publicKey: CryptoPublicKey.EC, override val signatureAlgorithm: SignatureAlgorithm.ECDSA
    ) : EphemeralSigner(privateKey), Signer.ECDSA

    class RSA(
        config: EphemeralSignerConfiguration, privateKey: EphemeralKeyRef,
        override val publicKey: CryptoPublicKey.RSA, override val signatureAlgorithm: SignatureAlgorithm.RSA
    ) : EphemeralSigner(privateKey), Signer.RSA
}

internal actual fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration): EphemeralKey {
    val key = AutofreeVariable<SecKeyRef>()
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
        val pubkey = alloc<SecKeyRefVar>()
        val status = SecKeyGeneratePair(attr, pubkey.ptr, key.ptr)
        if (status != errSecSuccess) {
            throw CFCryptoOperationFailed(thing = "generate ephemeral key", osStatus = status)
        }
        val pubkeyBytes = corecall {
            SecKeyCopyExternalRepresentation(pubkey.value, error)
        }.let { it.takeFromCF<NSData>() }.toByteArray()

        return when (val alg = configuration._algSpecific.v) {
            is SigningKeyConfiguration.ECConfiguration ->
                EphemeralKeyBase.EC(
                    EphemeralSigner::EC,
                    key,
                    CryptoPublicKey.EC.fromAnsiX963Bytes(alg.curve, pubkeyBytes),
                    alg.digests
                )

            is SigningKeyConfiguration.RSAConfiguration ->
                EphemeralKeyBase.RSA(
                    EphemeralSigner::RSA,
                    key,
                    CryptoPublicKey.RSA.fromPKCS1encoded(pubkeyBytes),
                    alg.digests,
                    alg.paddings
                )
        }
    }
}

