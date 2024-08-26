@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.secKeyAlgorithm
import at.asitplus.signum.supreme.CFCryptoOperationFailed
import at.asitplus.signum.supreme.cfDictionaryOf
import at.asitplus.signum.supreme.corecall
import at.asitplus.signum.supreme.createCFDictionary
import at.asitplus.signum.supreme.giveToCF
import at.asitplus.signum.supreme.os.SignerConfiguration
import at.asitplus.signum.supreme.takeFromCF
import at.asitplus.signum.supreme.toByteArray
import at.asitplus.signum.supreme.toNSData
import kotlinx.cinterop.Arena
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.Foundation.NSData
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyGeneratePair
import platform.Security.SecKeyRefVar
import platform.Security.errSecSuccess
import platform.Security.kSecAttrIsPermanent
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeEC
import platform.Security.kSecAttrKeyTypeRSA
import platform.Security.kSecKeyAlgorithmECDSASignatureDigestX962SHA1
import platform.Security.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
import platform.Security.kSecKeyAlgorithmECDSASignatureDigestX962SHA384
import platform.Security.kSecKeyAlgorithmECDSASignatureDigestX962SHA512
import platform.Security.kSecPrivateKeyAttrs
import platform.Security.kSecPublicKeyAttrs
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

actual class EphemeralSigningKeyConfiguration internal actual constructor(): SigningKeyConfiguration()
actual class EphemeralSignerConfiguration internal actual constructor(): SignerConfiguration()

sealed class EphemeralSigner(private val privateKey: EphemeralKeyRef): Signer {
    final override val mayRequireUserUnlock: Boolean get() = false
    final override suspend fun sign(data: SignatureInput) = catching {
        if (data.format != null) {
            (signatureAlgorithm as? SignatureAlgorithm.ECDSA).let {
                require (it != null && it.digest == data.format)
                { "Pre-hashed data (format ${data.format}) is unsupported by algorithm $signatureAlgorithm"}
            }
        }
        val algorithm = when (data.format) {
            Digest.SHA1 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA1
            Digest.SHA256 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA256
            Digest.SHA384 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA384
            Digest.SHA512 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA512
            null -> signatureAlgorithm.secKeyAlgorithm
        }
        val input = data.data.fold(byteArrayOf(), ByteArray::plus).toNSData()
        val signatureBytes = corecall {
            SecKeyCreateSignature(privateKey.key.value, algorithm, input.giveToCF(), error)
        }.let { it.takeFromCF<NSData>().toByteArray() }
        return@catching when (val pubkey = publicKey) {
            is CryptoPublicKey.EC -> CryptoSignature.EC.decodeFromDer(signatureBytes).withCurve(pubkey.curve)
            is CryptoPublicKey.Rsa -> CryptoSignature.RSAorHMAC(signatureBytes)
        }
    }
    class EC(privateKey: EphemeralKeyRef, override val publicKey: CryptoPublicKey.EC,
             override val signatureAlgorithm: SignatureAlgorithm.ECDSA): EphemeralSigner(privateKey), Signer.ECDSA

    class RSA(privateKey: EphemeralKeyRef, override val publicKey: CryptoPublicKey.Rsa,
              override val signatureAlgorithm: SignatureAlgorithm.RSA): EphemeralSigner(privateKey), Signer.RSA
}

class EphemeralKeyRef {
    private val arena = Arena()
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(arena, Arena::clear)
    val key = arena.alloc<SecKeyRefVar>()
}

internal actual fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey {
    val key = EphemeralKeyRef()
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
        val status = SecKeyGeneratePair(attr, pubkey.ptr, key.key.ptr)
        if (status != errSecSuccess) {
            throw CFCryptoOperationFailed(thing = "generate ephemeral key", osStatus = status)
        }
        val pubkeyBytes = corecall {
            SecKeyCopyExternalRepresentation(pubkey.value, error)
        }.let { it.takeFromCF<NSData>() }.toByteArray()
        return when (val alg = configuration._algSpecific.v) {
            is SigningKeyConfiguration.ECConfiguration ->
                EphemeralKeyBase.EC(EphemeralSigner::EC, key, CryptoPublicKey.EC.fromAnsiX963Bytes(alg.curve, pubkeyBytes), alg.digests)
            is SigningKeyConfiguration.RSAConfiguration ->
                EphemeralKeyBase.RSA(EphemeralSigner::RSA, key, CryptoPublicKey.Rsa.fromPKCS1encoded(pubkeyBytes), alg.digests, alg.paddings)
        }
    }
}
