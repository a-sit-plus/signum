@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.indispensable

import at.asitplus.signum.internals.*
import at.asitplus.KmmResult
import at.asitplus.catching
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.memScoped
import platform.CoreFoundation.CFRelease
import platform.Security.*

val SignatureAlgorithm.secKeyAlgorithm: SecKeyAlgorithm
    get() = when (this) {
        is SignatureAlgorithm.ECDSA -> {
            when (digest) {
                Digest.SHA1 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA1
                Digest.SHA256 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA256
                Digest.SHA384 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA384
                Digest.SHA512 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA512
                else -> throw IllegalArgumentException("Raw signing is not supported on iOS")
            }
        }

        is SignatureAlgorithm.RSA -> {
            when (padding) {
                RSAPadding.PSS -> when (digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA512
                }

                RSAPadding.PKCS1 -> when (digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
                }
            }
        }

        is SignatureAlgorithm.HMAC -> TODO("HMAC is unsupported")
    }!!
val SpecializedSignatureAlgorithm.secKeyAlgorithm
    get() =
        this.algorithm.secKeyAlgorithm

val SignatureAlgorithm.secKeyAlgorithmPreHashed: SecKeyAlgorithm
    get() = when (this) {
        is SignatureAlgorithm.ECDSA -> {
            when (digest) {
                Digest.SHA1 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA1
                Digest.SHA256 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA256
                Digest.SHA384 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA384
                Digest.SHA512 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA512
                else -> throw IllegalArgumentException("Raw signing is not supported on iOS")
            }
        }

        is SignatureAlgorithm.RSA -> {
            when (padding) {
                RSAPadding.PSS -> when (digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA512
                }

                RSAPadding.PKCS1 -> when (digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
                }
            }
        }

        is SignatureAlgorithm.HMAC -> TODO("HMAC is unsupported")
    }!!

val SpecializedSignatureAlgorithm.secKeyAlgorithmPreHashed
    get() =
        this.algorithm.secKeyAlgorithmPreHashed

val CryptoSignature.iosEncoded
    get() = when (this) {
        is CryptoSignature.EC -> this.encodeToDer()
        is CryptoSignature.RSAorHMAC -> this.rawByteArray
    }

/**
 * Converts this privateKey into a [SecKeyRef], making it usable on iOS
 */
fun CryptoPrivateKey.WithPublicKey<*>.toSecKey(): KmmResult<SecKeyRef> = catching {
    memScoped {
        var data : ByteArray? = null
        val attr = createCFDictionary {
            kSecAttrKeyClass mapsTo  kSecAttrKeyClassPrivate
            kSecPrivateKeyAttrs mapsTo cfDictionaryOf(kSecAttrIsPermanent to false)
            data = when (this@toSecKey) {
                is CryptoPrivateKey.EC.WithPublicKey -> {
                    kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
                    kSecAttrKeySizeInBits mapsTo curve.coordinateLength.bits.toInt()
                    val ecPubKey = this@toSecKey.publicKey
                    ecPubKey.iosEncoded+ privateKeyBytes
                }

                is CryptoPrivateKey.RSA -> {
                    kSecAttrKeyType mapsTo kSecAttrKeyTypeRSA
                    kSecAttrKeySizeInBits mapsTo this@toSecKey.publicKey.bits.number.toInt()
                    asPKCS1.encodeToDer()
                }

                else -> TODO("Unreachable")
            }
        }
        corecall {
            SecKeyCreateWithData(data!!.toNSData().giveToCF(), attr, error)
        }
    }
}