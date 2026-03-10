@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.indispensable

import at.asitplus.signum.internals.*
import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asymmetric.*
import at.asitplus.signum.UnsupportedCryptoException
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.memScoped
import platform.Foundation.NSData
import platform.Security.*

val AsymmetricEncryptionAlgorithm.secKeyAlgorithm: SecKeyAlgorithm get() = when (this) {
    is RsaEncryptionAlgorithm -> when(padding){
        RsaEncryptionPadding.OAEP_SHA1 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA1
        RsaEncryptionPadding.OAEP_SHA256 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA256
        RsaEncryptionPadding.OAEP_SHA384 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA384
        RsaEncryptionPadding.OAEP_SHA512 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA512
        @OptIn(HazardousMaterials::class)
        RsaEncryptionPadding.PKCS1 -> kSecKeyAlgorithmRSAEncryptionPKCS1
        @OptIn(HazardousMaterials::class)
        RsaEncryptionPadding.NONE -> kSecKeyAlgorithmRSAEncryptionRaw
        else -> throw UnsupportedCryptoException("Unsupported RSA encryption padding $padding on iOS")
    }!!
    else -> throw UnsupportedCryptoException("Unsupported asymmetric encryption algorithm $this on iOS")
}

val SignatureAlgorithm.secKeyAlgorithm: SecKeyAlgorithm
    get() = when (this) {
        is EcdsaSignatureAlgorithm -> {
            when (digest) {
                Digest.SHA1 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA1
                Digest.SHA256 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA256
                Digest.SHA384 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA384
                Digest.SHA512 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA512
                else -> throw IllegalArgumentException("Raw signing is not supported on iOS")
            }
        }

        is RsaSignatureAlgorithm -> {
            when (padding) {
                RsaSignaturePadding.PSS -> when (digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA512
                }

                RsaSignaturePadding.PKCS1 -> when (digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
                }
            }
        }
        else -> throw UnsupportedCryptoException("Unsupported signature algorithm $this on iOS")
    }!!

val SpecializedSignatureAlgorithm.secKeyAlgorithm
    get() =
        this.algorithm.secKeyAlgorithm

val SignatureAlgorithm.secKeyAlgorithmPreHashed: SecKeyAlgorithm
    get() = when (this) {
        is EcdsaSignatureAlgorithm -> {
            when (digest) {
                Digest.SHA1 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA1
                Digest.SHA256 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA256
                Digest.SHA384 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA384
                Digest.SHA512 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA512
                else -> throw IllegalArgumentException("Raw signing is not supported on iOS")
            }
        }

        is RsaSignatureAlgorithm -> {
            when (padding) {
                RsaSignaturePadding.PSS -> when (digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA512
                }

                RsaSignaturePadding.PKCS1 -> when (digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
                }
            }
        }
        else -> throw UnsupportedCryptoException("Unsupported signature algorithm $this on iOS")
    }!!

val SpecializedSignatureAlgorithm.secKeyAlgorithmPreHashed
    get() =
        this.algorithm.secKeyAlgorithmPreHashed

val Signature.iosEncoded
    get() = when (this) {
        is Signature.EC -> this.encodeToDer()
        is Signature.RSA -> this.rawByteArray
    }

fun PublicKey.toSecKey() = catching {
    memScoped {
        val attr = cfDictionaryOf(
            kSecAttrKeyClass to kSecAttrKeyClassPublic,
            kSecAttrKeyType to when (this@toSecKey) {
                is PublicKey.EC -> kSecAttrKeyTypeEC
                is PublicKey.RSA -> kSecAttrKeyTypeRSA
            })
        corecall {
            SecKeyCreateWithData(this@toSecKey.iosEncoded.toNSData().let(::giveToCF), attr, error)
        }.manage()
    }
}

/** Converts this privateKey into a [SecKeyRef], making it usable on iOS */
fun PrivateKey.WithPublicKey<*>.toSecKey(): KmmResult<OwnedCFValue<SecKeyRef>> = catching {
    memScoped {
        var data : ByteArray? = null
        val attr = createCFDictionary {
            kSecAttrKeyClass mapsTo kSecAttrKeyClassPrivate
            kSecPrivateKeyAttrs mapsTo cfDictionaryOf(kSecAttrIsPermanent to false)
            data = when (this@toSecKey) {
                is PrivateKey.EC.WithPublicKey -> {
                    kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
                    kSecAttrKeySizeInBits mapsTo curve.coordinateLength.bits.toInt()
                    val ecPubKey = this@toSecKey.publicKey
                    ecPubKey.iosEncoded+ privateKeyBytes
                }

                is PrivateKey.RSA -> {
                    kSecAttrKeyType mapsTo kSecAttrKeyTypeRSA
                    kSecAttrKeySizeInBits mapsTo this@toSecKey.publicKey.bits.number.toInt()
                    asPKCS1.encodeToDer()
                }
            }
        }
        corecall {
            SecKeyCreateWithData(data!!.toNSData().let(::giveToCF), attr, error)
        }.manage()
    }
}

fun SecKeyRef?.toPrivateKey() = catching {
    corecall {
        SecKeyCopyExternalRepresentation(this@toPrivateKey, error)
    }.let { it.takeFromCF<NSData>() }.toByteArray()
}.transform(PrivateKey::fromIosEncoded)

@Deprecated(
    "Renamed to toPrivateKey().",
    ReplaceWith("toPrivateKey()")
)
fun SecKeyRef?.toCryptoPrivateKey() = toPrivateKey()
