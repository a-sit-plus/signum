@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.SignatureAlgorithm.RSA.Padding as RSAPadding
import at.asitplus.signum.internals.*
import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.memScoped
import platform.Foundation.NSData
import platform.Security.*

private fun SignatureAlgorithm.RSA.requireSupportedIosPssParameters() {
    val pss = parameters as? SignatureAlgorithm.RSA.Parameters.PssPadded ?: return
    val mgf = pss.mgfAlgorithm as? SignatureAlgorithm.RSA.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1
    require(
        mgf?.digest == pss.digest &&
                pss.saltLength.toInt() == pss.digest.outputLength.bytes.toInt() &&
                pss.trailerField == 1
    ) {
        "iOS supports RSA-PSS only with MGF1 using the signature digest, a salt matching the digest length, and trailer field 1"
    }
}


val AsymmetricEncryptionAlgorithm.secKeyAlgorithm: SecKeyAlgorithm get() = when (this) {
    is AsymmetricEncryptionAlgorithm.RSA -> when(padding){
        at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA1 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA1
        at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA256 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA256
        at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA384 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA384
        at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA512 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA512
        @OptIn(HazardousMaterials::class)
        at.asitplus.signum.indispensable.asymmetric.RSAPadding.PKCS1 -> kSecKeyAlgorithmRSAEncryptionPKCS1
        @OptIn(HazardousMaterials::class)
        at.asitplus.signum.indispensable.asymmetric.RSAPadding.NONE -> kSecKeyAlgorithmRSAEncryptionRaw
    }!!
}

/**
 * Maps this algorithm to its iOS Security framework equivalent.
 *
 * RSA-PSS is supported only when MGF1 uses the signature digest, the salt length equals the digest output length,
 * and the trailer field is `1`.
 *
 * @throws IllegalArgumentException if the algorithm cannot be represented by an iOS [SecKeyAlgorithm].
 */
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
            requireSupportedIosPssParameters()
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
    }!!

val SpecializedSignatureAlgorithm.secKeyAlgorithm
    get() =
        this.algorithm.secKeyAlgorithm

/**
 * Maps this algorithm to its prehashed iOS Security framework equivalent.
 *
 * RSA-PSS is supported only when MGF1 uses the signature digest, the salt length equals the digest output length,
 * and the trailer field is `1`.
 *
 * @throws IllegalArgumentException if the algorithm cannot be represented by an iOS [SecKeyAlgorithm].
 */
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
            requireSupportedIosPssParameters()
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
    }!!

val SpecializedSignatureAlgorithm.secKeyAlgorithmPreHashed
    get() =
        this.algorithm.secKeyAlgorithmPreHashed


fun CryptoPublicKey.toSecKey() = catching {
    memScoped {
        val attr = cfDictionaryOf(
            kSecAttrKeyClass to kSecAttrKeyClassPublic,
            kSecAttrKeyType to when (this@toSecKey) {
                is CryptoPublicKey.EC -> kSecAttrKeyTypeEC
                is CryptoPublicKey.RSA -> kSecAttrKeyTypeRSA
            })
        corecall {
            SecKeyCreateWithData(this@toSecKey.iosEncoded.toNSData().let(::giveToCF), attr, error)
        }.manage()
    }
}

/** Converts this privateKey into a [SecKeyRef], making it usable on iOS */
fun CryptoPrivateKey.WithPublicKey<*>.toSecKey(): KmmResult<OwnedCFValue<SecKeyRef>> = catching {
    memScoped {
        var data : ByteArray? = null
        val attr = createCFDictionary {
            kSecAttrKeyClass mapsTo kSecAttrKeyClassPrivate
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
            }
        }
        corecall {
            SecKeyCreateWithData(data!!.toNSData().let(::giveToCF), attr, error)
        }.manage()
    }
}

fun SecKeyRef?.toCryptoPrivateKey() = catching {
    corecall {
        SecKeyCopyExternalRepresentation(this@toCryptoPrivateKey, error)
    }.let { it.takeFromCF<NSData>() }.toByteArray()
}.transform(CryptoPrivateKey::fromIosEncoded)
