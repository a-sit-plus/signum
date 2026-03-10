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

private const val IOS_SIGNATURE_MESSAGE_NAMESPACE = "ios.secKey.signature.message"
private const val IOS_SIGNATURE_PREHASHED_NAMESPACE = "ios.secKey.signature.prehashed"
private const val IOS_ASYMMETRIC_ENCRYPTION_NAMESPACE = "ios.secKey.asymmetric.encryption"

private val iosBuiltInMappings = run {
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA1, null, null),
        kSecKeyAlgorithmECDSASignatureMessageX962SHA1!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA256, null, null),
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA384, null, null),
        kSecKeyAlgorithmECDSASignatureMessageX962SHA384!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA512, null, null),
        kSecKeyAlgorithmECDSASignatureMessageX962SHA512!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA1, null, RsaSignaturePadding.PSS),
        kSecKeyAlgorithmRSASignatureMessagePSSSHA1!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA256, null, RsaSignaturePadding.PSS),
        kSecKeyAlgorithmRSASignatureMessagePSSSHA256!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA384, null, RsaSignaturePadding.PSS),
        kSecKeyAlgorithmRSASignatureMessagePSSSHA384!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA512, null, RsaSignaturePadding.PSS),
        kSecKeyAlgorithmRSASignatureMessagePSSSHA512!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA1, null, RsaSignaturePadding.PKCS1),
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA256, null, RsaSignaturePadding.PKCS1),
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA384, null, RsaSignaturePadding.PKCS1),
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_MESSAGE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA512, null, RsaSignaturePadding.PKCS1),
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512!!
    )

    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA1, null, null),
        kSecKeyAlgorithmECDSASignatureDigestX962SHA1!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA256, null, null),
        kSecKeyAlgorithmECDSASignatureDigestX962SHA256!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA384, null, null),
        kSecKeyAlgorithmECDSASignatureDigestX962SHA384!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA512, null, null),
        kSecKeyAlgorithmECDSASignatureDigestX962SHA512!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA1, null, RsaSignaturePadding.PSS),
        kSecKeyAlgorithmRSASignatureDigestPSSSHA1!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA256, null, RsaSignaturePadding.PSS),
        kSecKeyAlgorithmRSASignatureDigestPSSSHA256!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA384, null, RsaSignaturePadding.PSS),
        kSecKeyAlgorithmRSASignatureDigestPSSSHA384!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA512, null, RsaSignaturePadding.PSS),
        kSecKeyAlgorithmRSASignatureDigestPSSSHA512!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA1, null, RsaSignaturePadding.PKCS1),
        kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA256, null, RsaSignaturePadding.PKCS1),
        kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA384, null, RsaSignaturePadding.PKCS1),
        kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384!!
    )
    AlgorithmRegistry.registerSignatureMapping(
        IOS_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA512, null, RsaSignaturePadding.PKCS1),
        kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512!!
    )

    AlgorithmRegistry.registerAsymmetricMapping(
        IOS_ASYMMETRIC_ENCRYPTION_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.OAEP_SHA1),
        kSecKeyAlgorithmRSAEncryptionOAEPSHA1!!
    )
    AlgorithmRegistry.registerAsymmetricMapping(
        IOS_ASYMMETRIC_ENCRYPTION_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.OAEP_SHA256),
        kSecKeyAlgorithmRSAEncryptionOAEPSHA256!!
    )
    AlgorithmRegistry.registerAsymmetricMapping(
        IOS_ASYMMETRIC_ENCRYPTION_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.OAEP_SHA384),
        kSecKeyAlgorithmRSAEncryptionOAEPSHA384!!
    )
    AlgorithmRegistry.registerAsymmetricMapping(
        IOS_ASYMMETRIC_ENCRYPTION_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.OAEP_SHA512),
        kSecKeyAlgorithmRSAEncryptionOAEPSHA512!!
    )
    AlgorithmRegistry.registerAsymmetricMapping(
        IOS_ASYMMETRIC_ENCRYPTION_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.PKCS1),
        kSecKeyAlgorithmRSAEncryptionPKCS1!!
    )
    AlgorithmRegistry.registerAsymmetricMapping(
        IOS_ASYMMETRIC_ENCRYPTION_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.NONE),
        kSecKeyAlgorithmRSAEncryptionRaw!!
    )
}

val AsymmetricEncryptionAlgorithm.secKeyAlgorithm: SecKeyAlgorithm get() {
    iosBuiltInMappings
    return AlgorithmRegistry.findAsymmetricMapping<SecKeyAlgorithm>(IOS_ASYMMETRIC_ENCRYPTION_NAMESPACE, this)
        ?: throw UnsupportedCryptoException("Unsupported asymmetric encryption algorithm $this on iOS")
}

val SignatureAlgorithm.secKeyAlgorithm: SecKeyAlgorithm
    get() {
        iosBuiltInMappings
        return AlgorithmRegistry.findSignatureMapping<SecKeyAlgorithm>(IOS_SIGNATURE_MESSAGE_NAMESPACE, this)
            ?: throw UnsupportedCryptoException("Unsupported signature algorithm $this on iOS")
    }

val SpecializedSignatureAlgorithm.secKeyAlgorithm
    get() =
        this.algorithm.secKeyAlgorithm

val SignatureAlgorithm.secKeyAlgorithmPreHashed: SecKeyAlgorithm
    get() {
        iosBuiltInMappings
        return AlgorithmRegistry.findSignatureMapping<SecKeyAlgorithm>(IOS_SIGNATURE_PREHASHED_NAMESPACE, this)
            ?: throw UnsupportedCryptoException("Unsupported signature algorithm $this on iOS")
    }

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
