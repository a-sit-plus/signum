@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.indispensable

import at.asitplus.signum.internals.*
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SignatureInputFormat
import at.asitplus.signum.indispensable.integrity.SpecializedSignatureAlgorithm
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Security.*

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

interface CommonCryptoExtensionProvider {
    /** Converts a SignatureAlgorithm to its SecKeyAlgorithm equivalent */
    fun signatureAlgorithmToSecKeyAlgorithm(algorithm: SignatureAlgorithm): SecKeyAlgorithm? { return null }
    /** Converts a SignatureAlgorithm to its pre-hashed SecKeyAlgorithm equivalent.
     *    Only considered if [algorithm.preHashedSignatureFormat][SignatureAlgorithm.preHashedSignatureFormat] is not `null`. */
    fun signatureAlgorithmToSecKeyAlgorithmPreHashed(algorithm: SignatureAlgorithm): SecKeyAlgorithm? { return null }
    /** Converts a CommonCrypto SecKeyRef to a CryptoPublicKey */
    fun secKeyToCryptoPublicKey(key: SecKeyRef): CryptoPublicKey? { return null }
    /** Converts a CryptoPublicKey to a CommonCrypto SecKeyRef */
    fun cryptoPublicKeyToSecKey(key: CryptoPublicKey): OwnedCFValue<SecKeyRef>? { return null }
    /** Converts a CommonCrypto SecKeyRef to a CryptoPrivateKey, if possible */
    fun secKeyToCryptoPrivateKey(key: SecKeyRef): CryptoPrivateKey.WithPublicKey? { return null }
    /** Converts a CryptoPrivateKey to a CommonCrypto SecKeyRef */
    fun cryptoPrivateKeyToSecKey(key: CryptoPrivateKey.WithPublicKey): OwnedCFValue<SecKeyRef>? { return null }
}

/**
 * Maps this algorithm to its iOS Security framework equivalent.
 *
 * RSA-PSS is supported only when MGF1 uses the signature digest, the salt length equals the digest output length,
 * and the trailer field is `1`.
 *
 * @throws UnsupportedCryptoException if the algorithm cannot be represented by an iOS [SecKeyAlgorithm].
 */
val SignatureAlgorithm.secKeyAlgorithm: SecKeyAlgorithm get() =
    ServiceLoader.load<CommonCryptoExtensionProvider>()
        .get(this, CommonCryptoExtensionProvider::signatureAlgorithmToSecKeyAlgorithm)

val SpecializedSignatureAlgorithm.secKeyAlgorithm get() = this.algorithm.secKeyAlgorithm

/**
 * Maps this algorithm to its pre-hashed iOS Security framework equivalent.
 *
 * RSA-PSS is supported only when MGF1 uses the signature digest, the salt length equals the digest output length,
 * and the trailer field is `1`.
 *
 * @throws UnsupportedCryptoException if the algorithm cannot be represented by an iOS [SecKeyAlgorithm].
 */
val SignatureAlgorithm.secKeyAlgorithmPreHashed: SecKeyAlgorithm get() =
    ServiceLoader.load<CommonCryptoExtensionProvider>()
        .get(this, CommonCryptoExtensionProvider::signatureAlgorithmToSecKeyAlgorithmPreHashed)

val SpecializedSignatureAlgorithm.secKeyAlgorithmPreHashed get() = this.algorithm.secKeyAlgorithmPreHashed

/** We always pre-hash on iOS if possible because the digest methods take a sequence well, while the signature methods do not */
val SignatureAlgorithm.suitableSecKeyAlgAndFormat get(): Pair<SecKeyAlgorithm, SignatureInputFormat> {
    val phAlg = try { secKeyAlgorithmPreHashed } catch (_: UnsupportedCryptoException) { null }
    val phFormat = preHashedSignatureFormat
    return when {
        (phAlg != null && phFormat != null) -> Pair(phAlg, phFormat)
        else -> Pair(secKeyAlgorithm, null)
    }
}


fun CryptoPublicKey.toSecKey() =
    ServiceLoader.load<CommonCryptoExtensionProvider>()
        .get(this, CommonCryptoExtensionProvider::cryptoPublicKeyToSecKey)

fun SecKeyRef?.toCryptoPublicKey() =
    ServiceLoader.load<CommonCryptoExtensionProvider>()
        .get(this!!, CommonCryptoExtensionProvider::secKeyToCryptoPublicKey)

/** Converts this privateKey into a [SecKeyRef], making it usable on iOS */
fun CryptoPrivateKey.WithPublicKey.toSecKey() =
    ServiceLoader.load<CommonCryptoExtensionProvider>()
        .get(this, CommonCryptoExtensionProvider::cryptoPrivateKeyToSecKey)

fun SecKeyRef?.toCryptoPrivateKey() =
    ServiceLoader.load<CommonCryptoExtensionProvider>()
        .get(this!!, CommonCryptoExtensionProvider::secKeyToCryptoPrivateKey)
