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

interface IosExtensionProvider {
    /** Converts a SignatureAlgorithm to its SecKeyAlgorithm equivalent */
    fun signatureAlgorithmToSecKeyAlgorithm(algorithm: SignatureAlgorithm): SecKeyAlgorithm? { return null }
    /** Converts a SignatureAlgorithm to its pre-hashed SecKeyAlgorithm equivalent.
     *    Only considered if [algorithm.preHashedSignatureFormat][SignatureAlgorithm.preHashedSignatureFormat] is not `null`. */
    fun signatureAlgorithmToSecKeyAlgorithmPreHashed(algorithm: SignatureAlgorithm): SecKeyAlgorithm? { return null }

    /** Should parse the signature bytes produced by [SecKeyCreateSignature] when using the algorithm returned by
     * [signatureAlgorithmToSecKeyAlgorithm] into a [CryptoSignature]. */
    fun parseSignatureBytes(algorithm: SignatureAlgorithm, sigBytes: ByteArray): CryptoSignature? { return null }
    /** Should produce the signature bytes expected by [SecKeyVerifySignature] when using the algorithm returned by
     * [signatureAlgorithmToSecKeyAlgorithm]. */
    fun getSignatureBytes(signature: CryptoSignature): ByteArray? { return null }
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
    ServiceLoader.load<IosExtensionProvider>()
        .get(this, IosExtensionProvider::signatureAlgorithmToSecKeyAlgorithm)

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
    ServiceLoader.load<IosExtensionProvider>()
        .get(this, IosExtensionProvider::signatureAlgorithmToSecKeyAlgorithmPreHashed)

val SpecializedSignatureAlgorithm.secKeyAlgorithmPreHashed get() = this.algorithm.secKeyAlgorithmPreHashed

/** On iOS, pre-hashing is recommended when possible, because the digest methods take a sequence well, while the
 * signature methods do not. This returns a suitable pre-hashed algorithm+format combination if available. If not,
 * it returns the algorithm without pre-hashing. */
val SignatureAlgorithm.suitableSecKeyAlgAndFormat get(): Pair<SecKeyAlgorithm, SignatureInputFormat> {
    val phAlg = try { secKeyAlgorithmPreHashed } catch (_: UnsupportedCryptoException) { null }
    val phFormat = preHashedSignatureFormat
    return when {
        (phAlg != null && phFormat != null) -> Pair(phAlg, phFormat)
        else -> Pair(secKeyAlgorithm, null)
    }
}

/** Produces signature bytes that match the algorithms returned by [suitableSecKeyAlgAndFormat] etc. */
val CryptoSignature.secKeySignature get() =
    ServiceLoader.load<IosExtensionProvider>()
        .get(this, IosExtensionProvider::getSignatureBytes)

@Deprecated("Renamed", replaceWith = ReplaceWith("this.secKeySignature"))
val CryptoSignature.iosEncoded get() = this.secKeySignature

/** Parses the signature bytes produced by the algorithms from [suitableSecKeyAlgAndFormat] etc. */
fun SignatureAlgorithm.parseSecKeySignature(sigBytes: ByteArray) =
    ServiceLoader.load<IosExtensionProvider>()
        .get(this) { parseSignatureBytes(it, sigBytes) }

/** @see SignatureAlgorithm.parseSecKeySignature */
fun SpecializedSignatureAlgorithm.parseSecKeySignature(sigBytes: ByteArray) =
    this.algorithm.parseSecKeySignature(sigBytes)

fun CryptoPublicKey.toSecKey() =
    ServiceLoader.load<IosExtensionProvider>()
        .get(this, IosExtensionProvider::cryptoPublicKeyToSecKey)

fun SecKeyRef?.toCryptoPublicKey() =
    ServiceLoader.load<IosExtensionProvider>()
        .get(this!!, IosExtensionProvider::secKeyToCryptoPublicKey)

/** Converts this privateKey into a [SecKeyRef], making it usable on iOS */
fun CryptoPrivateKey.WithPublicKey.toSecKey() =
    ServiceLoader.load<IosExtensionProvider>()
        .get(this, IosExtensionProvider::cryptoPrivateKeyToSecKey)

fun SecKeyRef?.toCryptoPrivateKey() =
    ServiceLoader.load<IosExtensionProvider>()
        .get(this!!, IosExtensionProvider::secKeyToCryptoPrivateKey)
