@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.indispensable

import at.asitplus.catching
import at.asitplus.signum.internals.*
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureInputFormat
import at.asitplus.signum.indispensable.sign.SpecializedSignatureAlgorithm
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

interface IosMappingProvider {
    /** Converts a SignatureAlgorithm to its SecKeyAlgorithm equivalent */
    fun signatureAlgorithmToSecKeyAlgorithm(algorithm: SignatureAlgorithm): SecKeyAlgorithm? { return null }
    /** Converts a SignatureAlgorithm to its pre-hashed SecKeyAlgorithm equivalent.
     *    Only considered if [algorithm.preHashedSignatureFormat][SignatureAlgorithm.preHashedSignatureFormat] is not `null`. */
    fun signatureAlgorithmToSecKeyAlgorithmPreHashed(algorithm: SignatureAlgorithm): SecKeyAlgorithm? { return null }

    /** Should parse the signature bytes produced by [SecKeyCreateSignature] when using the algorithm returned by
     * [signatureAlgorithmToSecKeyAlgorithm] into a [Signature]. */
    fun parseSignatureBytes(algorithm: SignatureAlgorithm, sigBytes: ByteArray): Signature? { return null }
    /** Should produce the signature bytes expected by [SecKeyVerifySignature] when using the algorithm returned by
     * [signatureAlgorithmToSecKeyAlgorithm]. */
    fun getSignatureBytes(signature: Signature): ByteArray? { return null }
    /** Converts a CommonCrypto SecKeyRef to a PublicKey */
    fun secKeyToPublicKey(key: SecKeyRef): PublicKey? { return null }
    /** Converts a CryptoPublicKey to a CommonCrypto SecKeyRef */
    fun publicKeyToSecKey(key: PublicKey): OwnedCFValue<SecKeyRef>? { return null }
    /** Converts a CommonCrypto SecKeyRef to a PrivateKey, if possible */
    fun secKeyToPrivateKey(key: SecKeyRef): PrivateKey.WithPublicKey? { return null }
    /** Converts a CryptoPrivateKey to a CommonCrypto SecKeyRef */
    fun privateKeyToSecKey(key: PrivateKey.WithPublicKey): OwnedCFValue<SecKeyRef>? { return null }
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
    Signum.load<IosMappingProvider>()
        .get(this, IosMappingProvider::signatureAlgorithmToSecKeyAlgorithm)

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
    Signum.load<IosMappingProvider>()
        .get(this, IosMappingProvider::signatureAlgorithmToSecKeyAlgorithmPreHashed)

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
val Signature.secKeySignature get() =
    Signum.load<IosMappingProvider>()
        .get(this, IosMappingProvider::getSignatureBytes)

@Deprecated("Renamed", replaceWith = ReplaceWith("this.secKeySignature"))
val Signature.iosEncoded get() = this.secKeySignature

/** Parses the signature bytes produced by the algorithms from [suitableSecKeyAlgAndFormat] etc. */
fun SignatureAlgorithm.parseSecKeySignature(sigBytes: ByteArray) =
    Signum.load<IosMappingProvider>()
        .get(this) { parseSignatureBytes(it, sigBytes) }

/** @see SignatureAlgorithm.parseSecKeySignature */
fun SpecializedSignatureAlgorithm.parseSecKeySignature(sigBytes: ByteArray) =
    this.algorithm.parseSecKeySignature(sigBytes)

fun PublicKey.toSecKey() =
    Signum.load<IosMappingProvider>()
        .get(this, IosMappingProvider::publicKeyToSecKey)

fun SecKeyRef?.toPublicKey() =
    Signum.load<IosMappingProvider>()
        .get(this!!) { secKeyToPublicKey(it) }

/** Converts this privateKey into a [SecKeyRef], making it usable on iOS */
fun PrivateKey.WithPublicKey.toSecKey() =
    Signum.load<IosMappingProvider>()
        .get(this) { privateKeyToSecKey(it) }

fun SecKeyRef?.toPrivateKey() =
    Signum.load<IosMappingProvider>()
        .get(this!!) { secKeyToPrivateKey(it) }

@Deprecated("Renamed to toPublicKey", ReplaceWith("catching { this.toPublicKey() }", "at.asitplus.catching", "at.asitplus.signum.indispensable.toPublicKey"))
fun SecKeyRef?.toCryptoPublicKey() = catching { toPublicKey() }

@Deprecated("Renamed to toPrivateKey", ReplaceWith("catching { this.toPrivateKey() }", "at.asitplus.catching", "at.asitplus.signum.indispensable.toPrivateKey"))
fun SecKeyRef?.toCryptoPrivateKey() = catching { toPrivateKey() }
