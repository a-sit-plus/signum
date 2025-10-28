package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.secKeyAlgorithm
import at.asitplus.signum.indispensable.toSecKey
import at.asitplus.signum.internals.*
import at.asitplus.signum.supreme.dsl.DSL
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSData
import platform.Security.SecKeyCreateEncryptedData
import platform.Security.SecKeyCreateDecryptedData

actual class PlatformDecryptorConfiguration internal actual constructor() : DSL.Data() //TODO provider config like biometrics
actual class PlatformEncryptorConfiguration internal actual constructor() : DSL.Data() //TODO provider config like biometrics


/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
@OptIn(ExperimentalForeignApi::class)
internal actual fun encryptRSAImpl(
    algorithm: AsymmetricEncryptionAlgorithm.RSA,
    publicKey: CryptoPublicKey.RSA,
    data: ByteArray,
    config: PlatformEncryptorConfiguration
): ByteArray =
    corecall {
        val k = publicKey.toSecKey().getOrThrow()
        SecKeyCreateEncryptedData(k.value, algorithm.secKeyAlgorithm, data.toNSData().giveToCF(), error)
    }.takeFromCF<NSData>().toByteArray()


@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun decryptRSAImpl(
    algorithm: AsymmetricEncryptionAlgorithm.RSA,
    privateKey: CryptoPrivateKey.RSA,
    data: ByteArray,
    config: PlatformDecryptorConfiguration
): ByteArray=  corecall {
    val k = privateKey.toSecKey().getOrThrow()
    SecKeyCreateDecryptedData(k.value, algorithm.secKeyAlgorithm, data.toNSData().giveToCF(), error)
}.takeFromCF<NSData>().toByteArray()