package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.secKeyAlgorithm
import at.asitplus.signum.indispensable.toSecKey
import at.asitplus.signum.internals.*
import at.asitplus.signum.supreme.dsl.DSL
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSData
import platform.Security.SecKeyCreateEncryptedData

actual class PlatformEncryptorConfiguration internal actual constructor() : DSL.Data()


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
