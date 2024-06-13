package at.asitplus.crypto.provider.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.provider.DSL
import at.asitplus.crypto.provider.at.asitplus.crypto.provider.CryptoOperationFailed
import at.asitplus.crypto.provider.toNSData
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex

actual class PlatformVerifierConfiguration internal constructor() : DSL.Data()

@OptIn(ExperimentalForeignApi::class)
internal actual fun verifyECDSAImpl
    (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
     data: SignatureInput, signature: CryptoSignature.EC,
     configure: (PlatformVerifierConfiguration.() -> Unit)?) {
    val config = DSL.resolve(::PlatformVerifierConfiguration, configure)

    val digest = signatureAlgorithm.digest
    val curve = publicKey.curve
    val algString = when {
        ((digest == Digest.SHA256) && (curve == ECCurve.SECP_256_R_1)) -> "ECDSA_P256_SHA256"
        ((digest == Digest.SHA384) && (curve == ECCurve.SECP_384_R_1)) -> "ECDSA_P384_SHA384"
        ((digest == Digest.SHA512) && (curve == ECCurve.SECP_521_R_1)) -> "ECDSA_P521_SHA512"
        else -> throw UnsupportedOperationException("$curve with $digest is not supported on iOS")
    }

    lateinit var result: KmmResult<Unit>
    val barrier = Mutex(locked = true)

    /* asynchronous swift call */
    Krypto.verify(
        algString,
        publicKey.encodeToDer().toNSData(),
        signature.encodeToDer().toNSData(),
        data.data.fold(byteArrayOf(), ByteArray::plus).toNSData()
    ) { bool, err ->
        /* asynchronous callback from swift interop */
        result = catching {
            when {
                (bool != null) && (err == null) -> {
                    if (bool) return@catching
                    else throw InvalidSignature("Signature failed to validate")
                }
                (bool == null) && (err != null) -> {
                    throw CryptoOperationFailed(err.localizedDescription)
                }
                else -> {
                    throw IllegalStateException("Illegal return state from Swift interop")
                }
            }
        }
        barrier.unlock()
    }
    /* main function execution continues here */
    runBlocking {
        barrier.lock()
        result.getOrThrow()
    }
}

internal actual fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
             data: SignatureInput, signature: CryptoSignature.RSAorHMAC,
             configure: (PlatformVerifierConfiguration.() -> Unit)?): Unit = TODO()
