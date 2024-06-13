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
import at.asitplus.crypto.provider.swiftcall
import at.asitplus.crypto.provider.toNSData
import at.asitplus.swift.krypto.Krypto
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ObjCObject
import kotlinx.cinterop.ObjCObjectVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import platform.Foundation.NSError

actual class PlatformVerifierConfiguration internal constructor() : DSL.Data()

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
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

    val success = swiftcall {
        Krypto.verifyECDSA(
            algString,
            publicKey.encodeToDer().toNSData(),
            signature.encodeToDer().toNSData(),
            data.data.fold(byteArrayOf(), ByteArray::plus).toNSData(),
            error
        )
    }
    if (success != "true") throw InvalidSignature("Signature failed to verify")
}

internal actual fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
             data: SignatureInput, signature: CryptoSignature.RSAorHMAC,
             configure: (PlatformVerifierConfiguration.() -> Unit)?): Unit = TODO()
