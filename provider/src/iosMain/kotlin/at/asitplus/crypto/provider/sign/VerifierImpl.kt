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
import at.asitplus.crypto.provider.at.asitplus.crypto.provider.UnsupportedCryptoException
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
import kotlin.math.sign

actual class PlatformVerifierConfiguration internal constructor() : DSL.Data()

internal actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             configure: (PlatformVerifierConfiguration.()->Unit)?)
{
    when (publicKey.curve) {
        ECCurve.SECP_256_R_1, ECCurve.SECP_384_R_1, ECCurve.SECP_521_R_1 -> {}
        else -> throw UnsupportedCryptoException("Curve ${publicKey.curve} is not supported on iOS")
    }
    when (signatureAlgorithm.digest) {
        Digest.SHA256, Digest.SHA384, Digest.SHA512 -> {}
        else -> throw UnsupportedCryptoException("Digest ${signatureAlgorithm.digest} is not supported on iOS")
    }
}

internal actual fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
             configure: (PlatformVerifierConfiguration.()->Unit)?)
{
    throw UnsupportedCryptoException("RSA is not yet supported on iOS")
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
internal actual fun verifyECDSAImpl
    (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
     data: SignatureInput, signature: CryptoSignature.EC,
     configure: (PlatformVerifierConfiguration.() -> Unit)?) {
    val config = DSL.resolve(::PlatformVerifierConfiguration, configure)

    val digest = signatureAlgorithm.digest
    val curve = publicKey.curve
    var curveString = when (curve) {
        ECCurve.SECP_256_R_1 -> "P256"
        ECCurve.SECP_384_R_1 -> "P384"
        ECCurve.SECP_521_R_1 -> "P521"
        else -> throw UnsupportedOperationException("Unsupported curve $curve")
    }
    val digestString = when (digest) {
        Digest.SHA256 -> "SHA256"
        Digest.SHA384 -> "SHA384"
        Digest.SHA512 -> "SHA512"
        else -> throw UnsupportedOperationException("Unsupported digest $digest")
    }

    val success = swiftcall {
        Krypto.verifyECDSA(
            curveString,
            digestString,
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
