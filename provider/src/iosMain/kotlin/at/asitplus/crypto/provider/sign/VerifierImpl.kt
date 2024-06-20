package at.asitplus.crypto.provider.sign

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.RSAPadding
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.provider.dsl.DSL
import at.asitplus.crypto.provider.UnsupportedCryptoException
import at.asitplus.crypto.provider.swiftcall
import at.asitplus.crypto.provider.toNSData
import at.asitplus.swift.krypto.Krypto
import kotlinx.cinterop.ExperimentalForeignApi

/**
 * Configures iOS-specific properties.
 */
actual class PlatformVerifierConfiguration internal actual constructor() : DSL.Data()

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             config: PlatformVerifierConfiguration)
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

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
             config: PlatformVerifierConfiguration)
{

}

@OptIn(ExperimentalForeignApi::class)
internal actual fun verifyECDSAImpl
    (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
     data: SignatureInput, signature: CryptoSignature.EC,
     config: PlatformVerifierConfiguration) {

    val digest = signatureAlgorithm.digest
    val curve = publicKey.curve
    val curveString = when (curve) {
        ECCurve.SECP_256_R_1 -> "P256"
        ECCurve.SECP_384_R_1 -> "P384"
        ECCurve.SECP_521_R_1 -> "P521"
        //else -> throw UnsupportedOperationException("Unsupported curve $curve")
    }
    val digestString = when (digest) {
        Digest.SHA256 -> "SHA256"
        Digest.SHA384 -> "SHA384"
        Digest.SHA512 -> "SHA512"
        null, Digest.SHA1 -> throw UnsupportedOperationException("Unsupported digest $digest")
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

@OptIn(ExperimentalForeignApi::class)
internal actual fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
             data: SignatureInput, signature: CryptoSignature.RSAorHMAC,
             config: PlatformVerifierConfiguration) {
    val padding = signatureAlgorithm.padding
    val digest = signatureAlgorithm.digest

    val paddingString = when(padding) {
        RSAPadding.PKCS1 -> "PKCS1"
        RSAPadding.PSS -> "PSS"
        //else -> throw UnsupportedOperationException("Unsupported padding $padding")
    }
    val digestString = when (digest) {
        Digest.SHA1 -> "SHA1"
        Digest.SHA256 -> "SHA256"
        Digest.SHA384 -> "SHA384"
        Digest.SHA512 -> "SHA512"
        //else -> throw UnsupportedOperationException("Unsupported digest $digest")
    }

    val success = swiftcall {
        Krypto.verifyRSA(
            paddingString,
            digestString,
            publicKey.pkcsEncoded.toNSData(),
            signature.rawByteArray.toNSData(),
            data.data.fold(byteArrayOf(), ByteArray::plus).toNSData(),
            error
        )
    }
    if (success != "true") throw InvalidSignature("Signature failed to verify")
}
