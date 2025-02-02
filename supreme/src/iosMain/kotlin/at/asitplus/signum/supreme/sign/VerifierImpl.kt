@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.internals.*
import at.asitplus.signum.indispensable.iosEncoded
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.secKeyAlgorithmPreHashed
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.UnsupportedCryptoException
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.memScoped
import platform.CoreFoundation.CFRelease
import platform.Foundation.NSOSStatusErrorDomain
import platform.Security.SecKeyCreateWithData
import platform.Security.SecKeyRef
import platform.Security.SecKeyVerifySignature
import platform.Security.errSecVerifyFailed
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPublic
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeEC
import platform.Security.kSecAttrKeyTypeRSA

/**
 * Configures iOS-specific properties.
 */
actual class PlatformVerifierConfiguration internal actual constructor() : DSL.Data()

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             config: PlatformVerifierConfiguration)
{
    if (publicKey.curve == ECCurve.SECP_521_R_1 && signatureAlgorithm.digest == null)
        throw UnsupportedCryptoException("Raw signing over P521 is unsupported on iOS")
}

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             config: PlatformVerifierConfiguration)
{
}

private fun MemScope.toSecKey(key: CryptoPublicKey): SecKeyRef =
    corecall {
        SecKeyCreateWithData(key.iosEncoded.toNSData().giveToCF(), cfDictionaryOf(
            kSecAttrKeyClass to kSecAttrKeyClassPublic,
            kSecAttrKeyType to when (key) {
                is CryptoPublicKey.EC -> kSecAttrKeyTypeEC
                is CryptoPublicKey.RSA -> kSecAttrKeyTypeRSA
            }), error)
    }.also { defer { CFRelease(it) }}

private fun verifyImpl(signatureAlgorithm: SignatureAlgorithm, publicKey: CryptoPublicKey,
                       data: SignatureInput, signature: CryptoSignature,
                       config: PlatformVerifierConfiguration) {
    memScoped {
        val key = toSecKey(publicKey)
        val inputData = data.convertTo(signatureAlgorithm.preHashedSignatureFormat).getOrThrow().data.single()
        try {
            corecall {
                SecKeyVerifySignature(key, signatureAlgorithm.secKeyAlgorithmPreHashed,
                    inputData.toNSData().giveToCF(), signature.iosEncoded.toNSData().giveToCF(), error).takeIf { it }
            }
        } catch (x: CoreFoundationException) {
            if ((x.nsError.domain == NSOSStatusErrorDomain) && (x.nsError.code == errSecVerifyFailed.toLong()))
                throw InvalidSignature("Signature failed to verify", x)
            throw x
        }
    }
}

internal actual fun verifyECDSAImpl
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             data: SignatureInput, signature: CryptoSignature.EC,
             config: PlatformVerifierConfiguration) = when (signatureAlgorithm.digest) {
    null -> {
        val targetDigest = publicKey.curve.nativeDigest
        check(publicKey.curve.scalarLength == targetDigest.outputLength)
        val processed = SignatureInput.unsafeCreate(
            data.asECDSABigInteger(targetDigest.outputLength).toByteArray().ensureSize(targetDigest.outputLength.bytes),
            targetDigest)

        verifyImpl(SignatureAlgorithm.ECDSA(targetDigest, null), publicKey, processed, signature, config)
    }
    else -> verifyImpl(signatureAlgorithm, publicKey, data, signature, config)
 }


internal actual fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             data: SignatureInput, signature: CryptoSignature.RSA,
             config: PlatformVerifierConfiguration) =
verifyImpl(signatureAlgorithm, publicKey, data, signature, config)
