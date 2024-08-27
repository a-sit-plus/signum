@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.indispensable

import kotlinx.cinterop.ExperimentalForeignApi
import platform.Security.SecKeyAlgorithm
import platform.Security.kSecKeyAlgorithmECDSASignatureDigestX962SHA1
import platform.Security.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
import platform.Security.kSecKeyAlgorithmECDSASignatureDigestX962SHA384
import platform.Security.kSecKeyAlgorithmECDSASignatureDigestX962SHA512
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA1
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA256
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA384
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA512
import platform.Security.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
import platform.Security.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
import platform.Security.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
import platform.Security.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
import platform.Security.kSecKeyAlgorithmRSASignatureDigestPSSSHA1
import platform.Security.kSecKeyAlgorithmRSASignatureDigestPSSSHA256
import platform.Security.kSecKeyAlgorithmRSASignatureDigestPSSSHA384
import platform.Security.kSecKeyAlgorithmRSASignatureDigestPSSSHA512
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA1
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA256
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA384
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA512

val SignatureAlgorithm.secKeyAlgorithm : SecKeyAlgorithm get() = when (this) {
    is SignatureAlgorithm.ECDSA -> {
        when (digest) {
            Digest.SHA1 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA1
            Digest.SHA256 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA256
            Digest.SHA384 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA384
            Digest.SHA512 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA512
            else -> throw IllegalArgumentException("Raw signing is not supported on iOS")
        }
    }
    is SignatureAlgorithm.RSA -> {
        when (padding) {
            RSAPadding.PSS -> when (digest) {
                Digest.SHA1 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA1
                Digest.SHA256 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA256
                Digest.SHA384 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA384
                Digest.SHA512 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA512
            }
            RSAPadding.PKCS1 -> when (digest) {
                Digest.SHA1 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1
                Digest.SHA256 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
                Digest.SHA384 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
                Digest.SHA512 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
            }
        }
    }
    is SignatureAlgorithm.HMAC -> TODO("HMAC is unsupported")
}!!

val SignatureAlgorithm.secKeyAlgorithmPreHashed: SecKeyAlgorithm get() = when (this) {
    is SignatureAlgorithm.ECDSA -> {
        when (digest) {
            Digest.SHA1 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA1
            Digest.SHA256 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA256
            Digest.SHA384 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA384
            Digest.SHA512 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA512
            else -> throw IllegalArgumentException("Raw signing is not supported on iOS")
        }
    }
    is SignatureAlgorithm.RSA -> {
        when (padding) {
            RSAPadding.PSS -> when (digest) {
                Digest.SHA1 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA1
                Digest.SHA256 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA256
                Digest.SHA384 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA384
                Digest.SHA512 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA512
            }
            RSAPadding.PKCS1 -> when (digest) {
                Digest.SHA1 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
                Digest.SHA256 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
                Digest.SHA384 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
                Digest.SHA512 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
            }
        }
    }
    is SignatureAlgorithm.HMAC -> TODO("HMAC is unsupported")
}!!
