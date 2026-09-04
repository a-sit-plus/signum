@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.indispensable

import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.ECDSASignature
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.indispensable.sign.RSASignature
import at.asitplus.signum.internals.*
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.memScoped
import platform.CoreFoundation.CFRelease
import platform.Foundation.NSData
import platform.Security.*

private fun RSAAlgorithm.Parameters.PssPadded.requireSupportedIosPssParameters() {
    val mgf = mgfAlgorithm
    if (!(
        mgf is RSAAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1 &&
        mgf.digest == this.digest &&
        saltLength.toInt() == digest.outputLength.bytes.toInt() &&
        trailerField == 1
    )) {
        throw UnsupportedCryptoException("iOS supports RSA-PSS only with MGF1 using the signature digest, a salt matching the digest length, and trailer field 1")
    }
}

object IndispensableIosExtensionProvider : IosMappingProvider {
    override fun signatureAlgorithmToSecKeyAlgorithm(algorithm: SignatureAlgorithm) = when (algorithm) {
        is ECDSAAlgorithm -> {
            when (algorithm.digest) {
                Digest.SHA1 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA1
                Digest.SHA256 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA256
                Digest.SHA384 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA384
                Digest.SHA512 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA512
                null -> throw UnsupportedCryptoException("Raw signing is not supported on iOS")
                else -> throw UnsupportedCryptoException("Unknown digest ${algorithm.digest} is unsupported on iOS")
            }
        }

        is RSAAlgorithm -> {
            when (val params = algorithm.parameters) {
                is RSAAlgorithm.Parameters.PssPadded -> when (val digest = params.also {
                    it.requireSupportedIosPssParameters()
                }.digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA512
                    else -> throw UnsupportedCryptoException("Digest $digest is unsupported on iOS")
                }

                is RSAAlgorithm.Parameters.Pkcs1Padded -> when (val digest = params.digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
                    else -> throw UnsupportedCryptoException("Digest $digest is unsupported on iOS")
                }
            }
        }

        else -> throw UnsupportedCryptoException("Algorithm $this is unknown")
    }

    override fun signatureAlgorithmToSecKeyAlgorithmPreHashed(algorithm: SignatureAlgorithm) = when (algorithm) {
        is ECDSAAlgorithm -> {
            when (algorithm.digest) {
                Digest.SHA1 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA1
                Digest.SHA256 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA256
                Digest.SHA384 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA384
                Digest.SHA512 -> kSecKeyAlgorithmECDSASignatureDigestX962SHA512
                null -> throw UnsupportedCryptoException("Raw signing is not supported on iOS")
                else -> throw UnsupportedCryptoException("Unknown digest ${algorithm.digest} is unsupported on iOS")
            }
        }

        is RSAAlgorithm -> {
            when (val params = algorithm.parameters) {
                is RSAAlgorithm.Parameters.PssPadded -> when (val digest = params.also {
                    it.requireSupportedIosPssParameters()
                }.digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureDigestPSSSHA512
                    else -> throw UnsupportedCryptoException("Digest $digest is unsupported on iOS")
                }

                is RSAAlgorithm.Parameters.Pkcs1Padded -> when (val digest = params.digest) {
                    Digest.SHA1 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
                    Digest.SHA256 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
                    Digest.SHA384 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
                    Digest.SHA512 -> kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
                    else -> throw UnsupportedCryptoException("Digest $digest is unsupported on iOS")
                }
            }
        }

        else -> throw UnsupportedCryptoException("Algorithm $this is unknown")
    }

    override fun parseSignatureBytes(algorithm: SignatureAlgorithm, sigBytes: ByteArray) = when (algorithm) {
        is ECDSAAlgorithm -> ECDSASignature.fromRawSignatureValue(sigBytes)
        is RSAAlgorithm -> RSASignature.fromRawSignatureValue(sigBytes)
        else -> null
    }

    override fun getSignatureBytes(signature: CryptoSignature): ByteArray? = when (signature) {
        is ECDSASignature, is RSASignature -> signature.asn1Representation.rawBytes
        else -> null
    }

    override fun cryptoPublicKeyToSecKey(key: CryptoPublicKey): OwnedCFValue<SecKeyRef>? {
        val (keyType, keyBytes) = when (key) {
            is ECDSAPublicKey -> Pair(kSecAttrKeyTypeECSECPrimeRandom, key.iosEncoded)
            is RSAPublicKey -> Pair(kSecAttrKeyTypeRSA, key.iosEncoded)
            else -> return null
        }
        memScoped {
            val attr = cfDictionaryOf(
                kSecAttrKeyClass to kSecAttrKeyClassPublic,
                kSecAttrKeyType to keyType)
            return corecall {
                SecKeyCreateWithData(keyBytes.toNSData().giveToCF(), attr, error)
            }.adopt()
        }
    }

    override fun secKeyToCryptoPublicKey(key: SecKeyRef): CryptoPublicKey? {
        memScoped {
            val keyType = corecall {
                SecKeyCopyAttributes(key).also { defer { CFRelease(it) } }
            }.getAndTake<String>(kSecAttrKeyType)
            val ctor = when (keyType) {
                kSecAttrKeyTypeRSA.toKotlinString() -> RSAPublicKey::fromPKCS1encoded
                kSecAttrKeyTypeECSECPrimeRandom.toKotlinString() -> { bytes ->
                    ECDSAPublicKey.fromAnsiX963Bytes(
                        src = bytes,
                        curve = ECCurve.fromIosEncodedPublicKeyLength(bytes.size)
                            ?: throw IllegalArgumentException("Unknown curve in iOS raw key"))
                }
                else -> return null
            }
            return ctor(corecall {
                SecKeyCopyExternalRepresentation(key, error)
            }.takeFromCF<NSData>().toByteArray())
        }
    }

    override fun cryptoPrivateKeyToSecKey(key: CryptoPrivateKey.WithPublicKey): OwnedCFValue<SecKeyRef>? {
        memScoped {
            val (keyType, keySize, keyBytes) = when (key) {
                is ECDSAPrivateKey.WithPublicKey ->
                    Triple(kSecAttrKeyTypeECSECPrimeRandom, key.curve.coordinateLength.bits.toInt(), key.publicKey.iosEncoded+key.privateKeyBytes)
                is RSAPrivateKey ->
                    Triple(kSecAttrKeyTypeRSA, key.publicKey.bits.number.toInt(), key.asPKCS1.encodeToDer())
                else -> return null
            }
            val attr = createCFDictionary {
                kSecAttrKeyClass mapsTo kSecAttrKeyClassPrivate
                kSecPrivateKeyAttrs mapsTo cfDictionaryOf(kSecAttrIsPermanent to false)
                kSecAttrKeyType mapsTo keyType
                kSecAttrKeySizeInBits mapsTo keySize
            }
            return corecall {
                SecKeyCreateWithData(keyBytes.toNSData().giveToCF(), attr, error)
            }.adopt()
        }
    }

    override fun secKeyToCryptoPrivateKey(key: SecKeyRef): CryptoPrivateKey.WithPublicKey? {
        memScoped {
            val keyType = corecall {
                SecKeyCopyAttributes(key).also { defer { CFRelease(it) } }
            }.getAndTake<String>(kSecAttrKeyType)
            val ctor: ((ByteArray)-> CryptoPrivateKey.WithPublicKey) = when (keyType) {
                kSecAttrKeyTypeRSA.toKotlinString() ->
                    RSAPrivateKey.FromPKCS1::decodeFromDer
                kSecAttrKeyTypeECSECPrimeRandom.toKotlinString() ->
                    ECDSAPrivateKey::iosDecodeInternal
                else -> return null
            }
            return corecall {
                SecKeyCopyExternalRepresentation(key, error)
            }.takeFromCF<NSData>().toByteArray().let(ctor)
        }
    }
}