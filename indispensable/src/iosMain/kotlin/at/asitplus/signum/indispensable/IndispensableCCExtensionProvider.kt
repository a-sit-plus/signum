@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.fromIosEncodedPublicKeyLength
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.internals.OwnedCFValue
import at.asitplus.signum.internals.cfDictionaryOf
import at.asitplus.signum.internals.corecall
import at.asitplus.signum.internals.corecall.Companion.invoke
import at.asitplus.signum.internals.createCFDictionary
import at.asitplus.signum.internals.get
import at.asitplus.signum.internals.manage
import at.asitplus.signum.internals.takeFromCF
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.internals.toKotlinString
import at.asitplus.signum.internals.toNSData
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.memScoped
import platform.CoreFoundation.CFRelease
import platform.Foundation.NSData
import platform.Security.SecKeyCopyAttributes
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCreateWithData
import platform.Security.SecKeyRef
import platform.Security.kSecAttrIsPermanent
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPrivate
import platform.Security.kSecAttrKeyClassPublic
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecAttrKeyTypeRSA
import platform.Security.kSecPrivateKeyAttrs

object IndispensableCCExtensionProvider : CommonCryptoExtensionProvider {
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
            }.manage()
        }
    }

    override fun secKeyToCryptoPublicKey(key: SecKeyRef): CryptoPublicKey? {
        memScoped {
            val keyType = corecall {
                SecKeyCopyAttributes(key).also { defer { CFRelease(it) } }
            }.get<String>(kSecAttrKeyType)
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
            }.manage()
        }
    }

    override fun secKeyToCryptoPrivateKey(key: SecKeyRef): CryptoPrivateKey.WithPublicKey? {
        memScoped {
            val keyType = corecall {
                SecKeyCopyAttributes(key).also { defer { CFRelease(it) } }
            }.get<String>(kSecAttrKeyType)
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