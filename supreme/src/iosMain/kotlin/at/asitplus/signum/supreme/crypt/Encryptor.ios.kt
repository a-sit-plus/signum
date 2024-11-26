package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import at.asitplus.signum.supreme.aes.GCM
import at.asitplus.signum.supreme.aes.CBC
import at.asitplus.signum.supreme.swiftcall
import at.asitplus.signum.supreme.toByteArray
import at.asitplus.signum.supreme.toNSData
import kotlinx.cinterop.ExperimentalForeignApi
import platform.CoreCrypto.kCCDecrypt
import platform.CoreCrypto.kCCEncrypt

actual internal fun initCipher(
    algorithm: EncryptionAlgorithm,
    key: ByteArray,
    iv: ByteArray?,
    aad: ByteArray?
): PlatformCipher {
    return AESContainer(algorithm, key, iv!!, aad)
}

private data class AESContainer(
    val alg: EncryptionAlgorithm,
    val key: ByteArray,
    val iv: ByteArray?,
    val aad: ByteArray?
)

@OptIn(ExperimentalForeignApi::class)
actual internal fun PlatformCipher.encrypt(data: ByteArray): KmmResult<Ciphertext<*>> {
    this as AESContainer
    val nsData = data.toNSData()
    val nsKey = key.toNSData()
    val nsIV = iv?.toNSData()
    val nsAAD = aad?.toNSData()


    when (alg) {
        is EncryptionAlgorithm.AES.CBC.Plain -> {
            return catching{
                println("ALGORITHM : $alg doing CBC")

                val bytes: ByteArray = swiftcall {
                    CBC.crypt(kCCEncrypt.toLong(), nsData, nsKey, nsIV, error)
                }.toByteArray()
                Ciphertext.Unauthenticated(alg as EncryptionAlgorithm.Unauthenticated, bytes, iv)
            }
        }

        is EncryptionAlgorithm.AES.GCM -> {
            return catching{

                println("ALGORITHM : $alg doing GCM")
                require(iv != null) { "AES implementation error, please report this bug" }
                val ciphertext = GCM.encrypt(nsData, nsKey, nsIV, nsAAD)
                if (ciphertext == null) throw UnsupportedOperationException("Error from swift code!")

                return@catching Ciphertext.Authenticated(
                    alg as EncryptionAlgorithm.Authenticated,
                    ciphertext.ciphertext().toByteArray(),
                    ciphertext.iv().toByteArray(),
                    ciphertext.authTag().toByteArray(),
                    aad

                )
            }
        }

        else -> TODO()
    }
}

@OptIn(ExperimentalForeignApi::class)
actual internal fun Ciphertext.Authenticated.doDecrypt(secretKey: ByteArray): KmmResult<ByteArray> {
    return catching {
        swiftcall {
            GCM.decrypt(
                encryptedData.toNSData(),
                secretKey.toNSData(),
                iv!!.toNSData(),
                authTag.toNSData(),
                aad?.toNSData(),
                error
            )!!.toByteArray()
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
actual internal fun Ciphertext.Unauthenticated.doDecrypt(secretKey: ByteArray): KmmResult<ByteArray> = catching {

    swiftcall {
        CBC.crypt(
            kCCDecrypt.toLong(),
            this@doDecrypt.encryptedData.toNSData(),
            secretKey.toNSData(),
            this@doDecrypt.iv?.toNSData(),
            error
        )
    }.toByteArray()
}
