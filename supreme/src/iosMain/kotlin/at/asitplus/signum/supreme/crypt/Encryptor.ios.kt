package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.AuthTrait
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import at.asitplus.signum.supreme.aes.CBC
import at.asitplus.signum.supreme.aes.GCM
import at.asitplus.signum.supreme.swiftcall
import at.asitplus.signum.supreme.toByteArray
import at.asitplus.signum.supreme.toNSData
import kotlinx.cinterop.ExperimentalForeignApi
import platform.CoreCrypto.kCCDecrypt
import platform.CoreCrypto.kCCEncrypt

actual internal fun <T, A : AuthTrait, E : EncryptionAlgorithm<A>> initCipher(
    algorithm: E,
    key: ByteArray,
    macKey: ByteArray?,
    iv: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A>{
    return CipherParam<ByteArray, A>(algorithm, key, macKey?:key, iv, aad) as CipherParam<T, A>
}

@OptIn(ExperimentalForeignApi::class)
actual internal fun <A : AuthTrait> CipherParam<*, A>.encrypt(data: ByteArray): KmmResult<Ciphertext<A, EncryptionAlgorithm<A>>> {
    this as CipherParam<ByteArray, A>
    val nsData = data.toNSData()
    val nsIV = iv?.toNSData()
    val nsAAD = aad?.toNSData()


    when (alg) {
        is EncryptionAlgorithm.AES.CBC.Plain -> {
            return catching {
                println("ALGORITHM : $alg doing CBC")

                val bytes: ByteArray = swiftcall {
                    CBC.crypt(kCCEncrypt.toLong(), nsData, platformData.toNSData(), nsIV, error)
                }.toByteArray()
                Ciphertext.Unauthenticated(
                    alg as EncryptionAlgorithm.Unauthenticated,
                    bytes,
                    iv
                ) as Ciphertext<out A, EncryptionAlgorithm<A>>
            }
        }

        is EncryptionAlgorithm.AES.GCM -> {
            return catching {

                require(iv != null) { "AES implementation error, please report this bug" }
                val ciphertext = GCM.encrypt(nsData, platformData.toNSData(), nsIV, nsAAD)
                if (ciphertext == null) throw UnsupportedOperationException("Error from swift code!")

                return@catching Ciphertext.Authenticated(
                    alg as EncryptionAlgorithm.Authenticated,
                    ciphertext.ciphertext().toByteArray(),
                    ciphertext.iv().toByteArray(),
                    ciphertext.authTag().toByteArray(),
                    aad

                ) as Ciphertext<A, EncryptionAlgorithm<A>>
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
