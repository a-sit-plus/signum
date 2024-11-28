package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.AuthTrait
import at.asitplus.signum.indispensable.BlockCipher
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import at.asitplus.signum.indispensable.EncryptionAlgorithm.AES
import at.asitplus.signum.supreme.aes.CBC
import at.asitplus.signum.supreme.aes.GCM
import at.asitplus.signum.supreme.swiftcall
import at.asitplus.signum.supreme.toByteArray
import at.asitplus.signum.supreme.toNSData
import kotlinx.cinterop.ExperimentalForeignApi
import org.kotlincrypto.SecureRandom
import platform.CoreCrypto.kCCDecrypt
import platform.CoreCrypto.kCCEncrypt


private val secureRandom = SecureRandom()

actual internal fun <T, A : AuthTrait, E : EncryptionAlgorithm<A>> initCipher(
    algorithm: E,
    key: ByteArray,
    macKey: ByteArray?,
    iv: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A> {
    if (algorithm !is EncryptionAlgorithm.WithIV<*>) TODO()
    val nonce = iv ?: secureRandom.nextBytesOf(algorithm.ivNumBits.toInt() / 8)
    return CipherParam<ByteArray, A>(algorithm, key, macKey ?: key, nonce, aad) as CipherParam<T, A>
}

@OptIn(ExperimentalForeignApi::class)
actual internal fun <A : AuthTrait> CipherParam<*, A>.encrypt(data: ByteArray): KmmResult<Ciphertext<A, EncryptionAlgorithm<A>>> {
    this as CipherParam<ByteArray, A>
    require(iv != null)
    val nsIV = iv.toNSData()
    val nsAAD = aad?.toNSData()


    when (alg) {
        is EncryptionAlgorithm.AES.CBC.Plain -> {
            return catching {
                val padded = (alg as AES<*>).addPKCS7Padding(data)
                println("PADDED len: ${padded.size}")
                val bytes: ByteArray = swiftcall {
                    CBC.crypt(kCCEncrypt.toLong(), padded.toNSData(), platformData.toNSData(), nsIV, error)
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
                val ciphertext = GCM.encrypt(data.toNSData(), platformData.toNSData(), nsIV, nsAAD)
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

private fun BlockCipher<*>.addPKCS7Padding(plain: ByteArray): ByteArray {
    val blockBytes = blockSizeBits.toInt() / 8
    val diff = blockBytes - (plain.size % blockBytes)
    return if (diff == 0)
        plain + ByteArray(blockBytes) { blockBytes.toByte() }
    else plain + ByteArray(diff) { diff.toByte() }
}


private fun BlockCipher<*>.removePKCS7Padding(plainWithPadding: ByteArray): ByteArray {
    val paddingBytes = plainWithPadding.last().toInt()
    require(paddingBytes > 0) { "Illegal padding: $paddingBytes" }
    require(plainWithPadding.takeLast(paddingBytes).all { it.toInt() == paddingBytes }) { "Padding not consistent" }
    require(plainWithPadding.size - paddingBytes > 0) { "Too much padding" }
    return plainWithPadding.sliceArray(0..<plainWithPadding.size - paddingBytes)
}


@OptIn(ExperimentalForeignApi::class)
actual internal fun Ciphertext.Authenticated.doDecrypt(secretKey: ByteArray): KmmResult<ByteArray> {
    return catching {
        if (algorithm !is EncryptionAlgorithm.WithIV<*>) TODO()
        require(iv != null) { "IV must not be null!" }
        require(algorithm is AES<*>) { "Only AES is supported" }
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
    if (algorithm !is EncryptionAlgorithm.WithIV<*>) TODO()
    require(iv != null) { "IV must not be null!" }
    val decrypted = swiftcall {
        CBC.crypt(
            kCCDecrypt.toLong(),
            this@doDecrypt.encryptedData.toNSData(),
            secretKey.toNSData(),
            this@doDecrypt.iv!!.toNSData(),
            error
        )
    }.toByteArray()
    (algorithm as BlockCipher<*>).removePKCS7Padding(decrypted)
}
