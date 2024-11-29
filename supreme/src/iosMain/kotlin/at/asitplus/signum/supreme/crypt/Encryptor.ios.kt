package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.AuthTrait
import at.asitplus.signum.indispensable.BlockCipher
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.SymmetricEncryptionAlgorithm.AES
import at.asitplus.signum.supreme.aes.CBC
import at.asitplus.signum.supreme.aes.GCM
import at.asitplus.signum.supreme.swiftcall
import at.asitplus.signum.supreme.toByteArray
import at.asitplus.signum.supreme.toNSData
import kotlinx.cinterop.ExperimentalForeignApi
import platform.CoreCrypto.kCCDecrypt
import platform.CoreCrypto.kCCEncrypt


internal actual fun <T, A : AuthTrait, E : SymmetricEncryptionAlgorithm<A>> initCipher(
    algorithm: E,
    key: ByteArray,
    macKey: ByteArray?,
    iv: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A> {
    if (algorithm !is SymmetricEncryptionAlgorithm.WithIV<*>) TODO()
    val nonce = iv ?: algorithm.randomIV()
    return CipherParam<ByteArray, A>(algorithm, key, macKey ?: key, nonce, aad) as CipherParam<T, A>
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun <A : AuthTrait> CipherParam<*, A>.doEncrypt(data: ByteArray): KmmResult<Ciphertext<A, SymmetricEncryptionAlgorithm<A>>> {
    this as CipherParam<ByteArray, A>
    require(iv != null)
    val nsIV = iv.toNSData()
    val nsAAD = aad?.toNSData()


    when (alg) {
        is SymmetricEncryptionAlgorithm.AES.CBC.Plain -> {
            return catching {
                val padded = (alg as AES<*>).addPKCS7Padding(data)
                val bytes: ByteArray = swiftcall {
                    CBC.crypt(kCCEncrypt.toLong(), padded.toNSData(), platformData.toNSData(), nsIV, error)
                }.toByteArray()
                Ciphertext.Unauthenticated(
                    alg as SymmetricEncryptionAlgorithm.Unauthenticated,
                    bytes,
                    iv
                ) as Ciphertext<out A, SymmetricEncryptionAlgorithm<A>>
            }
        }

        is SymmetricEncryptionAlgorithm.AES.GCM -> {
            return catching {

                require(iv != null) { "AES implementation error, please report this bug" }
                val ciphertext = GCM.encrypt(data.toNSData(), platformData.toNSData(), nsIV, nsAAD)
                if (ciphertext == null) throw UnsupportedOperationException("Error from swift code!")

                return@catching Ciphertext.Authenticated(
                    alg as SymmetricEncryptionAlgorithm.Authenticated,
                    ciphertext.ciphertext().toByteArray(),
                    ciphertext.iv().toByteArray(),
                    ciphertext.authTag().toByteArray(),
                    aad

                ) as Ciphertext<A, SymmetricEncryptionAlgorithm<A>>
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
    require(plainWithPadding.size - paddingBytes >= 0) { "Too much padding: data ${plainWithPadding.joinToString()}" }
    return plainWithPadding.sliceArray(0..<plainWithPadding.size - paddingBytes)
}


@OptIn(ExperimentalForeignApi::class)
actual internal fun Ciphertext.Authenticated.doDecrypt(secretKey: ByteArray): KmmResult<ByteArray> {
    return catching {
        if (algorithm !is SymmetricEncryptionAlgorithm.WithIV<*>) TODO()
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
            ).toByteArray()
        }

    }
}

@OptIn(ExperimentalForeignApi::class)
actual internal fun Ciphertext.Unauthenticated.doDecrypt(secretKey: ByteArray): KmmResult<ByteArray> = catching {
    if (algorithm !is SymmetricEncryptionAlgorithm.WithIV<*>) TODO()
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
    (algorithm as AES<*>).removePKCS7Padding(decrypted)
}
