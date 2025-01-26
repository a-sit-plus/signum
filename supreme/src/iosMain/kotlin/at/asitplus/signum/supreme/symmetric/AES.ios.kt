package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.BlockCipher
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import at.asitplus.signum.indispensable.symmetric.sealedBox
import at.asitplus.signum.internals.swiftcall
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.internals.toNSData
import at.asitplus.signum.supreme.aes.CBC
import at.asitplus.signum.supreme.aes.ECB
import at.asitplus.signum.supreme.aes.GCM
import kotlinx.cinterop.ExperimentalForeignApi
import platform.CoreCrypto.kCCDecrypt
import platform.CoreCrypto.kCCEncrypt


private fun BlockCipher<*, *, *>.addPKCS7Padding(plain: ByteArray): ByteArray {
    val blockBytes = blockSize.bytes.toInt()
    val diff = blockBytes - (plain.size % blockBytes)
    return if (diff == 0)
        plain + ByteArray(blockBytes) { blockBytes.toByte() }
    else plain + ByteArray(diff) { diff.toByte() }
}


private fun BlockCipher<*, *, *>.removePKCS7Padding(plainWithPadding: ByteArray): ByteArray {
    val paddingBytes = plainWithPadding.last().toInt()
    require(paddingBytes > 0) { "Illegal padding: $paddingBytes" }
    require(plainWithPadding.takeLast(paddingBytes).all { it.toInt() == paddingBytes }) { "Padding not consistent" }
    require(plainWithPadding.size - paddingBytes >= 0) { "Too much padding: data ${plainWithPadding.joinToString()}" }
    return plainWithPadding.sliceArray(0..<plainWithPadding.size - paddingBytes)
}


internal object AESIOS {
    @OptIn(ExperimentalForeignApi::class, HazardousMaterials::class)
    fun encrypt(
        alg: SymmetricEncryptionAlgorithm.AES<*, *, *>,
        data: ByteArray,
        key: ByteArray,
        nonce: ByteArray?,
        aad: ByteArray?
    ) = when (alg) {
        is AES.CBC.Unauthenticated -> {
            val padded = (alg as AES<*, *, *>).addPKCS7Padding(data)
            val bytes: ByteArray = swiftcall {
                CBC.crypt(kCCEncrypt.toLong(), padded.toNSData(), key.toNSData(), nonce!!.toNSData(), error)
            }.toByteArray()
            alg.sealedBox(nonce!!, bytes)
        }

        is AES.ECB -> {
            val padded = (alg as AES<*, *, *>).addPKCS7Padding(data)
            val bytes: ByteArray = swiftcall {
                ECB.crypt(kCCEncrypt.toLong(), padded.toNSData(), key.toNSData(), error)
            }.toByteArray()
            alg.sealedBox(bytes)
        }

        is AES.GCM -> {
            val ciphertext = GCM.encrypt(data.toNSData(), key.toNSData(), nonce?.toNSData(), aad?.toNSData())
            if (ciphertext == null) throw UnsupportedOperationException("Error from swift code!")
            alg.sealedBox(
                ciphertext.iv().toByteArray(),
                ciphertext.ciphertext().toByteArray(),
                ciphertext.authTag().toByteArray(),
                aad
            )
        }

        else -> TODO("ALGORITHM UNSUPPORTED")
    }

    internal fun gcmDecrypt(
        encryptedData: ByteArray,
        secretKey: ByteArray,
        nonce: ByteArray,
        authTag: ByteArray,
        authenticatedData: ByteArray?
    ): ByteArray = swiftcall {
        @OptIn(ExperimentalForeignApi::class)
        GCM.decrypt(
            encryptedData.toNSData(),
            secretKey.toNSData(),
            nonce.toNSData(),
            authTag.toNSData(),
            authenticatedData?.toNSData(),
            error
        )
    }.toByteArray()


    internal fun cbcEcbDecrypt(
        algorithm: SymmetricEncryptionAlgorithm.AES<*, *, *>,
        encryptedData: ByteArray,
        secretKey: ByteArray,
        nonce: ByteArray?
    ): ByteArray {
        val decrypted = swiftcall {
            @OptIn(ExperimentalForeignApi::class, HazardousMaterials::class)
            when (algorithm) {
                is AES.CBC.Unauthenticated -> CBC.crypt(
                    kCCDecrypt.toLong(),
                    encryptedData.toNSData(),
                    secretKey.toNSData(),
                    nonce!!.toNSData(),
                    error
                )

                is AES.ECB -> ECB.crypt(
                    kCCDecrypt.toLong(),
                    encryptedData.toNSData(),
                    secretKey.toNSData(),
                    error
                )
                else -> TODO("UNSUPPORTED")
            }


        }.toByteArray()
        return (algorithm).removePKCS7Padding(decrypted)
    }
}

