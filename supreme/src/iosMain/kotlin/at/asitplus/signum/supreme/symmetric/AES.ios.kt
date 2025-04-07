package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.ImplementationError
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import at.asitplus.signum.internals.swiftcall
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.internals.toNSData
import at.asitplus.signum.supreme.symmetric.internal.ios.GCM
import kotlinx.cinterop.*
import platform.CoreCrypto.*

private fun BlockCipher<*, *, *>.addPKCS7Padding(plain: ByteArray): ByteArray {
    val blockBytes = blockSize.bytes.toInt()
    val diff = blockBytes - (plain.size % blockBytes)
    return plain + ByteArray(diff) { diff.toByte() }
}


private fun BlockCipher<*, *, *>.removePKCS7Padding(plainWithPadding: ByteArray): ByteArray {
    val paddingBytes = plainWithPadding.last().toInt()
    require(paddingBytes > 0) { "Illegal padding: $paddingBytes" }
    require(paddingBytes <= blockSize.bytes.toInt()) { "Illegal padding: $paddingBytes" }
    require(plainWithPadding.takeLast(paddingBytes).all { it.toInt() == paddingBytes }) { "Padding not consistent" }
    require(plainWithPadding.size - paddingBytes >= 0) { "Illegal padding: $paddingBytes" }
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
            val bytes = cbcEcbCrypt(alg, encrypt = true, key, nonce, data, pad = true)
            alg.sealedBox.withNonce(nonce!!).from(bytes).getOrThrow()
        }

        is AES.ECB -> {
            val bytes = cbcEcbCrypt(alg, encrypt = true, key, nonce, data, pad = true)
            alg.sealedBox.from(bytes).getOrThrow()
        }

        is AES.WRAP.RFC3394 -> {
            val bytes = cbcEcbCrypt(alg, encrypt = true, key, nonce, data, pad = false)
            alg.sealedBox.from(bytes).getOrThrow()
        }

        is AES.GCM -> {
            val ciphertext = GCM.encrypt(data.toNSData(), key.toNSData(), nonce?.toNSData(), aad?.toNSData())
            if (ciphertext == null) throw IllegalStateException("Error from swift code!")
            alg.sealedBox.withNonce(ciphertext.iv().toByteArray()).from(
                ciphertext.ciphertext().toByteArray(),
                ciphertext.authTag().toByteArray()
            ).getOrThrow()
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

    @OptIn(ExperimentalForeignApi::class, HazardousMaterials::class)
    internal fun cbcEcbCrypt(
        algorithm: SymmetricEncryptionAlgorithm.AES<*, KeyType.Integrated, *>,
        encrypt: Boolean,
        secretKey: ByteArray,
        nonce: ByteArray?,
        data: ByteArray,
        pad: Boolean
    ): ByteArray {
        //padding check == size check at this point, regardless of whether pad is set!
        if (!encrypt) require(data.size % algorithm.blockSize.bytes.toInt() == 0) { "Illegal data size: ${data.size}" }

        //better safe than sorry
        val keySize = when (secretKey.size) {
            SymmetricEncryptionAlgorithm.AES_128.keySize.bytes.toInt() -> kCCKeySizeAES128
            SymmetricEncryptionAlgorithm.AES_192.keySize.bytes.toInt() -> kCCKeySizeAES192
            SymmetricEncryptionAlgorithm.AES_256.keySize.bytes.toInt() -> kCCKeySizeAES256
            else -> throw ImplementationError("Illegal AES key size: ${secretKey.size}")
        }

        //must be CBC
        nonce?.let { nonce ->
            if (nonce.size != kCCBlockSizeAES128.toInt())
                throw ImplementationError("Illegal AES nonce length: ${nonce.size}")
        }

        if (Int.MAX_VALUE - kCCBlockSizeAES128.toInt() < data.size)
            throw ImplementationError("Input data too large: ${data.size}")

        val bytesEncrypted = ULongArray(1)
        //account for padding
        val destination = ByteArray(kCCBlockSizeAES128.toInt() + data.size)
        val result = destination.usePinned { output ->
            secretKey.usePinned { secretKey ->
                data.let { if (encrypt && pad) algorithm.addPKCS7Padding(it) else it }.usePinned { input ->
                    bytesEncrypted.usePinned { bytesEncrypted ->
                        when (algorithm) {
                            is AES.CBC.Unauthenticated, is AES.ECB -> {
                                CCCrypt(
                                    (if (encrypt) kCCEncrypt else kCCDecrypt),
                                    (kCCAlgorithmAES),
                                    algorithm.iosOptions,
                                    secretKey.addressOf(0), keySize.toULong(),
                                    nonce?.refTo(0),
                                    input.addressOf(0), input.get().size.toULong(),
                                    output.addressOf(0), output.get().size.toULong(),
                                    bytesEncrypted.addressOf(0)
                                )
                            }

                            is AES.WRAP.RFC3394 -> {
                                //Why Apple, why???
                                bytesEncrypted.get()[0] = output.get().size.toULong()
                                //Why, Apple, Why are these separate operations and not parameterized as others???
                                if (encrypt) @Suppress("UNCHECKED_CAST") CCSymmetricKeyWrap(
                                    kCCWRAPAES,
                                    CCrfc3394_iv, CCrfc3394_ivLen,
                                    //Why, Apple, Why is it ubyte for wrap and byte for others???
                                    secretKey.addressOf(0) as CValuesRef<UByteVarOf<UByte>>, keySize.toULong(),
                                    input.addressOf(0) as CValuesRef<UByteVarOf<UByte>>, input.get().size.toULong(),
                                    output.addressOf(0) as CValuesRef<UByteVarOf<UByte>>, bytesEncrypted.addressOf(0)
                                )
                                else @Suppress("UNCHECKED_CAST") CCSymmetricKeyUnwrap(
                                    kCCWRAPAES,
                                    CCrfc3394_iv, CCrfc3394_ivLen,
                                    //why is it ubyte for wrap and byte for others???
                                    secretKey.addressOf(0) as CValuesRef<UByteVarOf<UByte>>, keySize.toULong(),
                                    input.addressOf(0) as CValuesRef<UByteVarOf<UByte>>, input.get().size.toULong(),
                                    output.addressOf(0) as CValuesRef<UByteVarOf<UByte>>, bytesEncrypted.addressOf(0)
                                )
                            }

                            else -> throw ImplementationError("Illegal State in AES ${if (encrypt) "encryption" else "decryption"}.")
                        }
                    }
                }
            }
        }
        return when {
            (result != kCCSuccess) -> throw IllegalStateException("Invalid state returned by Core Foundation call: $result")
            else -> destination.sliceArray(0..<bytesEncrypted.first().toInt()/*remove superfluous bytes*/).let {
                if (!encrypt && pad) algorithm.removePKCS7Padding(it) else it
            }
        }
    }
}

val SymmetricEncryptionAlgorithm.AES<*, KeyType.Integrated, *>.iosOptions: UInt
    get() = @OptIn(HazardousMaterials::class) when (this) {
        is AES.CBC.Unauthenticated, is AES.WRAP.RFC3394 -> 0u //no options (=manual padding).
        is AES.ECB -> kCCOptionECBMode
        else -> throw ImplementationError()
    }