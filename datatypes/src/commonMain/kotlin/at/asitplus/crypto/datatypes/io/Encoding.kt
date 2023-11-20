package at.asitplus.crypto.datatypes.io

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.asn1.Asn1Primitive
import at.asitplus.crypto.datatypes.asn1.BERTags
import at.asitplus.crypto.datatypes.asn1.asn1Sequence
import at.asitplus.crypto.datatypes.asn1.ensureSize
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.base64.Base64ConfigBuilder
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Strict Base64 URL encode
 */
val Base64UrlStrict = Base64(config = Base64ConfigBuilder().apply {
    lineBreakInterval = 0
    encodeToUrlSafe = true
    isLenient = true
    padEncoded = false
}.build())


/**
 * Strict Base64 encoder
 */
val Base64Strict = Base64(config = Base64ConfigBuilder().apply {
    lineBreakInterval = 0
    encodeToUrlSafe = false
    isLenient = true
    padEncoded = true
}.build())


/**
 * De-/serializes Base64 strings to/from [ByteArray]
 */
object ByteArrayBase64Serializer : KSerializer<ByteArray> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteArrayBase64Serializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(value.encodeToString(Base64Strict))
    }

    //cannot annotate with throws here because interface has no annotation
    /**
     * @throws SerializationException on error
     */
    override fun deserialize(decoder: Decoder): ByteArray {
        return kotlin.runCatching { decoder.decodeString().decodeToByteArray(Base64Strict) }
            .getOrElse { throw SerializationException("Base64 decoding failed", it) }
    }

}


/**
 * De-/serializes Base64Url strings to/from [ByteArray]
 */
object ByteArrayBase64UrlSerializer : KSerializer<ByteArray> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteArrayBase64UrlSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(value.encodeToString(Base64UrlStrict))
    }

    //cannot annotate with throws here because interface has no annotation
    /**
     * @throws SerializationException on error
     */
    override fun deserialize(decoder: Decoder): ByteArray {
        return kotlin.runCatching { decoder.decodeString().decodeToByteArray(Base64UrlStrict) }
            .getOrElse { throw SerializationException("Base64 decoding failed", it) }
    }
}


object MultibaseHelper {
    private const val PREFIX_DID_KEY = "did:key"

    private fun multibaseWrapBase64(it: ByteArray) = "m${it.encodeToString(Base64Strict)}"

    private fun multicodecWrapRSA(it: ByteArray) = byteArrayOf(0x12.toByte(), 0x05.toByte()) + it

    // 0x1200 would be with compression, so we'll use 0x1290
    private fun multicodecWrapEC(it: ByteArray) = byteArrayOf(0x12.toByte(), 0x90.toByte()) + it

    /**
     * Returns something like `did:key:mEpA...` with the [x] and [y] values appended in Base64.
     * This translates to `Base64(0x12, 0x90, EC-P-{256,384,521}-Key)`.
     * Note that `0x1290` is not an official Multicodec prefix, but there seems to be none for
     * uncompressed P-256 key. We can't use the compressed format, because decoding that would
     * require some EC Point math...
     */
    fun calcKeyId(key: CryptoPublicKey): String {
        return when (key) {
            is CryptoPublicKey.Ec -> "$PREFIX_DID_KEY:${
                multibaseWrapBase64(
                    multicodecWrapEC(
                        key.iosEncoded.drop(1).toByteArray()
                    )
                )
            }"

            is CryptoPublicKey.Rsa -> "$PREFIX_DID_KEY:${multibaseWrapBase64(multicodecWrapRSA(key.iosEncoded))}"
        }
    }

    @Throws(Throwable::class)
    private fun multiKeyRemovePrefix(keyId: String): String =
        keyId.takeIf { it.startsWith("$PREFIX_DID_KEY:") }?.removePrefix("$PREFIX_DID_KEY:")
            ?: throw IllegalArgumentException("Key ID does not specify public key")

    @Throws(Throwable::class)
    private fun multibaseDecode(it: String): ByteArray =
        if (it.startsWith("m")) {
            it.removePrefix("m").decodeToByteArrayOrNull(Base64Strict)
                ?: throw SerializationException("Base64 decoding failed")
        } else throw IllegalArgumentException("Encoding not supported")

    @Throws(Throwable::class)
    private fun multiKeyGetKty(it: ByteArray): Pair<Boolean, ByteArray> =
        if (it.size <= 3) {
            throw IllegalArgumentException("Invalid key size")
        } else if (it[0] != 0x12.toByte()) {
            throw IllegalArgumentException("Unknown public key identifier")
        } else when (it[1]) {
            0x90.toByte() -> true to it.drop(2).toByteArray()  // Case EC
            0x05.toByte() -> false to it.drop(2).toByteArray() // Case RSA
            else -> throw IllegalArgumentException("Unknown public key identifier")
        }

    @Throws(Throwable::class)
    internal fun decodeKeyId(keyId: String): Pair<Boolean, ByteArray> =
        multiKeyGetKty(multibaseDecode(multiKeyRemovePrefix(keyId)))
}