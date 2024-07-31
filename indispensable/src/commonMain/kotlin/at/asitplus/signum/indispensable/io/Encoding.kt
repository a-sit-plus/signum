package at.asitplus.signum.indispensable.io

import at.asitplus.catching
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.base64.Base64ConfigBuilder
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
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

    /**
     * @throws SerializationException on error
     */
    override fun deserialize(decoder: Decoder): ByteArray {
        return catching { decoder.decodeString().decodeToByteArray(Base64Strict) }
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

    //cannot be annotated with @Throws here because interfaces do not have annotations
    /**
     * @throws SerializationException on error
     */
    override fun deserialize(decoder: Decoder): ByteArray =
        catching { decoder.decodeString().decodeToByteArray(Base64UrlStrict) }
            .getOrElse { throw SerializationException("Base64 decoding failed", it) }

}