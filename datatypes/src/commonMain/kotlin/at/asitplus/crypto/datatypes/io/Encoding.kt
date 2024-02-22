package at.asitplus.crypto.datatypes.io

import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.misc.ANSI_COMPRESSED_PREFIX_1
import at.asitplus.crypto.datatypes.misc.ANSI_COMPRESSED_PREFIX_2
import at.asitplus.crypto.datatypes.misc.ANSI_UNCOMPRESSED_PREFIX
import at.asitplus.crypto.datatypes.misc.UVarInt
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

    //cannot be annotated with @Throws here because interfaces do not have annotations
    /**
     * @throws SerializationException on error
     */
    override fun deserialize(decoder: Decoder): ByteArray {
        return kotlin.runCatching { decoder.decodeString().decodeToByteArray(Base64UrlStrict) }
            .getOrElse { throw SerializationException("Base64 decoding failed", it) }
    }
}


object MultibaseHelper {
    internal const val PREFIX_DID_KEY = "did:key"

    /**
     * TODO
     *  + add private lookup table for multicodec prefixes which needs to be of form VarInt as described here https://github.com/multiformats/unsigned-varint
     *    the bits after the prefix stay in their original representation (i think) as discussed here https://github.com/w3c-ccg/did-method-key/issues/43
     *  + base58-btc encoding
     *  + leading bit in EC case should not be dropped since its valid ANSIX963 encoding according to https://github.com/w3c-ccg/did-method-key/issues/37
     *
     */

    /**
     * https://datatracker.ietf.org/doc/html/draft-multiformats-multibase
     *Magic
     * Adds correct Multibase identifier ('m') to Base64 encoding
     */
    internal fun multibaseWrapBase64(it: ByteArray) = "m${it.encodeToString(Base64Strict)}"

    /**
     * Adds correct Multicodec identifier ('0x1205') to encoded RSA key
     * See https://github.com/multiformats/multicodec/blob/master/table.csv for up-to-date table
     */
    internal fun multicodecWrapRSA(it: ByteArray) = byteArrayOf(0x12.toByte(), 0x05.toByte()) + it

    /**
     * Adds a Multicodec identifier
     * We use '0x129x' to identify uncompressed EC keys of their respective size, these are not officially used identifiers.
     * Multicodec identifiers '0x120x' are draft identifiers for P-xxx keys with point compression
     *
     *  0x1200 P-256
     *  0x1201 P-384
     *  0x1202 P-512
     *
     *  0x1290 P-256
     *  0x1291 P-384
     *  0x1292 P-512
     */
//    internal fun multiCodecWrapEC(curve: EcCurve, it: ByteArray) =
//        when (it[0]) {
//            ANSI_COMPRESSED_PREFIX_1, ANSI_COMPRESSED_PREFIX_2 ->
//                when (curve) {
//                    EcCurve.SECP_256_R_1 -> UVarInt(byteArrayOf(0x12.toByte(), 0x00.toByte())).toByteArray() + it
//                    EcCurve.SECP_384_R_1 -> UVarInt(byteArrayOf(0x12.toByte(), 0x01.toByte())).toByteArray() + it
//                    EcCurve.SECP_521_R_1 -> UVarInt(byteArrayOf(0x12.toByte(), 0x02.toByte())).toByteArray() + it
//                }
//
//            ANSI_UNCOMPRESSED_PREFIX ->
//                when (curve) {
//                    EcCurve.SECP_256_R_1 -> UVarInt(byteArrayOf(0x12.toByte(), 0x00.toByte())).toByteArray() + it
//                    EcCurve.SECP_384_R_1 -> UVarInt(byteArrayOf(0x12.toByte(), 0x00.toByte())).toByteArray() + it
//                    EcCurve.SECP_521_R_1 -> UVarInt(byteArrayOf(0x12.toByte(), 0x00.toByte())).toByteArray() + it
//                }
//
//            else -> throw Exception("Some Exception")
//        }

    @Throws(Throwable::class)
    internal fun multiKeyRemovePrefix(keyId: String): String =
        keyId.takeIf { it.startsWith("$PREFIX_DID_KEY:") }?.removePrefix("$PREFIX_DID_KEY:")
            ?: throw IllegalArgumentException("Input does not specify public key")

    @Throws(Throwable::class)
    private fun multibaseDecode(it: String): ByteArray =
        when (it.first()) {
            'm' -> it.removePrefix("m").decodeToByteArrayOrNull(Base64Strict)
                ?: throw SerializationException("Base64 decoding failed")

            'z' -> TODO("Support Base58-Bitcoin not implemented")
            else -> throw IllegalArgumentException("Encoding not supported")
        }

    @Throws(Throwable::class)
    internal fun bytesFromDid(keyId: String): ByteArray = multibaseDecode(multiKeyRemovePrefix(keyId))
}

//fun BitSet.slice(start: Int, end: Int): BitSet {
//    val counter = 0L
//    val res = BitSet()
//    while (end >= counter + start){
//        res[counter] = this[counter + start]
//    }
//    return res
//}

//fun BitSet.toVarIntEncoded(): BitSet {
//    var vector = this
//    var counter: Long = 0
//    var offset = 0L
//    val res = BitSet()
//
//    for (i in vector) {
//        if (counter.mod(7) != 0 || counter == 0L) {
//            res[counter + offset] = i
//        } else {
//            res[counter + offset] = true
//            offset++
//        }
//        counter++
//    }
//    return res
//}