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
     * Simple Ec Key encoding, if appended with ANSI_PREFIX then valid ANSI X9.63 encoding
     * No compression, because decompression would need some EC math
     */
    fun encodeEcKey(key: CryptoPublicKey.Ec): ByteArray =
        key.x.ensureSize(key.curve.coordinateLengthBytes) + key.y.ensureSize(key.curve.coordinateLengthBytes)

    /**
     * PKCS#1 encoded RSA Public Key
     */
    fun encodeRsaKey(key: CryptoPublicKey.Rsa): ByteArray =
        asn1Sequence {
            append(
                Asn1Primitive(
                    BERTags.INTEGER,
                    key.n.ensureSize(key.bits.number / 8u)
                        .let { if (it.first() == 0x00.toByte()) it else byteArrayOf(0x00, *it) })
            )
            int(key.e)
        }.derEncoded

    /**
     * Returns something like `did:key:mEpA...` with the [x] and [y] values appended in Base64.
     * This translates to `Base64(0x12, 0x90, EC-P-{256,384,521}-Key)`.
     * Note that `0x1290` is not an official Multicodec prefix, but there seems to be none for
     * uncompressed P-256 key. We can't use the compressed format, because decoding that would
     * require some EC Point math...
     */
    fun calcKeyId(key: CryptoPublicKey): String {
        return when (key) {
            is CryptoPublicKey.Ec -> "$PREFIX_DID_KEY:${multibaseWrapBase64(multicodecWrapEC(encodeEcKey(key)))}"
            is CryptoPublicKey.Rsa -> "$PREFIX_DID_KEY:${multibaseWrapBase64(multicodecWrapRSA(key.iosEncoded))}"
        }
    }

    @Throws(Throwable::class)
    private fun multiKeyRemovePrefix(keyId: String): String =
        keyId.takeIf { it.startsWith("$PREFIX_DID_KEY:") }?.removePrefix("$PREFIX_DID_KEY:")
            ?: throw IllegalArgumentException("Key ID does not specify public key")

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
    private fun multibaseDecode(it: String): ByteArray =
        if (it.startsWith("m")) {
            it.removePrefix("m").decodeToByteArrayOrNull(Base64Strict)
                ?: throw SerializationException("Base64 decoding failed")
        } else throw IllegalArgumentException("Encoding not supported")

    @Throws(Throwable::class)
    private fun decodeEcKey(it: ByteArray): CryptoPublicKey {
        val bytes = byteArrayOf(CryptoPublicKey.Ec.ANSI_PREFIX, *it)
        return CryptoPublicKey.Ec.fromAnsiX963Bytes(bytes)
    }

    @Throws(Throwable::class)
    private fun decodeRsaKey(it: ByteArray): CryptoPublicKey =
        CryptoPublicKey.Rsa.fromPKCS1encoded(it)

    @Throws(Throwable::class)
    private fun decodeKeyId(keyId: String): Pair<Boolean, ByteArray> =
        multiKeyGetKty(multibaseDecode(multiKeyRemovePrefix(keyId)))

    @Throws(Throwable::class)
    internal fun calcPublicKey(keyId: String): CryptoPublicKey {
        val multiKey = decodeKeyId(keyId)
        return when (multiKey.first) {
            true -> decodeEcKey(multiKey.second)
            false -> decodeRsaKey(multiKey.second)
        }
    }

    //These two functions will remain until the latest version of this lib is integrated back into che VC lib.
    @Deprecated("Use [CryptoPublicKey.fromKeyId] instead")
    fun calcEcPublicKeyCoords(keyId: String): Pair<ByteArray, ByteArray>? {
        if (!keyId.startsWith("$PREFIX_DID_KEY:")) return null
        val stripped = keyId.removePrefix("$PREFIX_DID_KEY:")
        val multibaseDecode = multibaseDecode(stripped)
        val multiKey = multiKeyGetKty(multibaseDecode)

        return decodeEcKeyDep(multiKey.second)
    }


    @Deprecated("Use [Ec.fromAnsiX963Bytes] instead")
    // No decompression, because that would need some EC math
    private fun decodeEcKeyDep(it: ByteArray?): Pair<ByteArray, ByteArray>? {
        if (it == null) return null
        val half: Int = it.size.floorDiv(2)
        val x = it.sliceArray(0 until half)
        val y = it.sliceArray(half until it.size)
        return Pair(x, y)
    }
}