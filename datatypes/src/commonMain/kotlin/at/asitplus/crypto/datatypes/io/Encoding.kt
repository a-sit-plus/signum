package at.asitplus.crypto.datatypes.io

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.asn1.JwsExtensions.ensureSize
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.base64.Base64ConfigBuilder
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

val Base64UrlStrict = Base64(config = Base64ConfigBuilder().apply {
    lineBreakInterval = 0
    encodeToUrlSafe = true
    isLenient = true
    padEncoded = false
}.build())


val Base64Strict = Base64(config = Base64ConfigBuilder().apply {
    lineBreakInterval = 0
    encodeToUrlSafe = false
    isLenient = true
    padEncoded = true
}.build())


object ByteArrayBase64Serializer : KSerializer<ByteArray> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteArrayBase64Serializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(value.encodeToString(Base64Strict))
    }

    override fun deserialize(decoder: Decoder): ByteArray {
        return decoder.decodeString().decodeToByteArrayOrNull(Base64Strict) ?: byteArrayOf()
    }

}

object ByteArrayBase64UrlSerializer : KSerializer<ByteArray> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteArrayBase64UrlSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(value.encodeToString(Base64UrlStrict))
    }

    override fun deserialize(decoder: Decoder): ByteArray {
        return decoder.decodeString().decodeToByteArrayOrNull(Base64UrlStrict) ?: byteArrayOf()
    }

}

object MultibaseHelper {
    private const val PREFIX_DID_KEY = "did:key"

    /**
     * Returns something like `did:key:mEpA...` with the [x] and [y] values appended in Base64.
     * This translates to `Base64(0x12, 0x90, EC-P-{256,384,521}-Key)`.
     * Note that `0x1290` is not an official Multicodec prefix, but there seems to be none for
     * uncompressed P-256 key. We can't use the compressed format, because decoding that would
     * require some EC Point math...
     */
    fun calcKeyId(curve: EcCurve, x: ByteArray, y: ByteArray) =
        "$PREFIX_DID_KEY:${multibaseWrapBase64(multicodecWrapEC(encodeEcKey(x, y, curve)))}"


    fun calcKid(rsaPublicKey: CryptoPublicKey.Rsa) =
        "$PREFIX_DID_KEY:${multibaseWrapBase64(multicodecWrapRSA(rsaPublicKey.encoded))}"


    fun calcEcPublicKeyCoords(keyId: String): Pair<ByteArray, ByteArray>? {
        if (!keyId.startsWith("$PREFIX_DID_KEY:")) return null
        val stripped = keyId.removePrefix("$PREFIX_DID_KEY:")
        val multibaseDecode = multibaseDecode(stripped)
        val multiKey = multiKeyDecode(multibaseDecode) ?: return null

        return if (multiKey.first) decodeEcKey(multiKey.second) else TODO("ASN1 decoding of RSA keys")
    }

    private fun multibaseWrapBase64(it: ByteArray) = "m${it.encodeToString(Base64Strict)}"

    private fun multibaseDecode(it: String?) =
        if (it != null && it.startsWith("m")) {
            it.removePrefix("m").decodeToByteArrayOrNull(Base64Strict)
        } else null

    // 0x1200 would be with compression, so we'll use 0x1290
    private fun multicodecWrapEC(it: ByteArray) = byteArrayOf(0x12.toByte(), 0x90.toByte()) + it

    // 0x1200 would be with compression, so we'll use 0x1290
    private fun multicodecWrapRSA(it: ByteArray) = byteArrayOf(0x12.toByte(), 0x05.toByte()) + it

    // 0x1200 would be with compression, so we'll use 0x1290
    private fun multiKeyDecode(it: ByteArray?) =
        if (it != null && it.size > 3 && it[0] == 0x12.toByte()) {
            if (it[1] == 0x90.toByte()) {
                true to it.drop(2).toByteArray()
            } else if (it[1] == 0x05.toByte()) {
                false to it.drop(2).toByteArray()
            } else null
        } else null

    // No compression, because decompression would need some EC math
    private fun encodeEcKey(x: ByteArray, y: ByteArray, curve: EcCurve) =
        x.ensureSize(curve.coordinateLengthBytes) + y.ensureSize(curve.coordinateLengthBytes)

    // No decompression, because that would need some EC math
    private fun decodeEcKey(it: ByteArray?): Pair<ByteArray, ByteArray>? {
        if (it == null) return null
        val half: Int = it.size.floorDiv(2)
        val x = it.sliceArray(0 until half)
        val y = it.sliceArray(half until it.size)
        return Pair(x, y)
    }
}