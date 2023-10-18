package at.asitplus.crypto.datatypes.io

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.asn1.decodeFromDer
import at.asitplus.crypto.datatypes.asn1.ensureSize
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

    override fun deserialize(decoder: Decoder): ByteArray {
        return decoder.decodeString().decodeToByteArrayOrNull(Base64Strict) ?: byteArrayOf()
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

    override fun deserialize(decoder: Decoder): ByteArray {
        return decoder.decodeString().decodeToByteArrayOrNull(Base64UrlStrict) ?: byteArrayOf()
    }

}

object MultibaseHelper {
    private const val PREFIX_DID_KEY = "did:key"

    private fun multibaseWrapBase64(it: ByteArray) = "m${it.encodeToString(Base64Strict)}"

    // 0x1200 would be with compression, so we'll use 0x1290
    private fun multicodecWrapEC(it: ByteArray) = byteArrayOf(0x12.toByte(), 0x90.toByte()) + it

    // 0x1200 would be with compression, so we'll use 0x1290
    private fun multicodecWrapRSA(it: ByteArray) = byteArrayOf(0x12.toByte(), 0x05.toByte()) + it

    // No compression, because decompression would need some EC math
    private fun encodeEcKey(x: ByteArray, y: ByteArray, curve: EcCurve) =
        x.ensureSize(curve.coordinateLengthBytes) + y.ensureSize(curve.coordinateLengthBytes)

    /**
     * Returns something like `did:key:mEpA...` with the [x] and [y] values appended in Base64.
     * This translates to `Base64(0x12, 0x90, EC-P-{256,384,521}-Key)`.
     * Note that `0x1290` is not an official Multicodec prefix, but there seems to be none for
     * uncompressed P-256 key. We can't use the compressed format, because decoding that would
     * require some EC Point math...
     */
    fun calcKeyId(curve: EcCurve, x: ByteArray, y: ByteArray) =
        "$PREFIX_DID_KEY:${multibaseWrapBase64(multicodecWrapEC(encodeEcKey(x, y, curve)))}"

    fun calcKeyId(rsaPublicKey: CryptoPublicKey.Rsa) =
        "$PREFIX_DID_KEY:${multibaseWrapBase64(multicodecWrapRSA(rsaPublicKey.iosEncoded))}"

    fun stripKeyId(keyId: String): Pair<Boolean, ByteArray>? {
        if (!keyId.startsWith("$PREFIX_DID_KEY:")) return null
        val stripped = keyId.removePrefix("$PREFIX_DID_KEY:")
        val multibaseDecoded = multibaseDecode(stripped)
        val multiKey = multiKeyGetKty(multibaseDecoded) ?: return null

        return multiKey.first to multiKey.second
    }

    private fun multiKeyGetKty(it: ByteArray?) =
        if (it != null && it.size > 3 && it[0] == 0x12.toByte()) {
            when (it[1]) {
                0x90.toByte() -> true to it.drop(2).toByteArray()  // Case EC
                0x05.toByte() -> false to it.drop(2).toByteArray() // Case RSA
                else -> null
            }
        } else null

    private fun multibaseDecode(it: String?) =
        if (it != null && it.startsWith("m")) {
            it.removePrefix("m").decodeToByteArrayOrNull(Base64Strict)
        } else null

    // No decompression, because that would need some EC math
    private fun decodeEcKey(it: ByteArray?): Pair<ByteArray, ByteArray>? {
        if (it == null) return null
        val half: Int = it.size.floorDiv(2)
        val x = it.sliceArray(0 until half)
        val y = it.sliceArray(half until it.size)
        return Pair(x, y)
    }

    private fun decodeRsaKey(it: ByteArray?): CryptoPublicKey? {
        return if ( it != null ) CryptoPublicKey.Rsa.fromPKCS1encoded(it) else null
    }

    fun calcPublicKey(multiKey: Pair<Boolean, ByteArray>?): CryptoPublicKey? {
        when (multiKey?.first) {
            true -> {
                val (xCoordinate, yCoordinate) = decodeEcKey(
                    multiKey.second
                ) ?: return null
                val curve =
                    EcCurve.entries.find { it.coordinateLengthBytes.toInt() == xCoordinate.size } ?: return null
                return CryptoPublicKey.Ec(curve = curve, x = xCoordinate, y = yCoordinate)
            }

            false -> {
                return decodeRsaKey(multiKey.second)
            }

            else -> return null
        }
    }

    @Deprecated("Use [CryptoPublicKey.fromKeyId] instead")
    fun calcEcPublicKeyCoords(keyId: String): Pair<ByteArray, ByteArray>? {
        if (!keyId.startsWith("$PREFIX_DID_KEY:")) return null
        val stripped = keyId.removePrefix("$PREFIX_DID_KEY:")
        val multibaseDecode = multibaseDecode(stripped)
        val multiKey = multiKeyDecode(multibaseDecode) ?: return null

        return if (multiKey.first) decodeEcKey(multiKey.second) else TODO("ASN1 decoding of RSA keys")
    }

    @Deprecated("Dependency of calcEncPublicKeyCoords - Use [multiKeyGetKty] instead ")
    // 0x1200 would be with compression, so we'll use 0x1290
    private fun multiKeyDecode(it: ByteArray?) =
        if (it != null && it.size > 3 && it[0] == 0x12.toByte()) {
            if (it[1] == 0x90.toByte()) {
                true to it.drop(2).toByteArray()
            } else if (it[1] == 0x05.toByte()) {
                false to it.drop(2).toByteArray()
            } else null
        } else null
}