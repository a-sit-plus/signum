package at.asitplus.crypto.datatypes.jws

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.asn1.decodeFromDer
import at.asitplus.crypto.datatypes.asn1.encodeToByteArray
import at.asitplus.crypto.datatypes.io.Base64Strict
import at.asitplus.crypto.datatypes.io.ByteArrayBase64UrlSerializer
import at.asitplus.crypto.datatypes.jws.io.jsonSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okio.ByteString.Companion.toByteString

@Serializable
data class JsonWebKey(
    @SerialName("crv")
    val curve: EcCurve? = null,
    @SerialName("kty")
    val type: JwkType? = null,
    @SerialName("kid")
    val keyId: String? = null,
    //EC
    @SerialName("x")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val x: ByteArray? = null,
    @SerialName("y")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val y: ByteArray? = null,
    //RSA
    @SerialName("n")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val n: ByteArray? = null,
    @SerialName("e")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val e: ByteArray? = null,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JsonWebKey

        if (type != other.type) return false
        if (curve != other.curve) return false
        if (keyId != other.keyId) return false
        if (x != null) {
            if (other.x == null) return false
            if (!x.contentEquals(other.x)) return false
        } else if (other.x != null) return false
        if (y != null) {
            if (other.y == null) return false
            if (!y.contentEquals(other.y)) return false
        } else if (other.y != null) return false

        if (n != null) {
            if (other.n == null) return false
            if (!n.contentEquals(other.n)) return false
        } else if (other.n != null) return false
        if (e != null) {
            if (other.e == null) return false
            if (!e.contentEquals(other.e)) return false
        } else if (other.e != null) return false
        return true
    }

    override fun hashCode(): Int {
        var result = type?.hashCode() ?: 0
        result = 31 * result + (curve?.hashCode() ?: 0)
        result = 31 * result + (keyId?.hashCode() ?: 0)
        result = 31 * result + (x?.contentHashCode() ?: 0)
        result = 31 * result + (y?.contentHashCode() ?: 0)
        result = 31 * result + (n?.hashCode() ?: 0)
        result = 31 * result + (e?.hashCode() ?: 0)
        return result
    }

    companion object {

        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<JsonWebKey>(it)
        }.getOrNull()

        fun fromKeyId(it: String): JsonWebKey? = CryptoPublicKey.fromKeyId(it)?.toJsonWebKey()
        fun fromIosEncoded(bytes: ByteArray) = CryptoPublicKey.fromIosEncoded(bytes).toJsonWebKey()
    }

    fun fromCoordinates(
        curve: EcCurve,
        x: ByteArray,
        y: ByteArray
    ): JsonWebKey = CryptoPublicKey.Ec.fromCoordinates(curve, x, y).toJsonWebKey()


    @Deprecated("Use CryptoPublicKey functionality instead!")
    fun toAnsiX963ByteArray(): KmmResult<ByteArray> {
        if (x != null && y != null)
            return KmmResult.success(byteArrayOf(0x04.toByte()) + x + y);
        return KmmResult.failure(IllegalArgumentException())
    }

    val jwkThumbprint: String by lazy {
        Json.encodeToString(this).encodeToByteArray().toByteString().sha256().base64Url()
    }

    val identifier: String by lazy {
        keyId ?: "urn:ietf:params:oauth:jwk-thumbprint:sha256:${jwkThumbprint}"
    }

    override fun toString() =
        "JsonWebKey(" +
                "type=$type, " +
                "curve=$curve, " +
                "keyId=$keyId," +
                "x=${x?.encodeToString(Base64Strict)}," +
                "y=${y?.encodeToString(Base64Strict)}" +
                "n=${n?.encodeToString(Base64Strict)})" +
                "e=${e?.encodeToString(Base64Strict)}" +
                ")"

    fun toCryptoPublicKey(): CryptoPublicKey? =
        when (type) {
            JwkType.EC -> {
                this.curve?.let {
                    CryptoPublicKey.Ec(
                        curve = it,
                        x = x ?: return null,
                        y = y ?: return null
                    )
                }
            }

            JwkType.RSA -> {
                this.let {
                    CryptoPublicKey.Rsa(
                        n = n ?: return null,
                        e = e?.let { bytes -> Int.decodeFromDer(bytes) } ?: return null
                    )
                }
            }

            else -> null
        }?.apply { jwkId = identifier }

}

fun CryptoPublicKey.toJsonWebKey(): JsonWebKey =
    when (this) {
        is CryptoPublicKey.Ec ->
            JsonWebKey(
                type = JwkType.EC,
                keyId = jwkId,
                curve = curve,
                x = x,
                y = y
            )

        is CryptoPublicKey.Rsa ->
            JsonWebKey(
                type = JwkType.RSA,
                keyId = jwkId,
                n = n,
                e = e.encodeToByteArray()
            )
    }

private const val JWK_ID = "jwkIdentifier"
var CryptoPublicKey.jwkId: String
    get() = additionalProperties[JWK_ID] ?: keyId
    set(value) {
        additionalProperties[JWK_ID] = value
    }