package at.asitplus.crypto.datatypes.cose

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.cose.io.cborSerializer
import at.asitplus.crypto.datatypes.io.MultibaseHelper
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.*
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.SerialLabel

@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class CoseKey(
    @SerialLabel(1)
    @SerialName("kty")
    val type: CoseKeyType,
    @SerialLabel(2)
    @SerialName("kid")
    @ByteString
    val keyId: ByteArray? = null,
    @SerialLabel(3)
    @SerialName("alg")
    val algorithm: CoseAlgorithm? = null,
    @SerialLabel(4)
    @SerialName("key_ops")
    val operations: Array<CoseKeyOperation>? = null,
    @SerialLabel(5)
    @SerialName("Base IV")
    @ByteString
    val baseIv: ByteArray? = null,
    @SerialLabel(-1)
    @SerialName("crv")
    val curve: CoseEllipticCurve? = null,
    @SerialLabel(-2)
    @SerialName("x")
    val x: ByteArray? = null,
    @SerialLabel(-3)
    @SerialName("y") // TODO might also be bool
    val y: ByteArray? = null,
    @SerialLabel(-4)
    @SerialName("d")
    val d: ByteArray? = null,
) {
    fun serialize() = cborSerializer.encodeToByteArray(this)

    fun toAnsiX963ByteArray(): KmmResult<ByteArray> {
        if (x != null && y != null)
            return KmmResult.success(byteArrayOf(0x04.toByte()) + x + y);
        return KmmResult.failure(IllegalArgumentException())
    }

    companion object {

        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<CoseHeader>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }

        fun fromAnsiX963Bytes(type: CoseKeyType, curve: CoseEllipticCurve, it: ByteArray): CoseKey? {
            if (type != CoseKeyType.EC2 || curve != CoseEllipticCurve.P256) {
                return null
            }
            if (it.size != 1 + 32 + 32 || it[0] != 0x04.toByte()) {
                return null
            }
            val xCoordinate = it.sliceArray(1 until 33)
            val yCoordinate = it.sliceArray(33 until 65)
            val keyId = MultibaseHelper.calcKeyId(curve.toJwkCurve(), xCoordinate, yCoordinate)
            return CoseKey(
                type = type,
                keyId = keyId.encodeToByteArray(),
                algorithm = CoseAlgorithm.ES256,
                curve = curve,
                x = xCoordinate,
                y = yCoordinate,
            )
        }

        fun fromCoordinates(
            type: CoseKeyType,
            curve: CoseEllipticCurve,
            x: ByteArray,
            y: ByteArray
        ): CoseKey? {
            if (type != CoseKeyType.EC2 || curve != CoseEllipticCurve.P256) {
                return null
            }
            val keyId = MultibaseHelper.calcKeyId(curve.toJwkCurve(), x, y)
            return CoseKey(
                type = type,
                keyId = keyId.encodeToByteArray(),
                algorithm = CoseAlgorithm.ES256,
                curve = curve,
                x = x,
                y = y
            )
        }
    }

    override fun toString(): String {
        return "CoseKey(type=$type," +
                " keyId=${keyId?.encodeToString(Base16(strict = true))}," +
                " algorithm=$algorithm," +
                " operations=${operations?.contentToString()}," +
                " baseIv=${baseIv?.encodeToString(Base16(strict = true))}," +
                " curve=$curve," +
                " x=${x?.encodeToString(Base16(strict = true))}," +
                " y=${y?.encodeToString(Base16(strict = true))}," +
                " d=${d?.encodeToString(Base16(strict = true))})"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseKey

        if (type != other.type) return false
        if (keyId != null) {
            if (other.keyId == null) return false
            if (!keyId.contentEquals(other.keyId)) return false
        } else if (other.keyId != null) return false
        if (algorithm != other.algorithm) return false
        if (operations != null) {
            if (other.operations == null) return false
            if (!operations.contentEquals(other.operations)) return false
        } else if (other.operations != null) return false
        if (baseIv != null) {
            if (other.baseIv == null) return false
            if (!baseIv.contentEquals(other.baseIv)) return false
        } else if (other.baseIv != null) return false
        if (curve != other.curve) return false
        if (x != null) {
            if (other.x == null) return false
            if (!x.contentEquals(other.x)) return false
        } else if (other.x != null) return false
        if (y != null) {
            if (other.y == null) return false
            if (!y.contentEquals(other.y)) return false
        } else if (other.y != null) return false
        if (d != null) {
            if (other.d == null) return false
            if (!d.contentEquals(other.d)) return false
        } else if (other.d != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + (keyId?.contentHashCode() ?: 0)
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + (operations?.contentHashCode() ?: 0)
        result = 31 * result + (baseIv?.contentHashCode() ?: 0)
        result = 31 * result + (curve?.hashCode() ?: 0)
        result = 31 * result + (x?.contentHashCode() ?: 0)
        result = 31 * result + (y?.contentHashCode() ?: 0)
        result = 31 * result + (d?.contentHashCode() ?: 0)
        return result
    }

    fun toCryptoPublicKey(): CryptoPublicKey? {
        if (this.type != CoseKeyType.EC2 || this.curve == null || this.keyId == null || this.x == null || this.y == null) return null
        return CryptoPublicKey.Ec(
            curve = curve.toJwkCurve(),
            x = x,
            y = y,
        ).apply { coseKid = keyId }
    }


}

fun CryptoPublicKey.toCoseKey() = CoseKey( //TODO expand to other types!
    type = CoseKeyType.EC2,
    curve = (this as CryptoPublicKey.Ec).curve.toCoseCurve(),
    keyId = keyId.encodeToByteArray(),
    algorithm = CoseAlgorithm.ES256,
    x = x,
    y = y
)

private const val COSE_KID = "coseKid"
var CryptoPublicKey.coseKid: String
    get() = additionalProperties[COSE_KID] ?: keyId
    set(value) {
        additionalProperties[COSE_KID] = value
    }
