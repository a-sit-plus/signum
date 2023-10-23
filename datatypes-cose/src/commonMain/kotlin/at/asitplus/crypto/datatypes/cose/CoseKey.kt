package at.asitplus.crypto.datatypes.cose

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.asn1.encodeToByteArray
import at.asitplus.crypto.datatypes.cose.io.cborSerializer
import at.asitplus.crypto.datatypes.io.MultibaseHelper
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.*
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.SerialLabel

// Class needed to handle overlapping serial labels in COSE standard
sealed class CoseKeyParams() {

    // Implements elliptic curve public key parameters in case of y being a Bytearray
    @OptIn(ExperimentalSerializationApi::class)
    @Serializable
    data class EcYByteArray(
        @SerialLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @SerialLabel(-2)
        @SerialName("x")
        val x: ByteArray? = null,
        @SerialLabel(-3)
        @SerialName("y")
        val y: ByteArray? = null,
        @SerialLabel(-4)
        @SerialName("d")
        val d: ByteArray? = null
    ): CoseKeyParams() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EcYByteArray

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
            var result = curve?.hashCode() ?: 0
            result = 31 * result + (x?.contentHashCode() ?: 0)
            result = 31 * result + (y?.contentHashCode() ?: 0)
            result = 31 * result + (d?.contentHashCode() ?: 0)
            return result
        }

        fun toAnsiX963ByteArray(): KmmResult<ByteArray> {
            if (x != null && y != null)
                return KmmResult.success(byteArrayOf(0x04.toByte()) + x + y);
            return KmmResult.failure(IllegalArgumentException())
        }
    }

    // Implements elliptic curve public key parameters in case of y being a bool value
    @OptIn(ExperimentalSerializationApi::class)
    @Serializable
    data class EcYBool(
        @SerialLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @SerialLabel(-2)
        @SerialName("x")
        val x: ByteArray? = null,
        @SerialLabel(-3)
        @SerialName("y")
        val y: Boolean? = null,
        @SerialLabel(-4)
        @SerialName("d")
        val d: ByteArray? = null
    ): CoseKeyParams() {

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EcYBool

            if (curve != other.curve) return false
            if (x != null) {
                if (other.x == null) return false
                if (!x.contentEquals(other.x)) return false
            } else if (other.x != null) return false
            if (y != other.y) return false
            if (d != null) {
                if (other.d == null) return false
                if (!d.contentEquals(other.d)) return false
            } else if (other.d != null) return false

            return true
        }

        override fun hashCode(): Int {
            var result = curve?.hashCode() ?: 0
            result = 31 * result + (x?.contentHashCode() ?: 0)
            result = 31 * result + (y?.hashCode() ?: 0)
            result = 31 * result + (d?.contentHashCode() ?: 0)
            return result
        }

        fun toAnsiX963ByteArray(): KmmResult<ByteArray> {
//            if (x != null && y != null)
//                return KmmResult.success(byteArrayOf(0x04.toByte()) + x + y);
//            return KmmResult.failure(IllegalArgumentException())
            TODO()
        }
    }

    // Implements RSA public key parameters
    @OptIn(ExperimentalSerializationApi::class)
    @Serializable
    data class Rsa(
        @SerialLabel(-1)
        @SerialName("n")
        val n: ByteArray? = null,
        @SerialLabel(-2)
        @SerialName("e")
        val e: ByteArray? = null,
        @SerialLabel(-4)
        @SerialName("d")
        val d: ByteArray? = null
    ): CoseKeyParams() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Rsa

            if (n != null) {
                if (other.n == null) return false
                if (!n.contentEquals(other.n)) return false
            } else if (other.n != null) return false
            if (e != null) {
                if (other.e == null) return false
                if (!e.contentEquals(other.e)) return false
            } else if (other.e != null) return false
            if (d != null) {
                if (other.d == null) return false
                if (!d.contentEquals(other.d)) return false
            } else if (other.d != null) return false

            return true
        }

        override fun hashCode(): Int {
            var result = n?.contentHashCode() ?: 0
            result = 31 * result + (e?.contentHashCode() ?: 0)
            result = 31 * result + (d?.contentHashCode() ?: 0)
            return result
        }
    }
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class CoseKey (
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
    @Serializable
    @Contextual //TODO Serializer
    val keyParams: CoseKeyParams
) {
    override fun toString(): String {
        return "CoseKey(type=$type," +
                " keyId=${keyId?.encodeToString(Base16(strict = true))}," +
                " algorithm=$algorithm," +
                " operations=${operations?.contentToString()}," +
                " baseIv=${baseIv?.encodeToString(Base16(strict = true))}," +
                keyParams.toString()
    }

    fun toCryptoPublicKey(): CryptoPublicKey? {
//        if (this.type != CoseKeyType.EC2 || this.curve == null || this.keyId == null || this.x == null || this.y == null) return null
//        return CryptoPublicKey.Ec(
//            curve = curve.toJwkCurve(),
//            x = x,
//            y = y,
//        ).apply { coseKid = keyId }
        TODO()
    }

    fun serialize() = cborSerializer.encodeToByteArray(this)
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
        if (keyParams != other.keyParams) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + (keyId?.contentHashCode() ?: 0)
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + (operations?.contentHashCode() ?: 0)
        result = 31 * result + (baseIv?.contentHashCode() ?: 0)
        result = 31 * result + keyParams.hashCode()
        return result
    }

    companion object {

        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<CoseHeader>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }

        @Deprecated("Needlessly restrictive, use [fromAnsiX963Bytes(type, Bytearray)] instead!")
        fun fromAnsiX963Bytes(type: CoseKeyType, curve: CoseEllipticCurve, it: ByteArray) =
            if (type == CoseKeyType.EC2 && curve == CoseEllipticCurve.P256) {
                val pubKey = CryptoPublicKey.Ec.fromAnsiX963Bytes(it)
                pubKey.toCoseKey(type = type)
            } else null

        fun fromAnsiX963Bytes(type: CoseKeyType, it: ByteArray) =
            if (type == CoseKeyType.EC2) {
                val pubKey = CryptoPublicKey.Ec.fromAnsiX963Bytes(it)
                pubKey.toCoseKey(type)
            } else null

        fun fromCoordinates(
            type: CoseKeyType,
            curve: CoseEllipticCurve,
            x: ByteArray,
            y: ByteArray
        ) =
            if (type == CoseKeyType.EC2) {
                CryptoPublicKey.Ec.fromCoordinates(curve.toJwkCurve(), x, y).toCoseKey(type)
            } else null
    }
}

fun CryptoPublicKey.toCoseKey(type: CoseKeyType): Nothing =  //TODO expand to other types!
    when (type) {
        CoseKeyType.EC2 -> TODO()
//            CoseKey(
//                type = type,
//                curve = (this as CryptoPublicKey.Ec).curve.toCoseCurve(),
//                keyId = keyId.encodeToByteArray(),
//                algorithm = when (curve) {
//                    EcCurve.SECP_256_R_1 -> CoseAlgorithm.ES256
//                    EcCurve.SECP_384_R_1 -> CoseAlgorithm.ES384
//                    EcCurve.SECP_521_R_1 -> CoseAlgorithm.ES512
//                },
//                x = x,
//                y = y
//            )

        CoseKeyType.RSA -> TODO()
//            CoseKey(
//                type = type,
//                keyId = keyId.encodeToByteArray(),
//                algorithm = when ((this as CryptoPublicKey.Rsa).bits) {
//                    CryptoPublicKey.Rsa.Size.RSA_512 -> TODO()
//                    CryptoPublicKey.Rsa.Size.RSA_1024 -> TODO()
//                    CryptoPublicKey.Rsa.Size.RSA_2048 -> TODO()
//                    CryptoPublicKey.Rsa.Size.RSA_3027 -> TODO()
//                    CryptoPublicKey.Rsa.Size.RSA_4096 -> TODO()
//                },
//                n = n,
//                e = e.encodeToByteArray()
//            )

        else -> TODO()//throw IllegalArgumentException("Not supported") //TODO?
    }

private const val COSE_KID = "coseKid"
var CryptoPublicKey.coseKid: String
    get() = additionalProperties[COSE_KID] ?: keyId
    set(value) {
        additionalProperties[COSE_KID] = value
    }
