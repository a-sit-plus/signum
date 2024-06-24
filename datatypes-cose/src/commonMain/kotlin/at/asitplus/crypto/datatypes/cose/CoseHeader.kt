package at.asitplus.crypto.datatypes.cose

import at.asitplus.catching
import at.asitplus.crypto.datatypes.cose.io.Base16Strict
import at.asitplus.crypto.datatypes.cose.io.cborSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborLabel
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Protected header of a [CoseSigned].
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class CoseHeader(
    @CborLabel(1)
    @SerialName("alg")
    val algorithm: CoseAlgorithm? = null,
    @CborLabel(2)
    @SerialName("crit")
    val criticalHeaders: String? = null,
    @CborLabel(3)
    @SerialName("content type")
    val contentType: String? = null,
    @CborLabel(4)
    @SerialName("kid")
    @ByteString
    val kid: ByteArray? = null,
    @CborLabel(5)
    @SerialName("IV")
    @ByteString
    val iv: ByteArray? = null,
    @CborLabel(6)
    @SerialName("Partial IV")
    @ByteString
    val partialIv: ByteArray? = null,
    @SerialName("COSE_Key")
    @ByteString
    val coseKey: ByteArray? = null,
    @CborLabel(33)
    @SerialName("x5chain")
    @ByteString
    // TODO Might also be an array, if there is a real chain, not only one cert
    val certificateChain: ByteArray? = null,
) {

    fun serialize() = cborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseHeader

        if (algorithm != other.algorithm) return false
        if (criticalHeaders != other.criticalHeaders) return false
        if (contentType != other.contentType) return false
        if (kid != null) {
            if (other.kid == null) return false
            if (!kid.contentEquals(other.kid)) return false
        } else if (other.kid != null) return false
        if (iv != null) {
            if (other.iv == null) return false
            if (!iv.contentEquals(other.iv)) return false
        } else if (other.iv != null) return false
        if (partialIv != null) {
            if (other.partialIv == null) return false
            if (!partialIv.contentEquals(other.partialIv)) return false
        } else if (other.partialIv != null) return false
        if (coseKey != null) {
            if (other.coseKey == null) return false
            if (!coseKey.contentEquals(other.coseKey)) return false
        } else if (other.coseKey != null) return false
        if (certificateChain != null) {
            if (other.certificateChain == null) return false
            if (!certificateChain.contentEquals(other.certificateChain)) return false
        } else if (other.certificateChain != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = algorithm?.hashCode() ?: 0
        result = 31 * result + (criticalHeaders?.hashCode() ?: 0)
        result = 31 * result + (contentType?.hashCode() ?: 0)
        result = 31 * result + (kid?.contentHashCode() ?: 0)
        result = 31 * result + (iv?.contentHashCode() ?: 0)
        result = 31 * result + (partialIv?.contentHashCode() ?: 0)
        result = 31 * result + (coseKey?.contentHashCode() ?: 0)
        result = 31 * result + (certificateChain?.contentHashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "CoseHeader(algorithm=$algorithm," +
                " criticalHeaders=$criticalHeaders," +
                " contentType=$contentType," +
                " kid=${kid?.encodeToString(Base16Strict)}," +
                " iv=${iv?.encodeToString(Base16Strict)}," +
                " partialIv=${partialIv?.encodeToString(Base16Strict)}," +
                " coseKey=${coseKey?.encodeToString(Base16Strict)}," +
                " certificateChain=${certificateChain?.encodeToString(Base16Strict)})"
    }


    companion object {
        fun deserialize(it: ByteArray) = catching {
            cborSerializer.decodeFromByteArray<CoseHeader>(it)
        }
    }
}