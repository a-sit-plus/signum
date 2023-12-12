package at.asitplus.crypto.datatypes.cose

import at.asitplus.crypto.datatypes.cose.io.cborSerializer
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.*
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.SerialLabel

/**
 * Protected header of a [CoseSigned].
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class CoseHeader(
    @SerialLabel(1)
    @SerialName("alg")
    val algorithm: CoseAlgorithm? = null,
    @SerialLabel(2)
    @SerialName("crit")
    val criticalHeaders: String? = null,
    @SerialLabel(3)
    @SerialName("content type")
    val contentType: String? = null,
    @SerialLabel(4)
    @SerialName("kid")
    @ByteString
    val kid: ByteArray? = null,
    @SerialLabel(5)
    @SerialName("IV")
    @ByteString
    val iv: ByteArray? = null,
    @SerialLabel(6)
    @SerialName("Partial IV")
    @ByteString
    val partialIv: ByteArray? = null,
    @SerialLabel(33)
    @SerialName("x5chain")
    @ByteString
    // TODO this is wrong in the ISO example of IssuerAuth!?
    // shouldn't this be an array here?
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
        result = 31 * result + (certificateChain?.contentHashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "CoseHeader(algorithm=$algorithm," +
                " criticalHeaders=$criticalHeaders," +
                " contentType=$contentType," +
                " kid=${kid?.encodeToString(Base16(strict = true))}," +
                " iv=${iv?.encodeToString(Base16(strict = true))}," +
                " partialIv=${partialIv?.encodeToString(Base16(strict = true))}," +
                " certificateChain=${certificateChain?.encodeToString(Base16(strict = true))})"
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<CoseHeader>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}