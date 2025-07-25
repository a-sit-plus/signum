package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.cosef.CoseSigned.Companion.create
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalSerializationApi::class)
@Serializable(with = CoseMacSerializer::class)
@ConsistentCopyVisibility
data class CoseMac<P : Any?> internal constructor(
    val protectedHeader: CoseHeader,
    val unprotectedHeader: CoseHeader? = null,
    val payload: P?,
    val tag: ByteArray,
    val wireFormat: CoseBytes,
) {

    /**
     * @param detachedPayload only to be set when [payload] is null, i.e. it is transported externally
     */
    fun prepareCoseMacInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray = wireFormat.toCoseMacInput(externalAad, detachedPayload)

    fun serialize(parameterSerializer: KSerializer<P>): ByteArray = coseCompliantSerializer
        .encodeToByteArray(CoseMacSerializer(parameterSerializer), this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseMac<*>

        if (protectedHeader != other.protectedHeader) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (payload != null) {
            if (other.payload == null) return false
            if (!payload.contentEqualsIfArray(other.payload)) return false
        } else if (other.payload != null) return false
        if (!tag.contentEquals(other.tag)) return false
        if (wireFormat != other.wireFormat) return false

        return true
    }

    override fun hashCode(): Int {
        var result = protectedHeader.hashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + (payload?.hashCode() ?: 0)
        result = 31 * result + tag.contentHashCode()
        result = 31 * result + wireFormat.hashCode()
        return result
    }

    override fun toString(): String {
        return "CoseMac(protectedHeader=$protectedHeader," +
                " unprotectedHeader=$unprotectedHeader," +
                " payload=${if (payload is ByteArray) payload.encodeToByteArray(Base16()) else payload}," +
                " tag=$tag," +
                " wireFormat=$wireFormat)"
    }

    companion object {
        fun <P : Any> deserialize(parameterSerializer: KSerializer<P>, it: ByteArray): KmmResult<CoseMac<P>> =
            catching {
                coseCompliantSerializer.decodeFromByteArray(CoseMacSerializer(parameterSerializer), it)
            }

        /**
         * Use this method to create a new [CoseMac] object with correct [CoseMac.wireFormat] set.
         */
        @Throws(IllegalArgumentException::class)
        fun <P : Any> create(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader? = null,
            payload: P?,
            tag: ByteArray,
            payloadSerializer: KSerializer<P>,
        ): CoseMac<P> = CoseMac<P>(
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
            payload = payload,
            tag = tag,
            wireFormat = CoseBytes(
                protectedHeader = coseCompliantSerializer.encodeToByteArray(protectedHeader),
                unprotectedHeader = unprotectedHeader,
                payload = payload.toRawPayload(payloadSerializer),
                rawAuthBytes = tag
            ),
        )

        /**
         * Use this method to prepare a [CoseInput] object to calculate the tag,
         * and then call [create] to create a [CoseMac] object.
         */
        @Throws(IllegalArgumentException::class)
        fun <P : Any> prepare(
            protectedHeader: CoseHeader,
            externalAad: ByteArray = byteArrayOf(),
            payload: P?,
            payloadSerializer: KSerializer<P>,
        ): CoseInput = CoseInput(
            contextString = "MAC0",
            protectedHeader = coseCompliantSerializer.encodeToByteArray<CoseHeader>(protectedHeader),
            externalAad = externalAad,
            payload = payload.toRawPayload(payloadSerializer),
        )
    }
}