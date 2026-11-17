@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.contentHashCodeIfArray
import kotlinx.serialization.*
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborArray

/** Typed COSE_Mac0. A decoded tag must be verified before accepting the message. */
@Serializable(with = CoseMac0Serializer::class)
class CoseMac0<out ProtectedHeader : CoseHeader, out UnprotectedHeader : CoseHeader, out Payload> internal constructor(
    val raw: Raw<UnprotectedHeader>,
    val protectedHeader: ProtectedHeader,
    val payload: Payload?,
    /** Exact external content retained on detached creation; absent when decoding a detached envelope. */
    val detachedPayload: ByteArray? = null,
) {
    val unprotectedHeader: UnprotectedHeader get() = raw.unprotectedHeader
    val isDetached: Boolean get() = raw.plainPayload == null
    val tag: ByteArray get() = raw.tag
    fun macInput(externalAad: ByteArray = byteArrayOf(), detachedPayload: ByteArray? = null) = raw.macInput(externalAad, detachedPayload)
    override fun equals(other: Any?) = other is CoseMac0<*, *, *> && raw == other.raw && protectedHeader == other.protectedHeader && (payload?.contentEqualsIfArray(other.payload) ?: (other.payload == null))
    override fun hashCode() = 31 * (31 * raw.hashCode() + protectedHeader.hashCode()) + (payload?.contentHashCodeIfArray() ?: 0)

    @Serializable(with = CoseMac0RawSerializer::class)
    class Raw<out UnprotectedHeader : CoseHeader> internal constructor(
        val plainProtectedHeader: ByteArray,
        val unprotectedHeader: UnprotectedHeader,
        val plainPayload: ByteArray?,
        val tag: ByteArray,
        internal val unprotectedLabels: Set<CoseHeaderLabel>,
    ) {
        fun macInput(externalAad: ByteArray = byteArrayOf(), detachedPayload: ByteArray? = null) =
            COSE.mac0StructureInput(plainProtectedHeader, externalAad, authenticationPayload(plainPayload, detachedPayload))

        fun <ProtectedHeader : CoseHeader, Payload> typed(
            protectedHeaderSerializer: KSerializer<ProtectedHeader>, payloadSerializer: KSerializer<Payload>, serialFormat: Cbor = coseCompliantSerializer,
        ): CoseMac0<ProtectedHeader, UnprotectedHeader, Payload> {
            val decoded = decodeHeader(plainProtectedHeader, protectedHeaderSerializer, serialFormat)
            validateBuckets(decoded.header, unprotectedHeader, decoded.labels, unprotectedLabels)
            return CoseMac0(this, decoded.header, plainPayload?.toTypedPayload(payloadSerializer, serialFormat))
        }
        inline fun <reified ProtectedHeader : CoseHeader, reified Payload> typed(serialFormat: Cbor = coseCompliantSerializer) =
            typed(serialFormat.serializersModule.serializer<ProtectedHeader>(), serialFormat.serializersModule.serializer<Payload>(), serialFormat)

        override fun equals(other: Any?) = other is Raw<*> && plainProtectedHeader.contentEquals(other.plainProtectedHeader) &&
                unprotectedHeader == other.unprotectedHeader && plainPayload.contentEquals(other.plainPayload) && tag.contentEquals(other.tag)
        override fun hashCode() = 31 * (31 * (31 * plainProtectedHeader.contentHashCode() + unprotectedHeader.hashCode()) + (plainPayload?.contentHashCode() ?: 0)) + tag.contentHashCode()

        companion object {
            operator fun <UnprotectedHeader : CoseHeader> invoke(bytes: ByteArray, unprotectedHeaderSerializer: KSerializer<UnprotectedHeader>, serialFormat: Cbor = coseCompliantSerializer): Raw<UnprotectedHeader> =
                serialFormat.decodeFromByteArray(CoseMac0RawSerializer(unprotectedHeaderSerializer), bytes)
            inline operator fun <reified UnprotectedHeader : CoseHeader> invoke(bytes: ByteArray, serialFormat: Cbor = coseCompliantSerializer) =
                invoke(bytes, serialFormat.serializersModule.serializer<UnprotectedHeader>(), serialFormat)
        }
    }
    companion object {
        inline operator fun <reified ProtectedHeader : CoseHeader, reified UnprotectedHeader : CoseHeader, reified Payload> invoke(bytes: ByteArray, serialFormat: Cbor = coseCompliantSerializer): CoseMac0<ProtectedHeader, UnprotectedHeader, Payload> =
            Raw<UnprotectedHeader>(bytes, serialFormat).typed<ProtectedHeader, Payload>(serialFormat)
    }
}

/** Shared four-element wire shape; the authentication contexts remain distinct. */
@Serializable
@CborArray
internal data class CoseEnvelope<UnprotectedHeader>(
    @ByteString val protectedHeader: ByteArray,
    val unprotectedHeader: UnprotectedHeader,
    @ByteString val payload: ByteArray?,
    @ByteString val authentication: ByteArray,
)

class CoseMac0RawSerializer<UnprotectedHeader : CoseHeader>(private val headerSerializer: KSerializer<UnprotectedHeader>) : KSerializer<CoseMac0.Raw<UnprotectedHeader>> {
    override val descriptor = CoseEnvelope.serializer(headerSerializer).descriptor
    override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: CoseMac0.Raw<UnprotectedHeader>) =
        encoder.encodeSerializableValue(CoseEnvelope.serializer(HeaderBucketSerializer(headerSerializer)), CoseEnvelope(value.plainProtectedHeader, value.unprotectedHeader, value.plainPayload, value.tag))
    override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): CoseMac0.Raw<UnprotectedHeader> {
        val labels = mutableSetOf<CoseHeaderLabel>()
        val wire = decoder.decodeSerializableValue(CoseEnvelope.serializer(HeaderBucketSerializer(headerSerializer, labels)))
        return CoseMac0.Raw(wire.protectedHeader, wire.unprotectedHeader, wire.payload, wire.authentication, labels)
    }
}

class CoseMac0Serializer<ProtectedHeader : CoseHeader, UnprotectedHeader : CoseHeader, Payload>(
    protectedHeaderSerializer: KSerializer<ProtectedHeader>, unprotectedHeaderSerializer: KSerializer<UnprotectedHeader>, payloadSerializer: KSerializer<Payload>,
) : TransformingSerializerTemplate<CoseMac0<ProtectedHeader, UnprotectedHeader, Payload>, CoseMac0.Raw<UnprotectedHeader>>(
    parent = CoseMac0RawSerializer(unprotectedHeaderSerializer), serialName = "CoseMac0",
    encodeAs = { it.raw }, decodeAs = { it.typed(protectedHeaderSerializer, payloadSerializer) },
)
