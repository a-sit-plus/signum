@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.contentHashCodeIfArray
import kotlinx.serialization.*
import kotlinx.serialization.cbor.Cbor

/** Typed COSE_Sign1. Decoding does not verify signatures or establish trust. */
@Serializable(with = CoseSign1Serializer::class)
class CoseSign1<out ProtectedHeader : CoseHeader, out UnprotectedHeader : CoseHeader, out Payload> internal constructor(
    val raw: Raw<UnprotectedHeader>,
    val protectedHeader: ProtectedHeader,
    val payload: Payload?,
    /** Exact external content retained on detached creation; absent when decoding a detached envelope. */
    val detachedPayload: ByteArray? = null,
) {
    val unprotectedHeader: UnprotectedHeader get() = raw.unprotectedHeader
    val isDetached: Boolean get() = raw.plainPayload == null
    val signature = COSE.getSignature(raw.plainSignature, protectedHeader, unprotectedHeader)
    fun signatureInput(externalAad: ByteArray = byteArrayOf(), detachedPayload: ByteArray? = null) = raw.signatureInput(externalAad, detachedPayload)
    override fun equals(other: Any?) = other is CoseSign1<*, *, *> && raw == other.raw && protectedHeader == other.protectedHeader && (payload?.contentEqualsIfArray(other.payload) ?: (other.payload == null))
    override fun hashCode() = 31 * (31 * raw.hashCode() + protectedHeader.hashCode()) + (payload?.contentHashCodeIfArray() ?: 0)

    /**
     * Raw decoding interprets only the application-owned unprotected bucket. Ignored members of that map are
     * not retained on re-encoding. Keep the original input separately when unchanged byte forwarding is needed.
     */
    @Serializable(with = CoseSign1RawSerializer::class)
    class Raw<out UnprotectedHeader : CoseHeader> internal constructor(
        val plainProtectedHeader: ByteArray,
        val unprotectedHeader: UnprotectedHeader,
        val plainPayload: ByteArray?,
        val plainSignature: ByteArray,
        internal val unprotectedLabels: Set<CoseHeaderLabel>,
    ) {
        fun signatureInput(externalAad: ByteArray = byteArrayOf(), detachedPayload: ByteArray? = null) =
            COSE.sign1StructureInput(plainProtectedHeader, externalAad, authenticationPayload(plainPayload, detachedPayload))

        fun <ProtectedHeader : CoseHeader, Payload> typed(
            protectedHeaderSerializer: KSerializer<ProtectedHeader>,
            payloadSerializer: KSerializer<Payload>,
            serialFormat: Cbor = coseCompliantSerializer,
        ): CoseSign1<ProtectedHeader, UnprotectedHeader, Payload> {
            val decoded = decodeHeader(plainProtectedHeader, protectedHeaderSerializer, serialFormat)
            validateBuckets(decoded.header, unprotectedHeader, decoded.labels, unprotectedLabels)
            return CoseSign1(this, decoded.header, plainPayload?.toTypedPayload(payloadSerializer, serialFormat))
        }

        inline fun <reified ProtectedHeader : CoseHeader, reified Payload> typed(serialFormat: Cbor = coseCompliantSerializer) =
            typed(serialFormat.serializersModule.serializer<ProtectedHeader>(), serialFormat.serializersModule.serializer<Payload>(), serialFormat)

        override fun equals(other: Any?) = other is Raw<*> && plainProtectedHeader.contentEquals(other.plainProtectedHeader) &&
                unprotectedHeader == other.unprotectedHeader && plainPayload.contentEquals(other.plainPayload) && plainSignature.contentEquals(other.plainSignature)
        override fun hashCode() = 31 * (31 * (31 * plainProtectedHeader.contentHashCode() + unprotectedHeader.hashCode()) + (plainPayload?.contentHashCode() ?: 0)) + plainSignature.contentHashCode()

        companion object {
            operator fun <UnprotectedHeader : CoseHeader> invoke(bytes: ByteArray, unprotectedHeaderSerializer: KSerializer<UnprotectedHeader>, serialFormat: Cbor = coseCompliantSerializer): Raw<UnprotectedHeader> =
                serialFormat.decodeFromByteArray(CoseSign1RawSerializer(unprotectedHeaderSerializer), bytes)
            inline operator fun <reified UnprotectedHeader : CoseHeader> invoke(bytes: ByteArray, serialFormat: Cbor = coseCompliantSerializer) =
                invoke(bytes, serialFormat.serializersModule.serializer<UnprotectedHeader>(), serialFormat)
        }
    }

    companion object {
        inline operator fun <reified ProtectedHeader : CoseHeader, reified UnprotectedHeader : CoseHeader, reified Payload> invoke(bytes: ByteArray, serialFormat: Cbor = coseCompliantSerializer): CoseSign1<ProtectedHeader, UnprotectedHeader, Payload> =
            Raw<UnprotectedHeader>(bytes, serialFormat).typed<ProtectedHeader, Payload>(serialFormat)
    }
}

class CoseSign1RawSerializer<UnprotectedHeader : CoseHeader>(private val headerSerializer: KSerializer<UnprotectedHeader>) : KSerializer<CoseSign1.Raw<UnprotectedHeader>> {
    override val descriptor = CoseEnvelope.serializer(headerSerializer).descriptor
    override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: CoseSign1.Raw<UnprotectedHeader>) =
        encoder.encodeSerializableValue(CoseEnvelope.serializer(HeaderBucketSerializer(headerSerializer)), CoseEnvelope(value.plainProtectedHeader, value.unprotectedHeader, value.plainPayload, value.plainSignature))
    override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): CoseSign1.Raw<UnprotectedHeader> {
        val labels = mutableSetOf<CoseHeaderLabel>()
        val wire = decoder.decodeSerializableValue(CoseEnvelope.serializer(HeaderBucketSerializer(headerSerializer, labels)))
        return CoseSign1.Raw(wire.protectedHeader, wire.unprotectedHeader, wire.payload, wire.authentication, labels)
    }
}

/** Composes through the raw envelope, preserving protected and payload bytes during typed serialization. */
class CoseSign1Serializer<ProtectedHeader : CoseHeader, UnprotectedHeader : CoseHeader, Payload>(
    protectedHeaderSerializer: KSerializer<ProtectedHeader>,
    unprotectedHeaderSerializer: KSerializer<UnprotectedHeader>,
    payloadSerializer: KSerializer<Payload>,
) : TransformingSerializerTemplate<CoseSign1<ProtectedHeader, UnprotectedHeader, Payload>, CoseSign1.Raw<UnprotectedHeader>>(
    parent = CoseSign1RawSerializer(unprotectedHeaderSerializer),
    serialName = "CoseSign1",
    encodeAs = { it.raw },
    decodeAs = { it.typed(protectedHeaderSerializer, payloadSerializer) },
)
