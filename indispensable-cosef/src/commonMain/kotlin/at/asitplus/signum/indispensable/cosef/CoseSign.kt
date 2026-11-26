@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.contentHashCodeIfArray
import kotlinx.serialization.*
import kotlinx.serialization.cbor.*
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/** COSE_Sign keeps body and signer headers, order, and protected encodings distinct from COSE_Sign1. */
@Serializable(with = CoseSignSerializer::class)
class CoseSign<out BodyProtectedHeader : CoseHeader, out BodyUnprotectedHeader : CoseHeader, out SignerProtectedHeader : CoseHeader, out SignerUnprotectedHeader : CoseHeader, out Payload> internal constructor(
    val raw: Raw<BodyUnprotectedHeader, SignerUnprotectedHeader>,
    val protectedHeader: BodyProtectedHeader,
    signatures: List<Signature<SignerProtectedHeader, SignerUnprotectedHeader>>,
    val payload: Payload?,
    /** Exact external content retained on detached creation; absent when decoding a detached envelope. */
    val detachedPayload: ByteArray? = null,
) {
    val signatures = signatures.toList()
    val unprotectedHeader: BodyUnprotectedHeader get() = raw.unprotectedHeader
    val isDetached: Boolean get() = raw.plainPayload == null
    fun signatureInput(index: Int, externalAad: ByteArray = byteArrayOf(), detachedPayload: ByteArray? = null) = raw.signatureInput(index, externalAad, detachedPayload)
    private val decodedSignatures = this.signatures.map {
        COSE.getSignature(it.raw.plainSignature, when {
            it.protectedHeader.algorithm != null -> it.protectedHeader
            it.unprotectedHeader.algorithm != null -> it.unprotectedHeader
            protectedHeader.algorithm != null -> protectedHeader
            else -> unprotectedHeader
        })
    }

    fun signature(index: Int) = decodedSignatures[index]
    override fun equals(other: Any?) = other is CoseSign<*, *, *, *, *> && raw == other.raw && protectedHeader == other.protectedHeader &&
            signatures == other.signatures && (payload?.contentEqualsIfArray(other.payload) ?: (other.payload == null))
    override fun hashCode() = 31 * (31 * (31 * raw.hashCode() + protectedHeader.hashCode()) + signatures.hashCode()) + (payload?.contentHashCodeIfArray() ?: 0)

    class Signature<out ProtectedHeader : CoseHeader, out UnprotectedHeader : CoseHeader> internal constructor(
        val raw: SignatureRaw<UnprotectedHeader>, val protectedHeader: ProtectedHeader,
    ) {
        val unprotectedHeader: UnprotectedHeader get() = raw.unprotectedHeader
        override fun equals(other: Any?) = other is Signature<*, *> && raw == other.raw && protectedHeader == other.protectedHeader
        override fun hashCode() = 31 * raw.hashCode() + protectedHeader.hashCode()
    }

    @Serializable(with = CoseSignRawSerializer::class)
    class Raw<out BodyUnprotectedHeader : CoseHeader, out SignerUnprotectedHeader : CoseHeader> internal constructor(
        val plainProtectedHeader: ByteArray,
        val unprotectedHeader: BodyUnprotectedHeader,
        val plainPayload: ByteArray?,
        signatures: List<SignatureRaw<SignerUnprotectedHeader>>,
        internal val unprotectedLabels: Set<CoseHeaderLabel>,
    ) {
        val signatures = signatures.toList()
        init { require(this.signatures.isNotEmpty()) { "COSE_Sign requires at least one signature" } }
        fun signatureInput(index: Int, externalAad: ByteArray = byteArrayOf(), detachedPayload: ByteArray? = null) =
            COSE.signStructureInput(plainProtectedHeader, signatures[index].plainProtectedHeader, externalAad, authenticationPayload(plainPayload, detachedPayload))

        fun <BodyProtectedHeader : CoseHeader, SignerProtectedHeader : CoseHeader, Payload> typed(
            bodyProtectedHeaderSerializer: KSerializer<BodyProtectedHeader>,
            signerProtectedHeaderSerializer: KSerializer<SignerProtectedHeader>,
            payloadSerializer: KSerializer<Payload>, serialFormat: Cbor = coseCompliantSerializer,
        ): CoseSign<BodyProtectedHeader, BodyUnprotectedHeader, SignerProtectedHeader, SignerUnprotectedHeader, Payload> {
            val body = decodeHeader(plainProtectedHeader, bodyProtectedHeaderSerializer, serialFormat)
            validateBuckets(body.header, unprotectedHeader, body.labels, unprotectedLabels)
            val views = signatures.map {
                val signer = decodeHeader(it.plainProtectedHeader, signerProtectedHeaderSerializer, serialFormat)
                validateBuckets(signer.header, it.unprotectedHeader, signer.labels, it.unprotectedLabels)
                require(((body.labels + unprotectedLabels) intersect (signer.labels + it.unprotectedLabels)).isEmpty()) { "Body and signer parameters conflict" }
                Signature(it, signer.header)
            }
            return CoseSign(this, body.header, views, plainPayload?.toTypedPayload(payloadSerializer, serialFormat))
        }

        inline fun <reified BodyProtectedHeader : CoseHeader, reified SignerProtectedHeader : CoseHeader, reified Payload> typed(serialFormat: Cbor = coseCompliantSerializer) =
            typed(serialFormat.serializersModule.serializer<BodyProtectedHeader>(), serialFormat.serializersModule.serializer<SignerProtectedHeader>(), serialFormat.serializersModule.serializer<Payload>(), serialFormat)

        override fun equals(other: Any?) = other is Raw<*, *> && plainProtectedHeader.contentEquals(other.plainProtectedHeader) &&
                unprotectedHeader == other.unprotectedHeader && plainPayload.contentEquals(other.plainPayload) && signatures == other.signatures
        override fun hashCode() = 31 * (31 * (31 * plainProtectedHeader.contentHashCode() + unprotectedHeader.hashCode()) + (plainPayload?.contentHashCode() ?: 0)) + signatures.hashCode()

        companion object {
            operator fun <BodyUnprotectedHeader : CoseHeader, SignerUnprotectedHeader : CoseHeader> invoke(
                bytes: ByteArray, bodyUnprotectedHeaderSerializer: KSerializer<BodyUnprotectedHeader>, signerUnprotectedHeaderSerializer: KSerializer<SignerUnprotectedHeader>, serialFormat: Cbor = coseCompliantSerializer,
            ): Raw<BodyUnprotectedHeader, SignerUnprotectedHeader> = serialFormat.decodeFromByteArray(CoseSignRawSerializer(bodyUnprotectedHeaderSerializer, signerUnprotectedHeaderSerializer), bytes)

            inline operator fun <reified BodyUnprotectedHeader : CoseHeader, reified SignerUnprotectedHeader : CoseHeader> invoke(bytes: ByteArray, serialFormat: Cbor = coseCompliantSerializer) =
                invoke(bytes, serialFormat.serializersModule.serializer<BodyUnprotectedHeader>(), serialFormat.serializersModule.serializer<SignerUnprotectedHeader>(), serialFormat)
        }
    }

    @Serializable(with = CoseSignatureRawSerializer::class)
    class SignatureRaw<out UnprotectedHeader : CoseHeader> internal constructor(
        val plainProtectedHeader: ByteArray,
        val unprotectedHeader: UnprotectedHeader,
        val plainSignature: ByteArray,
        internal val unprotectedLabels: Set<CoseHeaderLabel>,
    ) {
        override fun equals(other: Any?) = other is SignatureRaw<*> && plainProtectedHeader.contentEquals(other.plainProtectedHeader) &&
                unprotectedHeader == other.unprotectedHeader && plainSignature.contentEquals(other.plainSignature)
        override fun hashCode() = 31 * (31 * plainProtectedHeader.contentHashCode() + unprotectedHeader.hashCode()) + plainSignature.contentHashCode()
    }
}

@Serializable
@CborArray
internal data class CoseSignEnvelope<BodyUnprotectedHeader, SignerUnprotectedHeader : CoseHeader>(
    @ByteString val protectedHeader: ByteArray,
    val unprotectedHeader: BodyUnprotectedHeader,
    @ByteString val payload: ByteArray?,
    val signatures: List<CoseSign.SignatureRaw<SignerUnprotectedHeader>>,
)

@Serializable
@CborArray
internal data class CoseSignatureEnvelope<UnprotectedHeader>(
    @ByteString val protectedHeader: ByteArray,
    val unprotectedHeader: UnprotectedHeader,
    @ByteString val signature: ByteArray,
)

class CoseSignRawSerializer<BodyUnprotectedHeader : CoseHeader, SignerUnprotectedHeader : CoseHeader>(
    private val bodySerializer: KSerializer<BodyUnprotectedHeader>, private val signerSerializer: KSerializer<SignerUnprotectedHeader>,
) : KSerializer<CoseSign.Raw<BodyUnprotectedHeader, SignerUnprotectedHeader>> {
    override val descriptor = CoseSignEnvelope.serializer(bodySerializer, signerSerializer).descriptor
    override fun serialize(encoder: Encoder, value: CoseSign.Raw<BodyUnprotectedHeader, SignerUnprotectedHeader>) =
        encoder.encodeSerializableValue(CoseSignEnvelope.serializer(HeaderBucketSerializer(bodySerializer), signerSerializer), CoseSignEnvelope(value.plainProtectedHeader, value.unprotectedHeader, value.plainPayload, value.signatures))
    override fun deserialize(decoder: Decoder): CoseSign.Raw<BodyUnprotectedHeader, SignerUnprotectedHeader> {
        val labels = mutableSetOf<CoseHeaderLabel>()
        val wire = decoder.decodeSerializableValue(CoseSignEnvelope.serializer(HeaderBucketSerializer(bodySerializer, labels), signerSerializer))
        return CoseSign.Raw(wire.protectedHeader, wire.unprotectedHeader, wire.payload, wire.signatures, labels)
    }
}

class CoseSignatureRawSerializer<UnprotectedHeader : CoseHeader>(private val headerSerializer: KSerializer<UnprotectedHeader>) : KSerializer<CoseSign.SignatureRaw<UnprotectedHeader>> {
    override val descriptor = CoseSignatureEnvelope.serializer(headerSerializer).descriptor
    override fun serialize(encoder: Encoder, value: CoseSign.SignatureRaw<UnprotectedHeader>) =
        encoder.encodeSerializableValue(CoseSignatureEnvelope.serializer(HeaderBucketSerializer(headerSerializer)), CoseSignatureEnvelope(value.plainProtectedHeader, value.unprotectedHeader, value.plainSignature))
    override fun deserialize(decoder: Decoder): CoseSign.SignatureRaw<UnprotectedHeader> {
        val labels = mutableSetOf<CoseHeaderLabel>()
        val wire = decoder.decodeSerializableValue(CoseSignatureEnvelope.serializer(HeaderBucketSerializer(headerSerializer, labels)))
        return CoseSign.SignatureRaw(wire.protectedHeader, wire.unprotectedHeader, wire.signature, labels)
    }
}

class CoseSignSerializer<BodyProtectedHeader : CoseHeader, BodyUnprotectedHeader : CoseHeader, SignerProtectedHeader : CoseHeader, SignerUnprotectedHeader : CoseHeader, Payload>(
    bodyProtectedHeaderSerializer: KSerializer<BodyProtectedHeader>, bodyUnprotectedHeaderSerializer: KSerializer<BodyUnprotectedHeader>,
    signerProtectedHeaderSerializer: KSerializer<SignerProtectedHeader>, signerUnprotectedHeaderSerializer: KSerializer<SignerUnprotectedHeader>, payloadSerializer: KSerializer<Payload>,
) : TransformingSerializerTemplate<CoseSign<BodyProtectedHeader, BodyUnprotectedHeader, SignerProtectedHeader, SignerUnprotectedHeader, Payload>, CoseSign.Raw<BodyUnprotectedHeader, SignerUnprotectedHeader>>(
    parent = CoseSignRawSerializer(bodyUnprotectedHeaderSerializer, signerUnprotectedHeaderSerializer), serialName = "CoseSign",
    encodeAs = { it.raw }, decodeAs = { it.typed(bodyProtectedHeaderSerializer, signerProtectedHeaderSerializer, payloadSerializer) },
)
