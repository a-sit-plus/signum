package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.contentHashCodeIfArray
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborElement

typealias CoseSign1Typed<P, H> = CoseTyped<CoseSign1, P, H>
typealias CoseMac0Typed<P, H> = CoseTyped<CoseMac0, P, H>

/**
 * Typed payload and effective header over an unchanged [cose] wire object.
 *
 * Forward [cose] or serialize through [CoseTypedSerializerTemplate] to preserve the original bytes.
 * Typed decoding does not verify signatures or establish key trust.
 */
@OptIn(ExperimentalSerializationApi::class)
data class CoseTyped<out C : COSE, out P, H : CoseHeaderBase>(
    val cose: C,
    val payload: P,
    internal val wrappedHeader: CoseHeaderWrapped<H>,
) {
    override fun toString(): String = cose.toString()

    /** The effective header: protected and unprotected bucket combined and decoded. */
    val header: H get() = wrappedHeader.header

    /** Labels of [header] carried in the unprotected bucket. */
    val unprotectedLabels: Set<CborElement> get() = wrappedHeader.unprotectedLabels

    /** Labels listed in `crit`, which the application must understand. */
    val criticalLabels: List<CborElement> get() = wrappedHeader.criticalLabels

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseTyped<*, *, *>

        if (cose != other.cose) return false
        if (payload != null) {
            if (other.payload == null) return false
            if (!payload.contentEqualsIfArray(other.payload)) return false
        } else if (other.payload != null) return false
        if (wrappedHeader != other.wrappedHeader) return false

        return true
    }

    override fun hashCode(): Int {
        var result = cose.hashCode()
        result = 31 * result + (payload?.contentHashCodeIfArray() ?: 0)
        result = 31 * result + wrappedHeader.hashCode()
        return result
    }

    companion object {

        /** Creates a [CoseSign1] with the buckets of [header] over [payload], encoded with [payloadSerializer]. */
        suspend fun <P : Any, H : CoseHeaderBase> sign1(
            header: CoseHeaderWrapped<H>,
            payload: P,
            payloadSerializer: KSerializer<P>,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            signer: suspend (ByteArray) -> ByteArray,
        ): CoseSign1Typed<P, H> = CoseTyped(
            CoseSign1(
                header = header,
                plainPayload = encodePayload(payload, payloadSerializer),
                detached = detached,
                externalAad = externalAad,
                signer = signer,
            ),
            payload,
            header,
        )

        /** Creates a [CoseSign1] from two [CoseHeader]s, one per bucket. */
        suspend fun <P : Any> sign1(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader? = null,
            payload: P,
            payloadSerializer: KSerializer<P>,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            signer: suspend (ByteArray) -> ByteArray,
        ): CoseSign1Typed<P, CoseHeader> = sign1(
            header = wrapCoseHeaders(protectedHeader, unprotectedHeader),
            payload = payload,
            payloadSerializer = payloadSerializer,
            detached = detached,
            externalAad = externalAad,
            signer = signer,
        )

        /** Creates a [CoseMac0] with the buckets of [header] over [payload], encoded with [payloadSerializer]. */
        suspend fun <P : Any, H : CoseHeaderBase> mac0(
            header: CoseHeaderWrapped<H>,
            payload: P,
            payloadSerializer: KSerializer<P>,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            mac: suspend (ByteArray) -> ByteArray,
        ): CoseMac0Typed<P, H> = CoseTyped(
            CoseMac0(
                header = header,
                plainPayload = encodePayload(payload, payloadSerializer),
                detached = detached,
                externalAad = externalAad,
                mac = mac,
            ),
            payload,
            header,
        )

        /** Creates a [CoseMac0] from two [CoseHeader]s, one per bucket. */
        suspend fun <P : Any> mac0(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader? = null,
            payload: P,
            payloadSerializer: KSerializer<P>,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            mac: suspend (ByteArray) -> ByteArray,
        ): CoseMac0Typed<P, CoseHeader> = mac0(
            header = wrapCoseHeaders(protectedHeader, unprotectedHeader),
            payload = payload,
            payloadSerializer = payloadSerializer,
            detached = detached,
            externalAad = externalAad,
            mac = mac,
        )
    }
}

/** The signature of a [CoseSign1], interpreted according to `alg` (or the `x5chain` leaf) of the effective header. */
val CoseSign1Typed<*, *>.signature: CryptoSignature
    get() = COSE.getSignature(cose.plainSignature, header)

/**
 * Serializes a [CoseTyped] through its wire object only, decoding the payload and header on the way back.
 *
 * Mirrors josef's `JwsTypedSerializerTemplate`.
 */
class CoseTypedSerializerTemplate<C : CosePlaintextMessage, P, H : CoseHeaderBase>(
    coseSerializer: KSerializer<C>,
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
    serialFormat: Cbor = coseCompliantSerializer,
) : TransformingSerializerTemplate<CoseTyped<C, P, H>, C>(
    parent = coseSerializer,
    serialName = "CoseTyped",
    encodeAs = { it.cose },
    decodeAs = { cose ->
        CoseTyped(
            cose,
            cose.getPayload(payloadSerializer, serialFormat).getOrThrow(),
            cose.wrappedHeader(headerSerializer, serialFormat),
        )
    }
)

/**
 * Encodes [payload] the way the previous `CoseSigned.create` did: a [ByteArray] is used as-is, anything else is
 * serialized and wrapped in CBOR tag 24
 */
internal fun <P : Any> encodePayload(payload: P, payloadSerializer: KSerializer<P>): ByteArray = when (payload) {
    is ByteArray -> payload
    is ByteStringWrapper<*> -> throw IllegalArgumentException("Payload must not be a ByteStringWrapper")
    else -> coseCompliantSerializer.encodeToByteArray(
        ByteStringWrapperSerializer(payloadSerializer), ByteStringWrapper(payload)
    ).wrapInCborTag(24)
}