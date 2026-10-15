package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer

typealias CoseSign1Typed<P> = CoseTyped<CoseSign1, P>
typealias CoseMac0Typed<P> = CoseTyped<CoseMac0, P>

/**
 * Pairs a [COSE] wire object with its decoded payload, for when the payload type is part of the contract.
 *
 * Everything that goes over the wire should use [cose] only; [payload] is derived from it.
 */
data class CoseTyped<out C : COSE, out P>(
    val cose: C,
    val payload: P,
) {
    override fun toString(): String = cose.toString()

    companion object {

        /** Creates a [CoseSign1] over [payload], encoded with [payloadSerializer]. */
        suspend fun <P : Any> sign1(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader? = null,
            payload: P,
            payloadSerializer: KSerializer<P>,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            signer: suspend (ByteArray) -> ByteArray,
        ): CoseSign1Typed<P> = CoseTyped(
            CoseSign1(
                protectedHeader = protectedHeader,
                unprotectedHeader = unprotectedHeader,
                plainPayload = encodePayload(payload, payloadSerializer),
                detached = detached,
                externalAad = externalAad,
                signer = signer,
            ),
            payload,
        )

        /** Creates a [CoseMac0] over [payload], encoded with [payloadSerializer]. */
        suspend fun <P : Any> mac0(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader? = null,
            payload: P,
            payloadSerializer: KSerializer<P>,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            mac: suspend (ByteArray) -> ByteArray,
        ): CoseMac0Typed<P> = CoseTyped(
            CoseMac0(
                protectedHeader = protectedHeader,
                unprotectedHeader = unprotectedHeader,
                plainPayload = encodePayload(payload, payloadSerializer),
                detached = detached,
                externalAad = externalAad,
                mac = mac,
            ),
            payload,
        )
    }
}

/**
 * Serializes a [CoseTyped] through its wire object only, decoding the payload on the way back.
 *
 * Mirrors josef's `JwsTypedSerializerTemplate`.
 */
class CoseTypedSerializerTemplate<C : COSE, P>(
    coseSerializer: KSerializer<C>,
    private val payloadSerializer: KSerializer<P>,
) : TransformingSerializerTemplate<CoseTyped<C, P>, C>(
    parent = coseSerializer,
    serialName = "CoseTyped",
    encodeAs = { it.cose },
    decodeAs = { cose -> CoseTyped(cose, cose.getPayload(payloadSerializer).getOrThrow()) }
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