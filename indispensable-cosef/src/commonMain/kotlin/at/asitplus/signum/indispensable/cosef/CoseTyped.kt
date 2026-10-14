package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encodeToByteArray

typealias CoseSign1Typed<P> = CoseTyped<CoseSign1, P>
typealias CoseMac0Typed<P> = CoseTyped<CoseMac0, P>

/**
 * Pairs a [COSE] wire object with its decoded payload, for when the payload type is part of the contract.
 *
 * The direct counterpart of josef's `JwsTyped`. The point is that the payload type is **not** a parameter of the
 * wire class: `CoseSign1` stays a plain four-element structure holding raw bytes, and typing is layered on top.
 * Everything that goes over the wire should use [cose] only.
 */
data class CoseTyped<out C : COSE, out P>(
    val cose: C,
    val payload: P,
) {
    override fun toString(): String = cose.toString()
}

/**
 * Serializes a [CoseTyped] through its wire object only, decoding the payload on the way back.
 *
 * Mirrors josef's `JwsTypedSerializerTemplate` and reuses the same `TransformingSerializerTemplate` already used by
 * the current `CoseSignedSerializer`.
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
 * serialized and wrapped in CBOR tag 24.
 *
 * Kept as its own function because it is an application convention (ISO/IEC 18013-5, CWT), not something RFC 9052
 * mandates — RFC 9052 only says the payload is a `bstr`. Keeping it out of [CoseSign1] is what lets a caller with a
 * different convention bypass it.
 */
fun <P : Any> encodePayload(payload: P?, payloadSerializer: KSerializer<P>): ByteArray? = when (payload) {
    null -> null
    is ByteArray -> payload
    is ByteStringWrapper<*> -> throw IllegalArgumentException("Payload must not be a ByteStringWrapper")
    else -> coseCompliantSerializer.encodeToByteArray(
        ByteStringWrapperSerializer(payloadSerializer), ByteStringWrapper(payload)
    ).wrapInCborTag24()
}

private fun ByteArray.wrapInCborTag24() = byteArrayOf(0xd8.toByte(), 24) + this

/**
 * Builds a [CoseSign1] over a typed [payload], signing the structure produced from the protected bucket bytes.
 */
suspend fun <P : Any> coseSign1(
    protectedHeader: CoseHeader,
    unprotectedHeader: CoseHeader? = null,
    payload: P?,
    payloadSerializer: KSerializer<P>,
    externalAad: ByteArray = byteArrayOf(),
    signer: suspend (ByteArray) -> ByteArray,
): CoseSign1Typed<P?> {
    val plainPayload = encodePayload(payload, payloadSerializer)
    val cose = CoseSign1(
        protectedHeader = protectedHeader,
        unprotectedHeader = unprotectedHeader,
        plainPayload = plainPayload,
        externalAad = externalAad,
        signer = signer,
    )
    return CoseTyped(cose, payload)
}