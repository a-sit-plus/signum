package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.jvm.Transient

/**
 * [RFC 7515 Sec 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1)
 * Allows multiple digital signatures and/or MACs for the same payload
 */
@Serializable(with = JwsGeneralSerializer::class)
data class JwsGeneral<P>(
    /**
     * The [payload] member MUST be present and contain the value BASE64URL(JWS Payload).
     */
    @SerialName(SerialNames.PAYLOAD)
    val payload: P,

    /**
     * The [signatures] member value MUST be an array of JSON objects.
     * Each object represents a signature or MAC over the JWS Payload and
     * the JWS Protected Header.
     */
    @SerialName(SerialNames.JWS_SIGNATURES)
    val signatures: List<SignatureElement>,

    /**
     * ASCII string `<BASE64URL(payload)>` as used for signature verification.
     * See second part of [JwsSigned.prepareJwsSignatureInput]
     *
     * This parameter is required for correct serialization!
     */
    @Transient
    val plainPayload: ByteArray,
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsGeneral<*>

        if (payload != other.payload) return false
        if (signatures != other.signatures) return false
        if (!plainPayload.contentEquals(other.plainPayload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = payload?.hashCode() ?: 0
        result = 31 * result + signatures.hashCode()
        result = 31 * result + plainPayload.contentHashCode()
        return result
    }

    @Suppress("UNUSED")
    fun getPlainSignatureInputAt(index: Int): ByteArray =
        "${signatures[index].plainHeaderInput.decodeToString()}.${plainPayload.decodeToString()}".encodeToByteArray()

    /**
     * Returns a new [JwsGeneral] with [jwsSigned] appended as an additional signature.
     *
     * The payload of [jwsSigned] must match this object's payload and, if available,
     * the payload bytes encoded in existing [signatures]' [SignatureElement.plainHeaderInput].
     */
    fun appendSignature(jwsSigned: JwsSigned<*>): JwsGeneral<P> {
        require(payloadMatches(jwsSigned.payload, payload)) {
            "Additional signed JWS payload must match existing payload"
        }

        val additionalPayloadPart = jwsSigned.plainSignatureInput.payloadPart()
        require(plainPayload.contentEquals(additionalPayloadPart)) {
            "Additional signed JWS must sign the same payload bytes as existing signatures"
        }

        return copy(
            signatures = signatures + SignatureElement(
                protectedHeader = jwsSigned.header,
                signature = jwsSigned.signature,
                plainHeaderInput = jwsSigned.plainSignatureInput.headerPart(),
            )
        )
    }

    object SerialNames{
        const val PAYLOAD = "payload"
        const val JWS_SIGNATURES = "signatures"
    }

    companion object {

        /**
         * Creates a JSON General JWS representation from one or more compact-style signed JWS objects.
         *
         * All inputs must represent signatures over exactly the same payload bytes.
         */
        fun <P : Any> fromSignedJws(jwsSigned: List<JwsSigned<P>>): JwsGeneral<P> {
            require(jwsSigned.isNotEmpty()) { "At least one signed JWS is required" }

            val first = jwsSigned.first()
            val payloadPart = first.plainSignatureInput.payloadPart()

            jwsSigned.drop(1).forEachIndexed { index, current ->
                require(payloadMatches(current.payload, first.payload)) {
                    "All signed JWS payloads must match (mismatch at index ${index + 1})"
                }
                require(current.plainSignatureInput.payloadPart().contentEquals(payloadPart)) {
                    "All signed JWS objects must sign the same payload bytes (mismatch at index ${index + 1})"
                }
            }

            return JwsGeneral(
                payload = first.payload,
                signatures = jwsSigned.map {
                    SignatureElement(
                        protectedHeader = it.header,
                        signature = it.signature,
                        plainHeaderInput = it.plainSignatureInput.headerPart(),
                    )
                },
                plainPayload = payloadPart
            )
        }

        fun <P : Any> fromSignedJws(vararg jwsSigned: JwsSigned<P>): JwsGeneral<P> =
            fromSignedJws(jwsSigned.toList())
    }
}

private fun ByteArray.payloadPart(): ByteArray {
    val separator = indexOf('.'.code.toByte())
    require(separator > 0) {
        "Invalid JWS signature input format"
    }
    return copyOfRange(separator + 1, size)
}

private fun ByteArray.headerPart(): ByteArray {
    val separator = indexOf('.'.code.toByte())
    require(separator > 0) {
        "Invalid JWS signature input format"
    }
    return copyOfRange(0, separator)
}

private fun payloadMatches(left: Any?, right: Any?): Boolean = when (left) {
    is Array<*> -> right is Array<*> && left.contentEquals(right)
    is ByteArray -> right is ByteArray && left.contentEquals(right)
    is ShortArray -> right is ShortArray && left.contentEquals(right)
    is IntArray -> right is IntArray && left.contentEquals(right)
    is LongArray -> right is LongArray && left.contentEquals(right)
    is FloatArray -> right is FloatArray && left.contentEquals(right)
    is DoubleArray -> right is DoubleArray && left.contentEquals(right)
    is CharArray -> right is CharArray && left.contentEquals(right)
    is BooleanArray -> right is BooleanArray && left.contentEquals(right)
    else -> left == right
}
