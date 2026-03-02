package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.Serializable

/**
 * [RFC 7515 Sec 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1)
 * Allows multiple digital signatures and/or MACs for the same payload
 */
@Serializable(with = JwsGeneralSerializer::class)
data class JwsGeneral<P>(
    /**
     * The [payload] member MUST be present and contain the value BASE64URL(JWS Payload).
     */
    val payload: P,
    /**
     * The [signatures] member value MUST be an array of JSON objects.
     * Each object represents a signature or MAC over the JWS Payload and
     * the JWS Protected Header.
     */
    val signatures: List<SignatureElement>,
) {

    /**
     * Returns a new [JwsGeneral] with [jwsSigned] appended as an additional signature.
     *
     * The payload of [jwsSigned] must match this object's payload and, if available,
     * the payload bytes encoded in existing [signatures]' [SignatureElement.plainSignatureInput].
     */
    fun appendSignature(jwsSigned: JwsSigned<*>): JwsGeneral<P> {
        require(payloadMatches(jwsSigned.payload, payload)) {
            "Additional signed JWS payload must match existing payload"
        }

        signatures.sharedPayloadPartOrNull()?.let { existingPayloadPart ->
            val additionalPayloadPart = jwsSigned.plainSignatureInput.payloadPart()
            require(additionalPayloadPart == existingPayloadPart) {
                "Additional signed JWS must sign the same payload bytes as existing signatures"
            }
        }

        return copy(
            signatures = signatures + SignatureElement(
                protectedHeader = jwsSigned.header,
                signature = jwsSigned.signature,
                plainSignatureInput = jwsSigned.plainSignatureInput,
            )
        )
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
                require(current.plainSignatureInput.payloadPart() == payloadPart) {
                    "All signed JWS objects must sign the same payload bytes (mismatch at index ${index + 1})"
                }
            }

            return JwsGeneral(
                payload = first.payload,
                signatures = jwsSigned.map {
                    SignatureElement(
                        protectedHeader = it.header,
                        signature = it.signature,
                        plainSignatureInput = it.plainSignatureInput,
                    )
                },
            )
        }

        fun <P : Any> fromSignedJws(vararg jwsSigned: JwsSigned<P>): JwsGeneral<P> =
            fromSignedJws(jwsSigned.toList())
    }
}

private fun ByteArray.payloadPart(): String {
    val separator = indexOf('.'.code.toByte())
    require(separator > 0 && separator < lastIndex) {
        "Invalid JWS signature input format"
    }
    return copyOfRange(separator + 1, size).decodeToString()
}

private fun List<SignatureElement>.sharedPayloadPartOrNull(): String? {
    var payloadPart: String? = null
    forEachIndexed { index, signatureElement ->
        val currentPart =
            runCatching { signatureElement.plainSignatureInput.payloadPart() }.getOrNull() ?: return@forEachIndexed
        payloadPart?.let {
            require(it == currentPart) {
                "Existing signatures do not share the same payload bytes (mismatch at index $index)"
            }
        } ?: run { payloadPart = currentPart }
    }
    return payloadPart
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
