package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Serializer
import kotlinx.serialization.builtins.ByteArraySerializer

/**
 * [RFC 7515 Sec 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1)
 * Allows multiple digital signatures and/or MACs for the same payload
 */
@Serializable
data class JwsGeneral(
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
     */
    @SerialName(SerialNames.PAYLOAD)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val plainPayload: ByteArray,
) {
    init {
        if (signatures.isEmpty()) throw AssertionError()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsGeneral

        if (signatures != other.signatures) return false
        if (!plainPayload.contentEquals(other.plainPayload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = signatures.hashCode()
        result = 31 * result + plainPayload.contentHashCode()
        return result
    }

    inline fun <reified P> getPayload(serializer: KSerializer<P>): P =
        if (serializer.descriptor.serialName == ByteArrayBase64UrlSerializer.descriptor.serialName) {
            plainPayload as P
        } else {
            joseCompliantSerializer.decodeFromString(
                serializer,
                plainPayload.decodeToString(),
            )
        }

    fun getPlainSignatureInputAt(index: Int): ByteArray =
        "${signatures[index].plainHeaderInput.decodeToString()}.${plainPayload.encodeToString(Base64UrlStrict)}".encodeToByteArray()

    /**
     * Returns a new [JwsGeneral] with [jwsSigned] appended as an additional signature.
     *
     * The payload of [jwsSigned] must match this object's payload and, if available,
     * the payload bytes encoded in existing [signatures]' [SignatureElement.plainHeaderInput].
     */
    fun appendSignature(jwsSigned: JwsSigned<*>): JwsGeneral {
        require(plainPayload.contentEqualsIfArray(jwsSigned.plainSignatureInput.payloadPart())) {
            "Additional signed JWS payload must match existing payload"
        }

        return copy(
            signatures = signatures + SignatureElement(
                protectedHeader = jwsSigned.header,
                signature = jwsSigned.signature,
                plainHeaderInput = jwsSigned.plainSignatureInput.headerPart(),
            )
        )
    }

    object SerialNames {
        const val PAYLOAD = "payload"
        const val JWS_SIGNATURES = "signatures"
    }

    companion object {

        /**
         * Creates a JSON General JWS representation from one or more compact-style signed JWS objects.
         *
         * All inputs must represent signatures over exactly the same payload bytes.
         */
        fun <P : Any> fromSignedJws(jwsSigned: List<JwsSigned<P>>): JwsGeneral {
            require(jwsSigned.isNotEmpty()) { "At least one signed JWS is required" }

            val first = jwsSigned.first()
            val payloadPart = first.plainSignatureInput.payloadPart()

            jwsSigned.drop(1).forEachIndexed { index, current ->
                require(payloadMatches(current.payload, first.payload)) {
                    "All signed JWS payloads must match (mismatch at index ${index + 1})"
                }
            }

            return JwsGeneral(
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

        fun <P : Any> fromSignedJws(vararg jwsSigned: JwsSigned<P>): JwsGeneral =
            fromSignedJws(jwsSigned.toList())
    }
}

private fun ByteArray.payloadPart(): ByteArray {
    val separator = indexOf('.'.code.toByte())
    require(separator > 0) {
        "Invalid JWS signature input format"
    }
    return copyOfRange(separator + 1, size).decodeToString().decodeToByteArray(Base64UrlStrict)
}

private fun ByteArray.headerPart(): ByteArray {
    val separator = indexOf('.'.code.toByte())
    require(separator > 0) {
        "Invalid JWS signature input format"
    }
    return copyOfRange(0, separator)
}

//Allows to circumvent reified generic in `fromJwsSigned`
private fun payloadMatches(left: Any?, right: Any?): Boolean =
    left.contentEqualsIfArray(right)
