package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Wrapper for all JWE formats.
 */
@Serializable(with = JWE.JweSerializer::class)
sealed class JWE : JsonSecured {

    object SerialNames {
        const val PROTECTED = "protected"
        const val UNPROTECTED = "unprotected"
        const val HEADER = "header"
        const val RECIPIENTS = "recipients"
        const val ENCRYPTED_KEY = "encrypted_key"
        const val AAD = "aad"
        const val INITIALIZATION_VECTOR = "iv"
        const val CIPHERTEXT = "ciphertext"
        const val AUTHENTICATION_TAG = "tag"

        /* Shapes */
        const val COMPACT = "compact"
        const val FLATTENED = "flattened"
        const val GENERAL = "general"
    }

    companion object {
        fun getEncodedProtectedHeader(protectedHeader: ByteArray?): String =
            protectedHeader?.encodeToString(Base64UrlStrict).orEmpty()

        /**
         * Builds the RFC 7516 Additional Authenticated Data input from the protected header and optional JWE AAD.
         */
        fun getAdditionalAuthenticatedData(
            protectedHeader: ByteArray?,
            additionalAuthenticatedData: ByteArray?
        ): ByteArray {
            val encodedProtectedHeader = getEncodedProtectedHeader(protectedHeader)
            return if (additionalAuthenticatedData == null) {
                encodedProtectedHeader.encodeToByteArray()
            } else {
                "$encodedProtectedHeader.${additionalAuthenticatedData.encodeToString(Base64UrlStrict)}".encodeToByteArray()
            }
        }
    }


    object JweSerializer : KSerializer<JWE> {
        @OptIn(InternalSerializationApi::class)
        override val descriptor: SerialDescriptor = buildSerialDescriptor("JWE", PolymorphicKind.SEALED) {
            element(SerialNames.COMPACT, JweCompactStringSerializer.descriptor)
            element(SerialNames.FLATTENED, JweFlattened.Companion.serializer().descriptor)
            element(SerialNames.GENERAL, JweGeneral.Companion.serializer().descriptor)
        }

        override fun serialize(encoder: Encoder, value: JWE) {
            require(encoder is JsonEncoder) { "JWE serialization requires a JsonEncoder" }
            when (value) {
                is JweCompact -> encoder.encodeSerializableValue(JweCompactStringSerializer, value)
                is JweFlattened -> encoder.encodeSerializableValue(JweFlattened.Companion.serializer(), value)
                is JweGeneral -> encoder.encodeSerializableValue(JweGeneral.Companion.serializer(), value)
            }
        }

        override fun deserialize(decoder: Decoder): JWE {
            require(decoder is JsonDecoder) { "JWE deserialization requires a JsonDecoder" }

            return when (val jsonElement = decoder.decodeJsonElement()) {
                is JsonPrimitive -> decoder.json.decodeFromJsonElement(JweCompactStringSerializer, jsonElement)
                is JsonObject -> {
                    val hasRecipients = SerialNames.RECIPIENTS in jsonElement
                    val hasFlattenedRecipientHeader = SerialNames.HEADER in jsonElement
                    val hasFlattenedEncryptedKey = SerialNames.ENCRYPTED_KEY in jsonElement
                    val hasCiphertext = SerialNames.CIPHERTEXT in jsonElement

                    when {
                        hasRecipients && (hasFlattenedRecipientHeader || hasFlattenedEncryptedKey) ->
                            throw SerializationException(
                                "Invalid JWE JSON serialization: object must not contain '${SerialNames.RECIPIENTS}' " +
                                        "with top-level '${SerialNames.HEADER}' or '${SerialNames.ENCRYPTED_KEY}'"
                            )

                        hasRecipients ->
                            decoder.json.decodeFromJsonElement(JweGeneral.Companion.serializer(), jsonElement)

                        hasCiphertext ->
                            decoder.json.decodeFromJsonElement(JweFlattened.Companion.serializer(), jsonElement)

                        else ->
                            throw SerializationException(
                                "Invalid JWE JSON serialization: object must contain " +
                                        "'${SerialNames.CIPHERTEXT}' or '${SerialNames.RECIPIENTS}'"
                            )
                    }
                }

                else -> throw SerializationException(
                    "Invalid JWE JSON serialization: expected a compact string or JSON object"
                )
            }
        }
    }
}
