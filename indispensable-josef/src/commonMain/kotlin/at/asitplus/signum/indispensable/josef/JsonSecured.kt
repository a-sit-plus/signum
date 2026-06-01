package at.asitplus.signum.indispensable.josef

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
 * Parent class of Json formats that either use [JWS] or [JWE]
 * If payload is [JwtClaims] and either [JwsCompact] and/or [JweCompact] is used then this is a JsonWebToken.
 */
@Serializable(with = JsonSecured.Serializer::class)
sealed interface JsonSecured {
    object Serializer : KSerializer<JsonSecured> {
        @OptIn(InternalSerializationApi::class)
        override val descriptor: SerialDescriptor = buildSerialDescriptor("JsonSecured", PolymorphicKind.SEALED) {
            element("jws", JWS.JwsSerializer.descriptor)
            element("jwe", JWE.JweSerializer.descriptor)
        }

        override fun serialize(encoder: Encoder, value: JsonSecured) {
            require(encoder is JsonEncoder) { "JsonSecured serialization requires a JsonEncoder" }
            when (value) {
                is JWS -> encoder.encodeSerializableValue(JWS.JwsSerializer, value)
                is JWE -> encoder.encodeSerializableValue(JWE.JweSerializer, value)
            }
        }

        override fun deserialize(decoder: Decoder): JsonSecured {
            require(decoder is JsonDecoder) { "JsonSecured deserialization requires a JsonDecoder" }
            val jsonElement = decoder.decodeJsonElement()

            return when (jsonElement) {
                is JsonPrimitive -> {
                    if (!jsonElement.isString) {
                        throw SerializationException(
                            "Invalid JOSE compact serialization: expected a compact string or JSON object"
                        )
                    }

                    val partCount = jsonElement.content.count { it == '.' } + 1
                    when (partCount) {
                        3 -> decoder.json.decodeFromJsonElement(JWS.JwsSerializer, jsonElement)
                        5 -> decoder.json.decodeFromJsonElement(JWE.JweSerializer, jsonElement)
                        else -> throw SerializationException(
                            "Invalid JOSE compact serialization: expected 3 JWS parts or 5 JWE parts, got $partCount"
                        )
                    }
                }

                is JsonObject -> {
                    val hasPayload = JWS.SerialNames.PAYLOAD in jsonElement
                    val hasCiphertext = JWE.SerialNames.CIPHERTEXT in jsonElement

                    when {
                        hasPayload && hasCiphertext -> throw SerializationException(
                            "Invalid JOSE JSON serialization: object must not contain both " +
                                    "'${JWS.SerialNames.PAYLOAD}' and '${JWE.SerialNames.CIPHERTEXT}'"
                        )

                        hasPayload -> decoder.json.decodeFromJsonElement(JWS.JwsSerializer, jsonElement)
                        hasCiphertext -> decoder.json.decodeFromJsonElement(JWE.JweSerializer, jsonElement)
                        else -> throw SerializationException(
                            "Invalid JOSE JSON serialization: object must contain " +
                                    "'${JWS.SerialNames.PAYLOAD}' or '${JWE.SerialNames.CIPHERTEXT}'"
                        )
                    }
                }

                else -> throw SerializationException(
                    "Invalid JOSE JSON serialization: expected a compact string or JSON object"
                )
            }
        }
    }
}
