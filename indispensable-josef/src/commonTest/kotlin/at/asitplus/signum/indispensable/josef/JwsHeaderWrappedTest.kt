package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

@Serializable
internal data class CustomJwsHeader(
    @SerialName("alg") override val algorithm: JwsAlgorithm,
    @SerialName("kid") override val keyId: String? = null,
    val extension: String? = null,
    @Transient override val crit: List<String>? = null,
) : JwsHeader {
    @Transient override val type: String? = null
    @Transient override val contentType: String? = null
    @Transient override val certificateChain: CertificateChain? = null
    @Transient override val jsonWebKey: JsonWebKey? = null
    @Transient override val jsonWebKeySetUrl: String? = null
    @Transient override val certificateUrl: String? = null
    @Transient override val certificateSha1Thumbprint: ByteArray? = null
    @Transient override val certificateSha256Thumbprint: ByteArray? = null
}

val JwsHeaderWrappedTest by matrixSuite {
    "custom headers split and decode with explicit and reified serializers" {
        val header = CustomJwsHeader(JwsAlgorithm.Signature.RS256, "custom-key", "custom-value")
        val explicit = JwsHeaderWrapped(header, CustomJwsHeader.serializer(), setOf("extension"))
        val reified = JwsHeaderWrapped(header, setOf("extension"))

        explicit shouldBe reified
        explicit.protectedHeader.toProtectedHeaderJsonObject() shouldBe JsonObject(
            mapOf("alg" to JsonPrimitive("RS256"), "kid" to JsonPrimitive("custom-key"))
        )
        explicit.unprotectedHeader shouldBe JsonObject(mapOf("extension" to JsonPrimitive("custom-value")))
        JwsHeaderWrapped.fromParts(
            CustomJwsHeader.serializer(), explicit.protectedHeader, explicit.unprotectedHeader
        ) shouldBe explicit
        JwsHeaderWrapped.fromJsonObjects<CustomJwsHeader>(
            explicit.protectedHeader.toProtectedHeaderJsonObject(), explicit.unprotectedHeader
        ) shouldBe explicit
    }

    "equality ignores unprotected member set order" {
        val header = CustomJwsHeader(JwsAlgorithm.Signature.RS256, "key", "value")
        val first = JwsHeaderWrapped(header, linkedSetOf("kid", "extension"))
        val second = JwsHeaderWrapped(header, linkedSetOf("extension", "kid"))

        first.unprotectedHeaderMembers shouldBe setOf("kid", "extension")
        first shouldBe second
        first.hashCode() shouldBe second.hashCode()
        (first == JwsHeaderWrapped(header)) shouldBe false
    }

    "cached fragments remain available with an erased header type" {
        var encodings = 0
        val serializer = object : KSerializer<CustomJwsHeader> by CustomJwsHeader.serializer() {
            override fun serialize(encoder: Encoder, value: CustomJwsHeader) {
                encodings++
                CustomJwsHeader.serializer().serialize(encoder, value)
            }
        }
        val placement = mutableSetOf("extension")
        val wrapped: JwsHeaderWrapped<*> = JwsHeaderWrapped(
            CustomJwsHeader(JwsAlgorithm.Signature.RS256, extension = "value"), serializer, placement,
        )
        placement.clear()

        repeat(2) {
            wrapped.protectedHeader.toProtectedHeaderJsonObject() shouldBe
                    JsonObject(mapOf("alg" to JsonPrimitive("RS256")))
            wrapped.unprotectedHeader shouldBe JsonObject(mapOf("extension" to JsonPrimitive("value")))
        }
        wrapped.unprotectedHeaderMembers shouldBe setOf("extension")
        encodings shouldBe 1
    }

    "factories cache fragments using the supplied JSON configuration" {
        val format = Json(joseCompliantSerializer) { encodeDefaults = true }
        val wrapped = JwsHeaderWrapped(
            CustomJwsHeader(JwsAlgorithm.Signature.RS256), setOf("extension"), serialFormat = format,
        )

        wrapped.unprotectedHeader shouldBe JsonObject(mapOf("extension" to JsonNull))
        wrapped.unprotectedHeaderMembers shouldBe setOf("extension")
        val decoded = JwsHeaderWrapped.fromParts<CustomJwsHeader>(
            wrapped.protectedHeader, wrapped.unprotectedHeader, format,
        )
        decoded.protectedHeader shouldBe wrapped.protectedHeader
        decoded.unprotectedHeader shouldBe wrapped.unprotectedHeader
    }

    "duplicate extension names are rejected before header decoding" {
        val result = runCatching {
            JwsHeaderWrapped.fromJsonObjects<CustomJwsHeader>(
                JsonObject(mapOf("alg" to JsonPrimitive("RS256"), "extension" to JsonPrimitive("a"))),
                JsonObject(mapOf("extension" to JsonPrimitive("b"))),
            )
        }
        result.shouldBeFailure() shouldBe IllegalArgumentException("Duplicate keys: extension")
    }
}
