package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

@Serializable
internal data class CustomJwsHeader(
    @SerialName("alg") override val algorithm: JwsAlgorithm,
    @SerialName("kid") override val keyId: String? = null,
    val extension: String? = null,
    @Transient override val crit: List<String>? = null,
) : JwsHeaderBase {
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
        explicit.toProtectedHeader().toProtectedHeaderJsonObject() shouldBe JsonObject(
            mapOf("alg" to JsonPrimitive("RS256"), "kid" to JsonPrimitive("custom-key"))
        )
        explicit.toUnprotectedHeader() shouldBe JsonObject(mapOf("extension" to JsonPrimitive("custom-value")))
        JwsHeaderWrapped.fromParts(
            CustomJwsHeader.serializer(), explicit.toProtectedHeader(), explicit.toUnprotectedHeader()
        ) shouldBe explicit
        JwsHeaderWrapped.fromJsonObjects<CustomJwsHeader>(
            explicit.toProtectedHeader().toProtectedHeaderJsonObject(), explicit.toUnprotectedHeader()
        ) shouldBe explicit
    }

    "equality uses effective placement rather than absent names or set order" {
        val header = CustomJwsHeader(JwsAlgorithm.Signature.RS256, "key", "value")
        val first = JwsHeaderWrapped(header, linkedSetOf("kid", "extension", "absent"))
        val second = JwsHeaderWrapped(header, linkedSetOf("extension", "kid"))

        first.unprotectedMembers shouldBe setOf("kid", "extension", "absent")
        first.effectiveUnprotectedMembers shouldBe setOf("kid", "extension")
        first shouldBe second
        first.hashCode() shouldBe second.hashCode()
        (first == JwsHeaderWrapped(header)) shouldBe false
    }

    "unknown fragment members do not become modeled unprotected members" {
        val wrapped = JwsHeaderWrapped.fromJsonObjects<CustomJwsHeader>(
            JsonObject(mapOf("alg" to JsonPrimitive("RS256"))),
            JsonObject(mapOf("unknown" to JsonPrimitive("value"))),
        )

        wrapped.unprotectedMembers shouldBe setOf("unknown")
        wrapped.effectiveUnprotectedMembers shouldBe emptySet()
        wrapped.toUnprotectedHeader() shouldBe JsonObject(emptyMap())
        wrapped shouldBe JwsHeaderWrapped(CustomJwsHeader(JwsAlgorithm.Signature.RS256))
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
