package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlin.time.Instant

/** [JwtPayload] implementation annotating its NumericDate claims, as implementations are required to. */
@Serializable
internal data class NumericDatePayload(
    @SerialName("iss")
    override val issuer: String? = null,
    @SerialName("sub")
    override val subject: String? = null,
    @SerialName("aud")
    override val audience: String? = null,
    @SerialName("nbf")
    @Serializable(with = InstantLongSerializer::class)
    override val notBefore: Instant? = null,
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant? = null,
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    override val expiration: Instant? = null,
    @SerialName("jti")
    override val jwtId: String? = null,
) : JwtPayload

private fun decodeExp(value: String) =
    joseCompliantSerializer.decodeFromString<NumericDatePayload>("""{"exp":$value}""").expiration

val NumericDateTest by matrixSuite {
    "JSON NumericDate representations are decoded" - {
        data(sequenceOf(
            "1700000000" to Instant.fromEpochSeconds(1700000000),
            "17e8" to Instant.fromEpochSeconds(1700000000),
            "1.7e9" to Instant.fromEpochSeconds(1700000000),
            "1.7E9" to Instant.fromEpochSeconds(1700000000),
            "1.7E+9" to Instant.fromEpochSeconds(1700000000),
            "17000000000e-1" to Instant.fromEpochSeconds(1700000000),
            "1700000000.0" to Instant.fromEpochSeconds(1700000000),
            "1700000000.5" to Instant.fromEpochSeconds(1700000000, 500_000_000),
            "1700000000.25e0" to Instant.fromEpochSeconds(1700000000, 250_000_000),
            "-1.5" to Instant.fromEpochSeconds(-2, 500_000_000),
            "\"1700000000\"" to Instant.fromEpochSeconds(1700000000),
            "\"1.7e9\"" to Instant.fromEpochSeconds(1700000000),
            "0" to Instant.fromEpochSeconds(0),
            "-1" to Instant.fromEpochSeconds(-1),
        ), nameFn = { it.first }) test { (json, expected) ->
            decodeExp(json) shouldBe expected
        }
    }

    "invalid JSON NumericDates are rejected" - {
        data(
            sequenceOf("1e300", "-1e300", "true", "{}", "[]", "\"abc\"", "\"NaN\"", "\"Infinity\"", "\"1700000000d\"", "\"\""),
            nameFn = { it },
        ) test { json ->
            shouldThrow<SerializationException> { decodeExp(json) }
        }
    }

    "null NumericDate decodes to null" {
        decodeExp("null") shouldBe null
    }

    "encoding produces whole seconds" {
        val payload = NumericDatePayload(
            notBefore = Instant.fromEpochSeconds(1700000000),
            issuedAt = Instant.fromEpochSeconds(1700000000, 999_000_000),
        )
        joseCompliantSerializer.encodeToString(payload) shouldBe """{"nbf":1700000000,"iat":1700000000}"""
    }

    "JweHeader decodes NumericDate representations" {
        val header = joseCompliantSerializer.decodeFromString<JweHeader>(
            """{"alg":"ECDH-ES","enc":"A256GCM","nbf":17e8,"iat":1.7e9,"exp":1700000000.5}"""
        )
        header.notBefore shouldBe Instant.fromEpochSeconds(1700000000)
        header.issuedAt shouldBe Instant.fromEpochSeconds(1700000000)
        header.expiration shouldBe Instant.fromEpochSeconds(1700000000, 500_000_000)
    }
}
