package at.asitplus.signum.indispensable.cosef

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo.Companion.from
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.ECPoint
import at.asitplus.signum.indispensable.ECPointSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@Serializable
private data class PointHolder(val before: Int, val point: ECPoint.Normalized, val after: String)

@Serializable
private data class PointlessHolder(val before: Int, val after: String)

/**
 * `coseCompliantSerializer` ignores unknown keys (`ignoreUnknownKeys = true`), so a reader that does
 * not know a field skips its value as exactly one CBOR data item. That only works if the value is
 * well-formed CBOR; a serializer whose descriptor does not match what it writes breaks it.
 */
val ECPointSerializationTest by matrixSuite {
    "Unknown point field is skipped as exactly one CBOR data item" {
        val bytes = coseCompliantSerializer.encodeToByteArray(
            PointHolder(42, ECCurve.SECP_256_R_1.generator, "trailer")
        )
        // `point` must be followed by another field, otherwise leftover items go unnoticed
        coseCompliantSerializer.decodeFromByteArray<PointlessHolder>(bytes) shouldBe
                PointlessHolder(42, "trailer")
    }

    "Unknown curve fails with a SerializationException" {
        val point = ECCurve.SECP_256_R_1.generator
        // 2.999 is the OID arc reserved for examples, so it never names a real curve
        val unknownCurve = ObjectIdentifier("2.999.1")
        val spki = SubjectPublicKeyInfo.from(Sec1EcPublicKeyInfo(unknownCurve, point.xBytes, point.yBytes))
        val der = DER.encodeToByteArray(SubjectPublicKeyInfo.serializer(), spki)
        shouldThrow<SerializationException> {
            coseCompliantSerializer.decodeFromByteArray(
                ECPointSerializer, coseCompliantSerializer.encodeToByteArray(ByteArraySerializer(), der)
            )
        }
    }
}
