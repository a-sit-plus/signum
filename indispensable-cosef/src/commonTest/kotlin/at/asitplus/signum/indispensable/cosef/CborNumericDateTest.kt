package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.time.Instant

private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }
private fun Long.bigEndian(size: Int) = ByteArray(size) { (this shr (8 * (size - 1 - it))).toByte() }
private fun float64(value: Double) = bytes(0xFB) + value.toRawBits().bigEndian(8)
private fun float32(value: Float) = bytes(0xFA) + value.toRawBits().toLong().bigEndian(4)

/** CBOR unsigned integer 1700000000 */
private val uint1700000000 = bytes(0x1A, 0x65, 0x53, 0xF1, 0x00)

/** Decodes a CWT consisting only of claim 4 ("exp") with the given encoded value */
private fun decodeExp(value: ByteArray) =
    coseCompliantSerializer.decodeFromByteArray<CborWebToken>(bytes(0xA1, 0x04) + value).expiration

val CborNumericDateTest by matrixSuite {
    "CBOR NumericDate representations are decoded" - {
        data(
            sequenceOf(
                Triple("unsigned integer", uint1700000000, Instant.fromEpochSeconds(1700000000)),
                Triple("negative integer", bytes(0x20), Instant.fromEpochSeconds(-1)),
                Triple("tag 1 with unsigned integer", bytes(0xC1) + uint1700000000, Instant.fromEpochSeconds(1700000000)),
                Triple("float16", bytes(0xF9, 0x3C, 0x00), Instant.fromEpochSeconds(1)),
                Triple("float32", float32(1.7e9f), Instant.fromEpochSeconds(1700000000)),
                Triple("float64", float64(1.7e9), Instant.fromEpochSeconds(1700000000)),
                Triple("fractional float64", float64(1700000000.5), Instant.fromEpochSeconds(1700000000, 500_000_000)),
                Triple("negative fractional float64", float64(-1.5), Instant.fromEpochSeconds(-2, 500_000_000)),
            ),
            nameFn = { it.first },
        ) test { (_, encoded, expected) ->
            decodeExp(encoded) shouldBe expected
        }
    }

    "invalid CBOR NumericDates are rejected" - {
        data(
            sequenceOf(
                "NaN" to float64(Double.NaN),
                "+Infinity" to float64(Double.POSITIVE_INFINITY),
                "-Infinity" to float64(Double.NEGATIVE_INFINITY),
                "out of range" to float64(1e300),
                "text string" to bytes(0x6A) + "1700000000".encodeToByteArray(),
            ),
            nameFn = { it.first },
        ) test { (_, encoded) ->
            shouldThrow<SerializationException> { decodeExp(encoded) }
        }
    }

    "all CWT NumericDate claims accept floats and are encoded as integers" {
        // {4: 1700000000.5, 5: 1.7e9 (float32), 6: 1700000000}
        val encoded = bytes(0xA3, 0x04) + float64(1700000000.5) +
                bytes(0x05) + float32(1.7e9f) +
                bytes(0x06) + uint1700000000
        val cwt = coseCompliantSerializer.decodeFromByteArray<CborWebToken>(encoded)

        cwt.expiration shouldBe Instant.fromEpochSeconds(1700000000, 500_000_000)
        cwt.notBefore shouldBe Instant.fromEpochSeconds(1700000000)
        cwt.issuedAt shouldBe Instant.fromEpochSeconds(1700000000)
        coseCompliantSerializer.encodeToByteArray(cwt) shouldBe
                bytes(0xA3, 0x04) + uint1700000000 + bytes(0x05) + uint1700000000 + bytes(0x06) + uint1700000000
    }
}
