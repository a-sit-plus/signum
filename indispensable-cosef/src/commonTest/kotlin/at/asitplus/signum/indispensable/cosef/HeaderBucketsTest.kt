@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.legacy.CoseHeader as FixtureHeader
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborLabel

val HeaderBucketsTest by matrixSuite {
    "Negative numeric labels encode correctly with upstream serialization" {
        val bytes = coseCompliantSerializer.encodeToByteArray(NegativeHeader.serializer(), NegativeHeader("x"))
        bytes.hex() shouldBe "A13A000100006178"
        coseCompliantSerializer.decodeFromByteArray(NegativeHeader.serializer(), bytes) shouldBe NegativeHeader("x")
    }

    "x5chain alternatives do not consume the following field" {
        for (encoded in listOf("A21821420102106178", "A2182182420102420304106178")) {
            val decoded = decodeHeader(encoded.hexBytes(), FixtureHeader.serializer(), coseCompliantSerializer)
            decoded.header.type shouldBe "x"
            decoded.header.certificateChain!!.first().hex() shouldBe "0102"
        }
        for (bad in listOf("A1182101", "A118218101", "A118214201", "A1182182420102", "A1182180")) {
            shouldThrowAny { decodeHeader(bad.hexBytes(), FixtureHeader.serializer(), coseCompliantSerializer) }
        }
    }

    "Duplicate modeled labels and cross-bucket presence are rejected" {
        shouldThrowAny { decodeHeader("A2012601390100".hexBytes(), FixtureHeader.serializer(), coseCompliantSerializer) }
        shouldThrowAny { encodeHeader(DuplicateHeader(), DuplicateHeader.serializer(), true) }
        val protected = encodeHeader(FixtureHeader(algorithm = CoseAlgorithm.Signature.ES256), FixtureHeader.serializer(), true)
        val empty = encodeHeader(FixtureHeader(), FixtureHeader.serializer(), false)
        // Optional descriptor properties are not present parameters.
        validateBuckets(protected.header, empty.header, protected.labels, empty.labels)
        shouldThrowAny { validateBuckets(protected.header, protected.header, protected.labels, protected.labels) }
    }

    "Integer and text unions retain following fields and reject malformed alternatives" {
        for (encoded in listOf("A203183C106178", "A2036463626F72106178", "A20282206161106178")) {
            decodeHeader(encoded.hexBytes(), FixtureHeader.serializer(), coseCompliantSerializer).header.type shouldBe "x"
        }
        for (bad in listOf("A10381", "A10318", "A1036463", "A102811A", "A1028180")) {
            shouldThrowAny { decodeHeader(bad.hexBytes(), FixtureHeader.serializer(), coseCompliantSerializer) }
        }
    }

    "crit is nonempty, protected, unique, and refers to present parameters" {
        shouldThrowAny { coseCompliantSerializer.decodeFromByteArray(FixtureHeader.serializer(), "A10280".hexBytes()) }
        shouldThrowAny { encodeHeader(FixtureHeader(criticalHeaders = emptyList()), FixtureHeader.serializer(), true) }
        val critical = FixtureHeader(criticalHeaders = listOf(CoseHeaderLabel.Numeric(-65537)))
        shouldThrowAny { validateBuckets(critical, EmptyCoseHeader, setOf(CoseHeaderLabel.Numeric(2)), emptySet()) }
        shouldThrowAny { validateBuckets(EmptyCoseHeader, critical, emptySet(), setOf(CoseHeaderLabel.Numeric(2))) }
    }
}

@Serializable
private data class NegativeHeader(@CborLabel(-65537) val required: String) : CoseHeader

@Serializable
private data class DuplicateHeader(@CborLabel(1) val first: Int = 1, @CborLabel(1) val second: Int = 2) : CoseHeader
