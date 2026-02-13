package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestMapSupport by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Map roundtrip is supported" {
        val plainMap = mapOf(1 to true, 2 to false, 3 to true)
        DER.decodeFromDer<Map<Int, Boolean>>(DER.encodeToDer(plainMap)) shouldBe plainMap

        val wrapped = MapInEnvelope(
            prefix = "map-check",
            values = plainMap,
            suffix = listOf(7, 8, 9)
        )

        DER.decodeFromDer<MapInEnvelope>(DER.encodeToDer(wrapped)) shouldBe wrapped
    }

    "Nullable map/list ambiguity is rejected unless tagged" {
        val ambiguous = AmbiguousNullableMapThenList(
            maybeMap = null,
            values = listOf(1, 2, 3)
        )
        shouldThrow<SerializationException> {
            DER.encodeToDer(ambiguous)
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<AmbiguousNullableMapThenList>("3000".hexToByteArray())
        }

        val taggedWithoutMap = TaggedNullableMapThenList(
            maybeMap = null,
            values = listOf(1, 2, 3)
        )
        val taggedWithMap = TaggedNullableMapThenList(
            maybeMap = mapOf(1 to true),
            values = listOf(1, 2, 3)
        )

        DER.decodeFromDer<TaggedNullableMapThenList>(DER.encodeToDer(taggedWithoutMap)) shouldBe taggedWithoutMap
        DER.decodeFromDer<TaggedNullableMapThenList>(DER.encodeToDer(taggedWithMap)) shouldBe taggedWithMap
    }
}

@Serializable
data class AmbiguousNullableMapThenList(
    val maybeMap: Map<Int, Boolean>?,
    val values: List<Int>,
)

@Serializable
data class TaggedNullableMapThenList(
    @Asn1Tag(tagNumber = 40u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val maybeMap: Map<Int, Boolean>?,
    val values: List<Int>,
)

@Serializable
data class MapInEnvelope(
    val prefix: String,
    val values: Map<Int, Boolean>,
    val suffix: List<Int>,
)
