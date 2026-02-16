package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestBitsAndBytes by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Bits and Bytes" - {
        "Bit string" {
            val empty = byteArrayOf()
            val valueClassEmpty = BitSetValue(empty)
            val valueClass = BitSetValue(byteArrayOf(1, 2, 3))

            DER.decodeFromDer<BitSetValue>(
                DER.encodeToDer(valueClassEmpty).also { it.toHexString() shouldBe "030100" }
            ).bytes shouldBe valueClassEmpty.bytes

            DER.decodeFromDer<BitSetValue>(
                DER.encodeToDer(valueClass).also { it.toHexString() shouldBe "030400010203" }
            ).bytes shouldBe valueClass.bytes

            val tagged = BitSetValueTagged(byteArrayOf(0x01, 0x02))
            DER.decodeFromDer<BitSetValueTagged>(DER.encodeToDer(tagged)).bytes.toList() shouldBe tagged.bytes.toList()
        }

        "octet string" {
            val empty = byteArrayOf()
            DER.decodeFromDer<ByteArray>(
                DER.encodeToDer(empty).also { it.toHexString() shouldBe "0400" }
            ) shouldBe empty
            val threeBytes = byteArrayOf(1, 2, 3)
            DER.decodeFromDer<ByteArray>(
                DER.encodeToDer(threeBytes).also { it.toHexString() shouldBe "0403010203" }
            ) shouldBe threeBytes
        }
    }
}

@JvmInline
@Serializable
value class BitSetValue(
    @Asn1BitString
    val bytes: ByteArray
)

@JvmInline
@Serializable
@Asn1Tag(tagNumber = 1336u)
value class BitSetValueTagged(
    @Asn1BitString
    val bytes: ByteArray
)
