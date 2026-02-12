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

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestBitsAndBytes by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Bits and Bytes" - {
        "Bit string" {
            val empty = byteArrayOf()

            val valueClassEmptyAnnotated = BitSetValueAnnotated(empty)

            DER.decodeFromDer<BitSetValueAnnotated>(
                DER.encodeToDer(valueClassEmptyAnnotated)
                    .also { it.toHexString() shouldBe "040bbf8a3b07bf8a3903030100" }
            ).bytes shouldBe valueClassEmptyAnnotated.bytes

            val normalEmpty = BitSetNormal(empty)

            DER.decodeFromDer<BitSetNormal>(
                DER.encodeToDer(normalEmpty).also { it.toHexString() shouldBe "3003030100" }
            ) shouldBe normalEmpty

            val normal = BitSetNormal(byteArrayOf(1, 2, 3))

            DER.decodeFromDer<BitSetNormal>(
                DER.encodeToDer(normal).also { it.toHexString() shouldBe "3006030400010203" }
            ) shouldBe normal

            val normalEmptyAnnotated = BitSetNormalAnnotated(empty)
            DER.decodeFromDer<BitSetNormalAnnotated>(
                DER.encodeToDer(normalEmptyAnnotated)
                    .also { it.toHexString() shouldBe "300b0409bf8a3b050403030100" }
            ) shouldBe normalEmptyAnnotated

            val normalEmptyAnnotatedOverride = BitSetNormalAnnotatedOverride(empty)
            DER.decodeFromDer<BitSetNormalAnnotatedOverride>(
                DER.encodeToDer(normalEmptyAnnotatedOverride)
                    .also { it.toHexString() shouldBe "300d040bbf8a3b0704059f8a390100" }
            ) shouldBe normalEmptyAnnotatedOverride

            val valueClassEmpty = BitSetValue(empty)
            val valueClass = BitSetValue(byteArrayOf(1, 2, 3))

            DER.decodeFromDer<BitSetValue>(
                DER.encodeToDer(valueClassEmpty)
                    .also { it.toHexString() shouldBe "030100" }
            ).bytes shouldBe valueClassEmpty.bytes

            DER.decodeFromDer<BitSetValue>(
                DER.encodeToDer(valueClass)
                    .also { it.toHexString() shouldBe "030400010203" }
            ).bytes shouldBe valueClass.bytes

            val valueClassEmptyAnnotatedOverride = BitSetValueAnnotatedOverride(empty)

            DER.decodeFromDer<BitSetValueAnnotatedOverride>(
                DER.encodeToDer(valueClassEmptyAnnotatedOverride)
                    .also { it.toHexString() shouldBe "0409bf8a3b059f8a390100" }
            ).bytes shouldBe valueClassEmptyAnnotatedOverride.bytes

            val valueClassEmptyAnnotatedAlsoInner = BitSetValueAnnotatedOverrideAlsoInner(empty)

            DER.decodeFromDer<BitSetValueAnnotatedOverrideAlsoInner>(
                DER.encodeToDer(valueClassEmptyAnnotatedAlsoInner)
                    .also { it.toHexString() shouldBe "0409bf8a3b059f8a390100" }
            ).bytes shouldBe valueClassEmptyAnnotatedAlsoInner.bytes
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
@Asn1nnotation(asBitString = true)
value class BitSetValue(val bytes: ByteArray)

@JvmInline
@Serializable
@Asn1nnotation(
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1339uL),
    Layer(Type.IMPLICIT_TAG, 1337uL),
    Layer(Type.IMPLICIT_TAG, 1336uL),
    asBitString = true,
)
value class BitSetValueAnnotatedOverride(val bytes: ByteArray)

@JvmInline
@Serializable
@Asn1nnotation(
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1339uL),
    Layer(Type.IMPLICIT_TAG, 1337uL),
    Layer(Type.EXPLICIT_TAG, 1390uL),
    asBitString = true,
)
value class BitSetValueAnnotated(val bytes: ByteArray)

// only the outer stuff counts
@JvmInline
@Serializable
@Asn1nnotation(
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1339uL),
    Layer(Type.IMPLICIT_TAG, 1337uL),
    Layer(Type.IMPLICIT_TAG, 1336uL),
    asBitString = true,
)
value class BitSetValueAnnotatedOverrideAlsoInner(
    @Asn1nnotation(
        Layer(Type.OCTET_STRING),
        Layer(Type.EXPLICIT_TAG, 999uL),
    ) val bytes: ByteArray
)

@Serializable
data class BitSetNormal(
    @Asn1nnotation(asBitString = true) val bytes: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitSetNormal) return false

        if (!bytes.contentEquals(other.bytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }
}

@Serializable
data class BitSetNormalAnnotated(
    @Asn1nnotation(
        Layer(Type.OCTET_STRING),
        Layer(Type.EXPLICIT_TAG, 1339uL),
        Layer(Type.OCTET_STRING),
        asBitString = true
    ) val bytes: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitSetNormalAnnotated) return false

        if (!bytes.contentEquals(other.bytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }
}

@Serializable
data class BitSetNormalAnnotatedOverride(
    @Asn1nnotation(
        Layer(Type.OCTET_STRING),
        Layer(Type.EXPLICIT_TAG, 1339uL),
        Layer(Type.OCTET_STRING),
        Layer(Type.IMPLICIT_TAG, 1337uL),
        asBitString = true
    ) val bytes: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitSetNormalAnnotatedOverride) return false

        if (!bytes.contentEquals(other.bytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }
}
