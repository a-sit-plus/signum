package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import at.asitplus.testballoon.checkAll
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.arbitrary
import kotlin.random.Random

@OptIn(ExperimentalStdlibApi::class)
val Asn1SetSortingTest by testSuite {
    "SET sorts children lexicographically by DER bytes" {
        val larger = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, byteArrayOf(0x01))
        val smaller = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, byteArrayOf(0x00))

        val set = Asn1Set(listOf(larger, smaller))

        set.children.shouldContainExactly(smaller, larger)
        set.derEncoded.toHexString() shouldBe "3106040100040101"
    }

    "SET OF sorts children lexicographically by DER bytes" {
        val larger = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, byteArrayOf(0x01))
        val smaller = Asn1Primitive(Asn1Element.Tag.OCTET_STRING, byteArrayOf(0x00))

        val setOf = Asn1SetOf(listOf(larger, smaller))

        setOf.children.shouldContainExactly(smaller, larger)
        setOf.derEncoded.toHexString() shouldBe "3106040100040101"
    }

    "Property checks" - {
        "SET sorts OCTET STRING payloads like independent DER ordering baseline" - {
            checkAll(iterations = 750, randomOctetStringPayloadLists()) { payloads ->
                val asn1Set = Asn1Set(payloads.map { payload ->
                    Asn1Primitive(Asn1Element.Tag.OCTET_STRING, payload)
                })

                val expectedPayloadOrder = payloads.sortedWith(::compareOctetStringPayloadsByDerRules)
                val actualPayloadOrder = asn1Set.children.map { it.asPrimitive().content }

                actualPayloadOrder.size shouldBe expectedPayloadOrder.size
                actualPayloadOrder.zip(expectedPayloadOrder).forEach { (actual, expected) ->
                    (actual contentEquals expected) shouldBe true
                }
            }
        }

        "SET OF sorts OCTET STRING payloads like independent DER ordering baseline" - {
            checkAll(iterations = 750, randomOctetStringPayloadLists()) { payloads ->
                val asn1Set = Asn1SetOf(payloads.map { payload ->
                    Asn1Primitive(Asn1Element.Tag.OCTET_STRING, payload)
                })

                val expectedPayloadOrder = payloads.sortedWith(::compareOctetStringPayloadsByDerRules)
                val actualPayloadOrder = asn1Set.children.map { it.asPrimitive().content }

                actualPayloadOrder.size shouldBe expectedPayloadOrder.size
                actualPayloadOrder.zip(expectedPayloadOrder).forEach { (actual, expected) ->
                    (actual contentEquals expected) shouldBe true
                }
            }
        }

        "SET encoding is permutation-invariant for identical OCTET STRING multiset" - {
            checkAll(iterations = 400, randomOctetStringPayloadLists()) { payloads ->
                val forward = Asn1Set(payloads.map { Asn1Primitive(Asn1Element.Tag.OCTET_STRING, it) })
                val reversed = Asn1Set(payloads.asReversed().map { Asn1Primitive(Asn1Element.Tag.OCTET_STRING, it) })

                (forward.derEncoded contentEquals reversed.derEncoded) shouldBe true
            }
        }

        "SET of random mixed nested elements is strictly DER-sorted" - {
            checkAll(iterations = 500, randomAsn1ElementLists(maxDepth = 3)) { generated ->
                val deduplicated = generated.distinctBy { it.derEncoded.toHexString() }
                val set = Asn1Set(deduplicated)
                val sortedChildrenDer = set.children.map { it.derEncoded }

                for (index in 1 until sortedChildrenDer.size) {
                    val predecessor = sortedChildrenDer[index - 1]
                    val successor = sortedChildrenDer[index]
                    (compareUnsignedLexicographically(predecessor, successor) < 0) shouldBe true
                }
            }
        }
    }
}

private fun randomOctetStringPayloadLists(): Arb<List<ByteArray>> = arbitrary { rs ->
    val count = rs.random.nextInt(0, 64)
    List(count) {
        val size = rs.random.nextInt(0, 384)
        ByteArray(size) { rs.random.nextInt(0, 256).toByte() }
    }
}

private fun randomAsn1ElementLists(maxDepth: Int): Arb<List<Asn1Element>> = arbitrary { rs ->
    val count = rs.random.nextInt(0, 40)
    List(count) { randomAsn1Element(rs.random, maxDepth) }
}

private fun randomAsn1Element(random: Random, depth: Int): Asn1Element {
    val forcePrimitive = depth <= 0 || random.nextInt(100) < 65
    if (forcePrimitive) return randomPrimitiveElement(random)

    val childCount = random.nextInt(0, 8)
    val children = List(childCount) { randomAsn1Element(random, depth - 1) }
    return when (random.nextInt(3)) {
        0 -> Asn1Sequence(children)
        1 -> Asn1Set(children)
        else -> Asn1ExplicitlyTagged(random.nextInt(0, 64).toULong(), children)
    }
}

private fun randomPrimitiveElement(random: Random): Asn1Element = when (random.nextInt(8)) {
    0 -> random.nextBoolean().encodeToAsn1Primitive()
    1 -> random.nextInt().encodeToAsn1Primitive()
    2 -> random.nextLong().encodeToAsn1Primitive()
    3 -> randomAsciiString(random).encodeToAsn1Primitive()
    4 -> Asn1Primitive(Asn1Element.Tag.OCTET_STRING, randomByteArray(random, 0, 96))
    5 -> Asn1Null
    6 -> Asn1Primitive(randomCustomPrimitiveTag(random), randomByteArray(random, 0, 32))
    else -> Asn1Primitive(Asn1Element.Tag.BIT_STRING, randomByteArray(random, 0, 96))
}

private fun randomCustomPrimitiveTag(random: Random) = Asn1Element.Tag(
    tagValue = random.nextInt(0, 256).toULong(),
    constructed = false,
    tagClass = when (random.nextInt(4)) {
        0 -> TagClass.UNIVERSAL
        1 -> TagClass.APPLICATION
        2 -> TagClass.CONTEXT_SPECIFIC
        else -> TagClass.PRIVATE
    }
)

private fun randomAsciiString(random: Random): String {
    val len = random.nextInt(0, 64)
    val chars = CharArray(len) { (' '..'~').random(random) }
    return chars.concatToString()
}

private fun randomByteArray(random: Random, min: Int, maxExclusive: Int): ByteArray {
    val len = random.nextInt(min, maxExclusive)
    return ByteArray(len) { random.nextInt(0, 256).toByte() }
}

private fun compareOctetStringPayloadsByDerRules(a: ByteArray, b: ByteArray): Int {
    val lengthOctetsCompare = compareUnsignedLexicographically(encodeDerLength(a.size), encodeDerLength(b.size))
    if (lengthOctetsCompare != 0) return lengthOctetsCompare
    return compareUnsignedLexicographically(a, b)
}

private fun compareUnsignedLexicographically(a: ByteArray, b: ByteArray): Int {
    val minLength = minOf(a.size, b.size)
    for (index in 0 until minLength) {
        val byteCompare = a[index].toUByte().compareTo(b[index].toUByte())
        if (byteCompare != 0) return byteCompare
    }
    return a.size.compareTo(b.size)
}

private fun encodeDerLength(length: Int): ByteArray {
    require(length >= 0)
    if (length < 128) return byteArrayOf(length.toByte())

    var value = length
    val valueOctets = mutableListOf<Byte>()
    while (value > 0) {
        valueOctets += (value and 0xFF).toByte()
        value = value ushr 8
    }

    val result = ByteArray(valueOctets.size + 1)
    result[0] = (0x80 or valueOctets.size).toByte()
    for (index in valueOctets.indices) {
        result[result.lastIndex - index] = valueOctets[index]
    }
    return result
}
