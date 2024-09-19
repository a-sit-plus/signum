package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1PrimitiveOctetString
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.encoding.parseAll
import at.asitplus.signum.indispensable.asn1.encoding.parseFirst
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlin.random.Random

class Asn1ParserTest : FreeSpec({

    "Multiple Elements" - {
        val seq = Asn1.Sequence {
            repeat(10) {
                +Asn1PrimitiveOctetString(Random.nextBytes(16))
            }
        }

        val encoded = seq.derEncoded
        val rawChildren =
            encoded.sliceArray(seq.tag.encodedTagLength + seq.encodedLength.size until seq.derEncoded.size)

        "without Garbage" {
            val iterator = rawChildren.iterator()
            val parseFirst = Asn1Element.parseFirst(iterator)
            val childIterator = seq.children.iterator()
            parseFirst shouldBe childIterator.next()



            val bytes = iterator.toByteArray()
            bytes shouldBe rawChildren.sliceArray(parseFirst.overallLength until rawChildren.size)
            val byteIterator = bytes.iterator()
            repeat(9) { Asn1Element.parseFirst(byteIterator) shouldBe childIterator.next() }
            Asn1Element.parseAll(rawChildren.iterator()) shouldBe seq.children

            shouldThrow<Asn1Exception> { Asn1Element.parse(rawChildren) }
            shouldThrow<Asn1Exception> { Asn1Element.parse(rawChildren.iterator()) }
        }

        "with Garbage" {
            val garbage = Random.nextBytes(32)
            val withGarbage = rawChildren + garbage
            val iterator = withGarbage.iterator()
            val parseFirst = Asn1Element.parseFirst(iterator)
            val childIterator = seq.children.iterator()
            parseFirst shouldBe childIterator.next()

            val bytes = iterator.toByteArray()
            bytes shouldBe withGarbage.sliceArray(parseFirst.overallLength until withGarbage.size)

            val byteIterator = bytes.iterator()
            repeat(9) { Asn1Element.parseFirst(byteIterator) shouldBe childIterator.next() }


            shouldThrow<Asn1Exception> { Asn1Element.parseAll(withGarbage.iterator()) shouldBe seq.children }

            shouldThrow<Asn1Exception> { Asn1Element.parse(withGarbage) }
            shouldThrow<Asn1Exception> { Asn1Element.parse(withGarbage.iterator()) }
        }
    }
})