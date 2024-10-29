package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.*
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

            val (parseFirst, rest) = Asn1Element.parseFirst(rawChildren)
            val childIterator = seq.children.iterator()
            parseFirst shouldBe childIterator.next()




            rest shouldBe rawChildren.sliceArray(parseFirst.overallLength until rawChildren.size)
            Asn1Element.parseFirst(rawChildren).let { (elem,rest )->
                elem shouldBe seq.children.first()
                rest shouldBe  rawChildren.sliceArray(parseFirst.overallLength until rawChildren.size)
            }
            var byteIterator = rest
            repeat(9) {
                Asn1Element.parseFirst(byteIterator)
                    .let { (elem, residue) -> byteIterator = residue;elem } shouldBe childIterator.next()
            }
            Asn1Element.parseAll(rawChildren) shouldBe seq.children

            shouldThrow<Asn1Exception> { Asn1Element.parse(rawChildren) }
            shouldThrow<Asn1Exception> { Asn1Element.parse(rawChildren.iterator()) }
        }

        "with Garbage" {
            val garbage = Random.nextBytes(32)
            val withGarbage = rawChildren + garbage
            val source = withGarbage.wrapInUnsafeSource()
            val (parseFirst,rest) = Asn1Element.parseFirst(withGarbage)
            val firstFromSource= source.readAsn1Element().first
            firstFromSource shouldBe parseFirst
            val childIterator = seq.children.iterator()
            parseFirst shouldBe childIterator.next()


            rest shouldBe withGarbage.sliceArray(parseFirst.overallLength until withGarbage.size)

            Asn1Element.parseFirst(withGarbage).let { (elem,rest )->
                elem shouldBe seq.children.first()
                rest shouldBe   withGarbage.sliceArray(parseFirst.overallLength until withGarbage.size)
            }


            repeat(9) { source.readAsn1Element().first shouldBe childIterator.next() }


            shouldThrow<Asn1Exception> { Asn1Element.parseAll(withGarbage.iterator()) shouldBe seq.children }

            shouldThrow<Asn1Exception> { Asn1Element.parse(withGarbage) }
            shouldThrow<Asn1Exception> { Asn1Element.parse(withGarbage.iterator()) }
        }
    }
})