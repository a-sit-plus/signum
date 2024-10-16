package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.io.copyToSource
import at.asitplus.signum.indispensable.toByteArray
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.readByteArray
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
            val iterator = rawChildren.copyToSource()
            val parseFirst =iterator.readAsn1Element()
            val childIterator = seq.children.iterator()
            parseFirst shouldBe childIterator.next()

            val bytes = iterator.readByteArray()
            bytes shouldBe rawChildren.sliceArray(parseFirst.overallLength.toInt() until rawChildren.size)
            Asn1Element.parseFirst(rawChildren).let { (elem,rest )->
                elem shouldBe seq.children.first()
                rest shouldBe  rawChildren.sliceArray(parseFirst.overallLength.toInt() until rawChildren.size)
            }
            val byteIterator = bytes.copyToSource()
            repeat(9) { byteIterator.readAsn1Element()shouldBe childIterator.next() }
            Asn1Element.parseAll(rawChildren) shouldBe seq.children

            shouldThrow<Asn1Exception> { Asn1Element.parse(rawChildren) }
            shouldThrow<Asn1Exception> { Asn1Element.parse(rawChildren) }
            println(iterator)
        }

        "with Garbage" {
            val garbage = Random.nextBytes(32)
            val withGarbage = rawChildren + garbage
            val iterator = withGarbage.copyToSource()
            val parseFirst =iterator.readAsn1Element()
            val childIterator = seq.children.iterator()
            parseFirst shouldBe childIterator.next()

            val bytes = iterator.readByteArray()
            bytes shouldBe withGarbage.sliceArray(parseFirst.overallLength.toInt() until withGarbage.size)

            Asn1Element.parseFirst(withGarbage).let { (elem,rest )->
                elem shouldBe seq.children.first()
                rest shouldBe   withGarbage.sliceArray(parseFirst.overallLength.toInt() until withGarbage.size)
            }

            val byteIterator = bytes.copyToSource()
            repeat(9) { byteIterator.readAsn1Element() shouldBe childIterator.next() }


            shouldThrow<Asn1Exception> { Asn1Element.parseAll(withGarbage) shouldBe seq.children }

            shouldThrow<Asn1Exception> { Asn1Element.parse(withGarbage) }
            shouldThrow<Asn1Exception> { Asn1Element.parse(withGarbage) }
        }
    }
})