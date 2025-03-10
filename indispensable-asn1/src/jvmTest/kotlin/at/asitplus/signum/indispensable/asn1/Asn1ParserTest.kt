package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.asn1.encoding.readFullyToAsn1Elements
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlin.random.Random


//this copied over to not change delicate test behaviour, as the original function is not deprecated, with DeprecationLevel.ERROR
private fun Asn1Element.Companion.parseInternal(input: ByteIterator)=parse(mutableListOf<Byte>().also { while (input.hasNext()) it.add(input.nextByte()) }.toByteArray())

class Asn1ParserTest : FreeSpec({

    "Multiple Elements" - {
        val seq = Asn1.Sequence {
            repeat(10) {
                +Asn1OctetString(Random.nextBytes(16))
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
                val (elem, residue) = Asn1Element.parseFirst(byteIterator)
                elem shouldBe childIterator.next()
                byteIterator = residue
            }
            Asn1Element.parseAll(rawChildren) shouldBe seq.children

            shouldThrow<Asn1Exception> { Asn1Element.parse(rawChildren) }
            shouldThrow<Asn1Exception> { Asn1Element.parseInternal(rawChildren.iterator()) }
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


            shouldThrow<Asn1Exception> { run {
                withGarbage.wrapInUnsafeSource().readFullyToAsn1Elements()
            } shouldBe seq.children }

            shouldThrow<Asn1Exception> { Asn1Element.parse(withGarbage) }
            shouldThrow<Asn1Exception> { Asn1Element.parseInternal(withGarbage.iterator()) }
        }
    }
})