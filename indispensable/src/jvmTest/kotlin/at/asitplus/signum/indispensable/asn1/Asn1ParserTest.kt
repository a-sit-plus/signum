package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.io.wrapInUnsafeSource
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.Buffer
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
            var (parseFirst, bytes) = Asn1Element.parseFirst(rawChildren)
            val childIterator = seq.children.iterator()
            parseFirst shouldBe childIterator.next()

            bytes shouldBe rawChildren.sliceArray(parseFirst.overallLength.toInt() until rawChildren.size)
            Asn1Element.parseFirst(rawChildren).let { (elem,rest )->
                elem shouldBe seq.children.first()
                rest shouldBe  rawChildren.sliceArray(parseFirst.overallLength.toInt() until rawChildren.size)
            }
            repeat(9) {
                val (a,b) = Asn1Element.parseFirst(bytes)
                a shouldBe childIterator.next()
                bytes = b
            }
            Asn1Element.parseAll(rawChildren) shouldBe seq.children

            shouldThrow<Asn1Exception> { Asn1Element.parse(rawChildren) }
            shouldThrow<Asn1Exception> { Asn1Element.parse(rawChildren) }
        }

        "with Garbage" {
            val garbage = Random.nextBytes(32)
            val withGarbage = rawChildren + garbage

            val childIterator = seq.children.iterator()
            var bytes: ByteArray = withGarbage
            repeat(10) {
                val (child, rest) = Asn1Element.parseFirst(bytes)
                child shouldBe childIterator.next()
                bytes = rest
            }
            bytes shouldBe garbage
            
            shouldThrow<Asn1Exception> { Asn1Element.parseAll(withGarbage) }
            shouldThrow<Asn1Exception> { Asn1Element.parse(withGarbage) }
        }
    }
})