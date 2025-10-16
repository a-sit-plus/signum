package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val Asn1IteratorTest by testSuite() {
    "Iteration" {
        val elm = Asn1.Sequence {
            +Asn1.Int(42)
            +Asn1.Utf8String("Hello World")
            +Asn1.Bool(true)
        }
        val it1 = elm.iterator()
        it1.isForward shouldBe true
        it1.isReverse shouldBe false
        it1.hasNext() shouldBe true
        it1.peek() shouldBe Asn1.Int(42)
        shouldThrow<NoSuchElementException> { it1.currentElement }
        it1.next() shouldBe Asn1.Int(42)

        val it2 = elm.iterator()
        it2.currentIndex shouldBe -1
        shouldThrow<NoSuchElementException> { it2.currentElement }
        it2.peek() shouldBe Asn1.Int(42)
        it2.next() shouldBe Asn1.Int(42)
        it2.peek() shouldBe Asn1.Utf8String("Hello World")
        it2.next() shouldBe Asn1.Utf8String("Hello World")
        it2.currentElement shouldBe Asn1.Utf8String("Hello World")

        it1.currentElement shouldBe Asn1.Int(42)
        it1.next() shouldBe Asn1.Utf8String("Hello World")
        it2.next() shouldBe Asn1.Bool(true)
        it2.hasNext() shouldBe false
        it2.peek() shouldBe null
        shouldThrow<NoSuchElementException> { it2.next() }
        it1.hasNext() shouldBe true
        it1.peek() shouldBe Asn1.Bool(true)
        it1.next() shouldBe Asn1.Bool(true)

        val it3 = it1.reversed()
        it3.isForward shouldBe false
        it3.isReverse shouldBe true
        it3.currentElement shouldBe Asn1.Bool(true)
        it3.currentIndex shouldBe 2
        it3.peek() shouldBe Asn1.Utf8String("Hello World")
        it3.next() shouldBe Asn1.Utf8String("Hello World")
        it3.next() shouldBe Asn1.Int(42)
        it3.hasNext() shouldBe false
        it3.peek() shouldBe null
        shouldThrow<NoSuchElementException> { it3.next() }

        val it4 = elm.reverseIterator()
        it4.isForward shouldBe false
        it4.isReverse shouldBe true
        shouldThrow<NoSuchElementException> { it4.currentElement }
        it4.hasNext() shouldBe true
        it4.next() shouldBe Asn1.Bool(true)
    }
}
