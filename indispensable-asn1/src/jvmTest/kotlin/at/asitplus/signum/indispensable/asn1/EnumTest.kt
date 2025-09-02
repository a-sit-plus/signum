package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decodeToEnum
import at.asitplus.signum.indispensable.asn1.encoding.decodeToEnumOrdinal
import de.infix.testBalloon.framework.testSuite
import invoke
import minus
import withData
import io.kotest.matchers.shouldBe

enum class TestEnum {
    ONE, TWO, THREE
}

val EnumTest by testSuite {

    "Values beyond valid Kotlin enum ordinals should work" - {
        withData(Long.MIN_VALUE, Long.MAX_VALUE, -1L, Int.MAX_VALUE.toLong()+1L, Int.MIN_VALUE.toLong()-1L) {
            Asn1.Enumerated(it).decodeToEnumOrdinal() shouldBe it
        }
    }

    "encoding should produce correct ordinals" - {
        withData(data = TestEnum.entries) {
            val automagically = Asn1.Enumerated(it)
            automagically shouldBe Asn1.Enumerated(it.ordinal)
            //check correct tag
            automagically.derEncoded shouldBe byteArrayOf(0xa, 1, it.ordinal.toByte())

            automagically.decodeToEnumOrdinal() shouldBe it.ordinal
            val decoded: TestEnum = automagically.decodeToEnum()
            decoded shouldBe it
        }
    }
}