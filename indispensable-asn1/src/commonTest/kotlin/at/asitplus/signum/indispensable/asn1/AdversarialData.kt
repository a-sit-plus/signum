package io.kotest.provided.at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.testSuite
import io.kotest.assertions.throwables.shouldThrow
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val AdversarialData by testSuite {
    "Overlong length" - {
        "OCTET STRING" {
            val nineBytesLength =
                "04898000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString(nineBytesLength) }
            val moreThanLongMaxValue =
                "04888000000000000000"
            shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString(moreThanLongMaxValue) }
            val moreThanIntMaxValue =
                "048480000000"
            shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString(moreThanIntMaxValue) }
        }
        "SEQUENCE" {
            val nineBytesLength =
                "30 89 80 00 00 00 00 00 00 00 00"
            shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString(nineBytesLength) }
            val mismatch1 =
                "30887fffffffffffffff04887fffffffffffffff41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141"
            shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString(mismatch1) }
            val mismatch2 =
                "30887fffffffffffff7f30013081804141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141"
            shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString(mismatch2) }
        }
    }
}