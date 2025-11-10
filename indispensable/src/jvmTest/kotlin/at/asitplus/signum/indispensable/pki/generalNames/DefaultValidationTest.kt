package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val DefaultValidationTest by testSuite{
    val bytes = byteArrayOf(-96, 30, 6, 3, 42, 3, 4, -96, 23, 12, 21, 115, 111, 109, 101, 32, 111, 116, 104, 101, 114, 32, 105, 100, 101, 110, 116, 105, 102, 105, 101, 114)

    "EDIPartyName without custom validation " {
        val value = Asn1Element.parse(bytes).asExplicitlyTagged()

        val name = EDIPartyName(value)
        name.isValid shouldBe null

        val validated = name.createValidatedCopy { true }
        validated.isValid shouldBe true
    }

    "OtherName without custom validation " {
        val value = Asn1Element.parse(bytes).asExplicitlyTagged()

        val name = OtherName(value)
        name.isValid shouldBe null

        val validated = name.createValidatedCopy { true }
        validated.isValid shouldBe true
    }

    "X400AddressName without custom validation " {
        val value = Asn1Element.parse(bytes)

        val name = X400AddressName(value)
        name.isValid shouldBe null

        val validated = name.createValidatedCopy { true }
        validated.isValid shouldBe true
    }
}