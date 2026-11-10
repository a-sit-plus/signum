package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.indispensable.pki.isValid
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.assertions.throwables.shouldThrow

val DefaultValidationTest by matrixSuite {

    "EDIPartyName validates its semantic fields" {
        EDIPartyName("Party").isValid shouldBe true
        EDIPartyName("Party", "Assigner").isValid shouldBe true
        shouldThrow<IllegalArgumentException> { EDIPartyName("") }
        shouldThrow<IllegalArgumentException> { EDIPartyName("Party", "") }
    }

    "OtherName without custom validation " {
        val other = X509GeneralName.Other(
            X509GeneralName.Other.SemanticValue.Generic(ObjectIdentifier("1.2.3.4"), Asn1.Int(1)),
        )
        val name = OtherName(other)
        name.isValid shouldBe null
    }

    "X400AddressName without custom validation " {
        val name = X400AddressName(Asn1.Sequence { +Asn1.Int(1) })
        name.isValid shouldBe null
    }
}
