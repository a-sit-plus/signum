@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.ServiceLoader
import io.kotest.matchers.types.shouldBeInstanceOf
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.assertions.throwables.shouldThrow

val DefaultValidationTest by matrixSuite {

    "EDIPartyName validates its semantic fields" {
        EDIPartyName("Party").partyName shouldBe "Party"
        EDIPartyName("Party", "Assigner").nameAssigner shouldBe "Assigner"
        shouldThrow<IllegalArgumentException> { EDIPartyName("") }
        shouldThrow<IllegalArgumentException> { EDIPartyName("Party", "") }
    }

    "Unknown OtherName remains in its own family" {
        val other = X509GeneralName.Other(
            X509GeneralName.Other.SemanticValue.Generic(ObjectIdentifier("1.2.3.4"), Asn1.Int(1)),
        )
        val name = OtherName(other)
        name.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
        name.oid shouldBe other.value.oid
    }

    "X400AddressName exposes its uninterpreted source" {
        val name = X400AddressName(Asn1.Sequence { +Asn1.Int(1) })
        name.x400Address.elements shouldBe listOf(Asn1.Int(1))
    }
}
