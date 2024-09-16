package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.Asn1
import at.asitplus.signum.indispensable.asn1.Asn1PrimitiveOctetString
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class CastingTest : FreeSpec({

    "Primitive" {
        shouldThrow<Asn1StructuralException> { Asn1.Int(0).asSet() }
        shouldThrow<Asn1StructuralException> { Asn1.Int(0).asTagged() }
        shouldThrow<Asn1StructuralException> { Asn1.Int(0).asStructure() }
        shouldThrow<Asn1StructuralException> { Asn1.Int(0).asSequence() }
        shouldThrow<Asn1StructuralException> { Asn1.Int(0).asPrimitiveOctetString() }
        shouldThrow<Asn1StructuralException> { Asn1.Int(0).asEncapsulatingOctetString() }
        Asn1.Int(0).asPrimitive() shouldBe Asn1.Int(0)
    }

    "Set" {
        shouldThrow<Asn1StructuralException> { Asn1.Set { +Asn1.Null() }.asSequence() }
        shouldThrow<Asn1StructuralException> { Asn1.Set { +Asn1.Null() }.asTagged() }
        shouldThrow<Asn1StructuralException> { Asn1.Set { +Asn1.Null() }.asPrimitiveOctetString() }
        shouldThrow<Asn1StructuralException> { Asn1.Set { +Asn1.Null() }.asEncapsulatingOctetString() }

        Asn1.Set { +Asn1.Null() }.asStructure() shouldBe Asn1.Set { +Asn1.Null() }
        Asn1.Set { +Asn1.Null() }.asSet() shouldBe Asn1.Set { +Asn1.Null() }
    }

    "OctetString ENCAPSULATING" {
        shouldThrow<Asn1StructuralException> { Asn1.OctetStringEncapsulating { +Asn1.Null() }.asSet() }
        shouldThrow<Asn1StructuralException> { Asn1.OctetStringEncapsulating { +Asn1.Null() }.asTagged() }
        shouldThrow<Asn1StructuralException> { Asn1.OctetStringEncapsulating { +Asn1.Null() }.asPrimitiveOctetString() }
        shouldThrow<Asn1StructuralException> { Asn1.OctetStringEncapsulating { +Asn1.Null() }.asSequence() }

        Asn1.OctetStringEncapsulating { +Asn1.Null() }
            .asEncapsulatingOctetString() shouldBe Asn1.OctetStringEncapsulating { +Asn1.Null() }
        Asn1.OctetStringEncapsulating { +Asn1.Null() }
            .asStructure() shouldBe Asn1.OctetStringEncapsulating { +Asn1.Null() }
    }


    "OctetString PRIMITIVE" {
        shouldThrow<Asn1StructuralException> { Asn1PrimitiveOctetString(byteArrayOf()).asSet() }
        shouldThrow<Asn1StructuralException> { Asn1PrimitiveOctetString(byteArrayOf()).asStructure() }
        shouldThrow<Asn1StructuralException> { Asn1PrimitiveOctetString(byteArrayOf()).asSequence() }
        shouldThrow<Asn1StructuralException> { Asn1PrimitiveOctetString(byteArrayOf()).asTagged() }
        shouldThrow<Asn1StructuralException> { Asn1PrimitiveOctetString(byteArrayOf()).asEncapsulatingOctetString() }
        Asn1PrimitiveOctetString(byteArrayOf()).asPrimitiveOctetString() shouldBe Asn1PrimitiveOctetString(byteArrayOf())
        Asn1PrimitiveOctetString(byteArrayOf()).asPrimitive() shouldBe Asn1PrimitiveOctetString(byteArrayOf())
    }


    "Custom Structure" {
        shouldThrow<Asn1StructuralException> { Asn1.Tagged(19u) { +Asn1.Null() }.asSequence() }
        shouldThrow<Asn1StructuralException> { Asn1.Tagged(19u) { +Asn1.Null() }.asSet() }
        shouldThrow<Asn1StructuralException> { Asn1.Tagged(19u) { +Asn1.Null() }.asPrimitiveOctetString() }
        shouldThrow<Asn1StructuralException> { Asn1.Tagged(19u) { +Asn1.Null() }.asEncapsulatingOctetString() }

        Asn1.Tagged(19u) { +Asn1.Null() }.asStructure() shouldBe Asn1.Tagged(19u) { +Asn1.Null() }
        Asn1.Tagged(19u) { +Asn1.Null() }.asTagged() shouldBe Asn1.Tagged(19u) { +Asn1.Null() }.asTagged()
    }


})