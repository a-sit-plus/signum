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
        shouldThrow<Asn1StructuralException> { Asn1.Int(0).asExplicitlyTagged() }
        shouldThrow<Asn1StructuralException> { Asn1.Int(0).asStructure() }
        shouldThrow<Asn1StructuralException> { Asn1.Int(0).asSequence() }
        shouldThrow<Asn1StructuralException> { Asn1.Int(0).asPrimitiveOctetString() }
        shouldThrow<Asn1StructuralException> { Asn1.Int(0).asEncapsulatingOctetString() }
        Asn1.Int(0).let { it.asPrimitive() shouldBe it }
    }

    "Set" {
        shouldThrow<Asn1StructuralException> { Asn1.Set { +Asn1.Null() }.asSequence() }
        shouldThrow<Asn1StructuralException> { Asn1.Set { +Asn1.Null() }.asExplicitlyTagged() }
        shouldThrow<Asn1StructuralException> { Asn1.Set { +Asn1.Null() }.asPrimitiveOctetString() }
        shouldThrow<Asn1StructuralException> { Asn1.Set { +Asn1.Null() }.asEncapsulatingOctetString() }

        Asn1.Set { +Asn1.Null() }.let { it.asStructure() shouldBe it }
        Asn1.Set { +Asn1.Null() }.let { it.asSet() shouldBe it }
    }

    "OctetString ENCAPSULATING" {
        shouldThrow<Asn1StructuralException> { Asn1.OctetStringEncapsulating { +Asn1.Null() }.asSet() }
        shouldThrow<Asn1StructuralException> { Asn1.OctetStringEncapsulating { +Asn1.Null() }.asExplicitlyTagged() }
        shouldThrow<Asn1StructuralException> { Asn1.OctetStringEncapsulating { +Asn1.Null() }.asPrimitiveOctetString() }
        shouldThrow<Asn1StructuralException> { Asn1.OctetStringEncapsulating { +Asn1.Null() }.asSequence() }

        Asn1.OctetStringEncapsulating { +Asn1.Null() }.let { it.asEncapsulatingOctetString() shouldBe it }
        Asn1.OctetStringEncapsulating { +Asn1.Null() }.let { it.asStructure() shouldBe it }
    }


    "OctetString PRIMITIVE" {
        shouldThrow<Asn1StructuralException> { Asn1PrimitiveOctetString(byteArrayOf()).asSet() }
        shouldThrow<Asn1StructuralException> { Asn1PrimitiveOctetString(byteArrayOf()).asStructure() }
        shouldThrow<Asn1StructuralException> { Asn1PrimitiveOctetString(byteArrayOf()).asSequence() }
        shouldThrow<Asn1StructuralException> { Asn1PrimitiveOctetString(byteArrayOf()).asExplicitlyTagged() }
        shouldThrow<Asn1StructuralException> { Asn1PrimitiveOctetString(byteArrayOf()).asEncapsulatingOctetString() }
        Asn1PrimitiveOctetString(byteArrayOf()).let { it.asPrimitiveOctetString() shouldBe it }
        Asn1PrimitiveOctetString(byteArrayOf()).let { it.asPrimitive() shouldBe it }
    }


    "Custom Structure" {
        shouldThrow<Asn1StructuralException> { Asn1.ExplicitlyTagged(19u) { +Asn1.Null() }.asSequence() }
        shouldThrow<Asn1StructuralException> { Asn1.ExplicitlyTagged(19u) { +Asn1.Null() }.asSet() }
        shouldThrow<Asn1StructuralException> { Asn1.ExplicitlyTagged(19u) { +Asn1.Null() }.asPrimitiveOctetString() }
        shouldThrow<Asn1StructuralException> { Asn1.ExplicitlyTagged(19u) { +Asn1.Null() }.asEncapsulatingOctetString() }

        Asn1.ExplicitlyTagged(19u) { +Asn1.Null() }.let { it.asStructure() shouldBe it }
        Asn1.ExplicitlyTagged(19u) { +Asn1.Null() }.let { it.asExplicitlyTagged() shouldBe it }
    }


})