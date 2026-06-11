package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import org.bouncycastle.asn1.ASN1InputStream

val CustomTaggedTest by matrixSuite {
    compact("Custom CONSTRUCTED") - {
        property(Arb.int(min = 0, max = Int.MAX_VALUE/*BC limits*/)) test {
            Asn1CustomStructure(
                listOf(),
                it.toULong(),
                TagClass.entries.filterNot { it == TagClass.UNIVERSAL }.random()
            ).also {
                ASN1InputStream(it.derEncoded).readObject().encoded shouldBe it.derEncoded
                Asn1Element.parse(it.derEncoded) shouldBe it
            }
        }
    }

    compact("Custom as Primitive") - {
        property(Arb.int(min = 0, max = Int.MAX_VALUE/*BC limits*/)) test {
            Asn1CustomStructure.asPrimitive(
                listOf(),
                it.toULong(),
                TagClass.entries.filterNot { it == TagClass.UNIVERSAL }.random()
            ).also {
                ASN1InputStream(it.derEncoded).readObject().encoded shouldBe it.derEncoded
                Asn1Element.parse(it.derEncoded).apply {
                    derEncoded shouldBe it.derEncoded //it will parse to a primitive
                    this.shouldBeInstanceOf<Asn1Primitive>()
                }
            }
        }
    }

}
