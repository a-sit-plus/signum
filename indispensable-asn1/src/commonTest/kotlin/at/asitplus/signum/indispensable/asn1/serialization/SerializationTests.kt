@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

class SerializationTests :FreeSpec( {
    "Manual" {

      val foo = Foo("ABC", 1337, false, Foo.Bar.A,'f')
      val bytes=  Asn1.Serializer().encodeToByteArray(foo)
       println( bytes.toHexString(HexFormat.UpperCase ))

        Asn1.Serializer().decodeFromByteArray<Foo>(bytes) shouldBe foo

    }
})

@Serializable
data class Foo (val a: String, val b: Int, val c: Boolean, val d: Bar, val e: Char){

    @Serializable
    enum class Bar {
        A, B, C
    }
}