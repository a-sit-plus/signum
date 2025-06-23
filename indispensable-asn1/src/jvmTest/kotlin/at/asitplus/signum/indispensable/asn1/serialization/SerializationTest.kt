package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1OctetString
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import kotlinx.serialization.Serializable
import kotlin.random.Random


@OptIn(ExperimentalStdlibApi::class)
class SerializationTest : FreeSpec({

    "Implicit tagging" {
        val imlNothing = encodeToDer(NothingOnClass("foo"))
        val imlClass = encodeToDer(ImplicitOnClass("foo"))
        val imlProp = encodeToDer(ImplicitOnProperty("foo"))
        val imlBoth = encodeToDer(ImplicitOnBoth("foo"))

        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnProperty>(imlClass) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnProperty>(imlBoth) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnProperty>(imlNothing) }

        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnClass>(imlNothing) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnClass>(imlBoth) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnClass>(imlProp) }

        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnBoth>(imlProp) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnBoth>(imlClass) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnBoth>(imlNothing) }

        shouldThrow<Asn1TagMismatchException> { decodeFromDer<NothingOnClass>(imlClass) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<NothingOnClass>(imlProp) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<NothingOnClass>(imlBoth) }


        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnClassWrong>(imlClass) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnPropertyWrong>(imlProp) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnBothWrong>(imlBoth) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnBothWrongClass>(imlBoth) }
        shouldThrow<Asn1TagMismatchException> { decodeFromDer<ImplicitOnBothWrongProperty>(imlBoth) }

        decodeFromDer<NothingOnClass>(imlNothing)
        decodeFromDer<ImplicitOnClass>(imlClass)
        decodeFromDer<ImplicitOnProperty>(imlProp)
        decodeFromDer<ImplicitOnBoth>(imlBoth)

    }

    "Writing" {

        // Add this diagnostic code
        val descriptor = TypesUmbrella.serializer().descriptor
        println("--- Descriptor Inspection ---")
        for (i in 0 until descriptor.elementsCount) {
            val name = descriptor.getElementName(i)
            val annotations = descriptor.getElementAnnotations(i)
            println("Property '$name' (index $i) annotations: $annotations")
        }
        println("---------------------------")


        val derEncoded = encodeToDer(
            TypesUmbrella(
                str = "foo",
                i = 2u,
                nullable = null,
                list = listOf("Foo", "Bar", "Baz"),
                map = mapOf(3 to false),
                inner = Simple("simpleton"),
                innersList = listOf(SimpleOctet("one"), SimpleOctet("three")),
                byteString = Random.nextBytes(1336),
                byteArray = Random.nextBytes(1337),
                innerImpl = SimpleLong(-333L),
                enum = Baz.BAR,
                octet = Asn1OctetString("Hello World".encodeToByteArray())
            )
        )
        println(derEncoded.toHexString())

        val string = "Foo"
        println(encodeToDer(string).toHexString())


        val str = decodeFromDer<String>(encodeToDer(string))

        println("DECODED: $str\n")

        val complex = decodeFromDer<TypesUmbrella>(derEncoded)

        println(encodeToDer(SimpleLong(666L)).toHexString())
        println(encodeToDer(3.141516).toHexString())
        println(encodeToDer(Simple("a")).toHexString())
        println(encodeToDer(NumberTypesUmbrella(1, 2, 3.0f, 4.0, true, 'd')).toHexString())

    }

})


@Serializable
//@Asn1ImplicitlyTagged(7353uL)
data class SimpleLong(val a: Long)

@Serializable
//@Asn1ExplicitlyTagged(1337998uL)
data class Simple(val a: String)

@Serializable
//@Asn1OctetString
data class SimpleOctet(val a: String)

//@Asn1ExplicitlyTagged(99uL)
@Asn1ImplicitlyTagged(99uL)
@Serializable
enum class Baz {
    FOO,
    BAR //no custom serializer supported
}

@Serializable
data class TypesUmbrella(

    //@Asn1OctetString
    val inner: Simple,
    // @Asn1ImplicitlyTagged(333uL)
    val str: String,
    //  @Asn1OctetString
    val i: UInt,
    @Asn1EncodeNull
    val nullable: Double?,
    val list: List<String>,
    val map: Map<Int, Boolean>,

    val innersList: List<SimpleOctet>,

    val byteString: ByteArray,
    val byteArray: ByteArray,
    val innerImpl: SimpleLong,
    @Asn1ImplicitlyTagged(33uL)
    val enum: Baz,
    val octet: Asn1OctetString
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as TypesUmbrella

        if (str != other.str) return false
        if (i != other.i) return false
        if (nullable != other.nullable) return false
        if (list != other.list) return false
        if (map != other.map) return false
        if (inner != other.inner) return false
        if (innersList != other.innersList) return false
        if (!byteString.contentEquals(other.byteString)) return false
        if (!byteArray.contentEquals(other.byteArray)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = str.hashCode()
        result = 31 * result + i.toInt()
        result = 31 * result + (nullable?.hashCode() ?: 0)
        result = 31 * result + list.hashCode()
        result = 31 * result + map.hashCode()
        result = 31 * result + inner.hashCode()
        result = 31 * result + innersList.hashCode()
        result = 31 * result + byteString.contentHashCode()
        result = 31 * result + byteArray.contentHashCode()
        return result
    }
}

@Serializable
data class NumberTypesUmbrella(
    val int: Int,
    val long: Long,
    val float: Float,
    val double: Double,
    val boolean: Boolean,
    val char: Char
)

@Serializable
data class NullableByteString(
    val byteString: ByteArray?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as NullableByteString

        if (byteString != null) {
            if (other.byteString == null) return false
            if (!byteString.contentEquals(other.byteString)) return false
        } else if (other.byteString != null) return false

        return true
    }

    override fun hashCode(): Int {
        return byteString?.contentHashCode() ?: 0
    }
}

@Serializable
class NothingOnClass(val a: String)

@Serializable
@Asn1ImplicitlyTagged(1337uL)
class ImplicitOnClass(val a: String)

@Serializable
@Asn1ImplicitlyTagged(3771uL)
class ImplicitOnClassWrong(val a: String)

@Serializable
class ImplicitOnProperty(@Asn1ImplicitlyTagged(1338uL) val a: String)

@Serializable
class ImplicitOnPropertyWrong(@Asn1ImplicitlyTagged(8331uL) val a: String)

@Serializable
@Asn1ImplicitlyTagged(1337uL)
class ImplicitOnBoth(@Asn1ImplicitlyTagged(1338uL) val a: String)

@Serializable
@Asn1ImplicitlyTagged(7331uL)
class ImplicitOnBothWrong(@Asn1ImplicitlyTagged(8331uL) val a: String)

@Serializable
@Asn1ImplicitlyTagged(7331uL)
class ImplicitOnBothWrongClass(@Asn1ImplicitlyTagged(1338uL) val a: String)

@Serializable
@Asn1ImplicitlyTagged(1337uL)
class ImplicitOnBothWrongProperty(@Asn1ImplicitlyTagged(8331uL) val a: String)