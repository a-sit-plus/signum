package at.asitplus.signum.indispensable.asn1.serialization

import io.kotest.core.spec.style.FreeSpec
import kotlinx.serialization.Serializable
import kotlin.random.Random


@OptIn(ExperimentalStdlibApi::class)
class SerializationTest : FreeSpec({

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


        println(
            encodeToDer(
                TypesUmbrella(
                    str = "foo",
                    i = 2,
                    nullable = null,
                    list = listOf("Foo", "Bar", "Baz"),
                    map = mapOf(3 to false),
                    inner = Simple("simpleton"),
                    innersList = listOf(SimpleOctet("one"), SimpleOctet("three")),
                    byteString = Random.nextBytes(1336),
                    byteArray = Random.nextBytes(1337),
                    innerImpl = SimpleLong(-333L),
                    enum = Baz.BAR
                )
            ).toHexString()
        )

        val string = "Foo"
        println(encodeToDer(string).toHexString())


        val str = decodeFromDer<String>(encodeToDer(string))

        println(encodeToDer(SimpleLong(666L)).toHexString())
        println(encodeToDer(3.141516).toHexString())
        println(encodeToDer(Simple("a")).toHexString())
        println(encodeToDer(NumberTypesUmbrella(1, 2, 3.0f, 4.0, true, 'd')).toHexString())

    }

})


@Serializable
@Asn1ImplicitlyTagged(7353uL)
data class SimpleLong(val a: Long)

@Serializable
@Asn1ExplicitlyTagged(1337998uL)
data class Simple(val a: String)

@Serializable
@Asn1OctetString
data class SimpleOctet(val a: String)

@Asn1ExplicitlyTagged(99uL)
@Serializable
enum class Baz {
    FOO,
    BAR //no custom serializer supported
}

@Serializable
data class TypesUmbrella(

    @Asn1OctetString
    val inner: Simple,
    @Asn1ImplicitlyTagged(333uL)
    val str: String,
    @Asn1OctetString
    val i: Int,
    @Asn1EncodeNull
    val nullable: Double?,
    val list: List<String>,
    val map: Map<Int, Boolean>,

    val innersList: List<SimpleOctet>,
    val byteString: ByteArray,
    val byteArray: ByteArray,
    val innerImpl: SimpleLong,
    @Asn1ImplicitlyTagged(33uL)
    val enum: Baz
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
        result = 31 * result + i
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
