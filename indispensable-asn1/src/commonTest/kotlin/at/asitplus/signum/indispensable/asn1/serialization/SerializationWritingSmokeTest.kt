package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1OctetString
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import kotlinx.serialization.Serializable
import kotlin.random.Random

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestWritingSmoke by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Writing" {
        val descriptor = TypesUmbrella.serializer().descriptor
        for (i in 0 until descriptor.elementsCount) {
            val name = descriptor.getElementName(i)
            val annotations = descriptor.getElementAnnotations(i)
            println("Property '$name' (index $i) annotations: $annotations")
        }

        val derEncoded = DER.encodeToDer(
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
        println(DER.encodeToDer(string).toHexString())

        println(DER.encodeToDer(SimpleLong(666L)).toHexString())
        println(DER.encodeToDer(3.141516).toHexString())
        println(DER.encodeToDer(Simple("a")).toHexString())
        println(DER.encodeToDer(NumberTypesUmbrella(1, 2, 3.0f, 4.0, true, 'd')).toHexString())
    }
}

@Serializable
data class SimpleLong(val a: Long)

@Serializable
data class Simple(val a: String)

@Serializable
data class SimpleOctet(val a: String)

@Asn1Tag(
    tagNumber = 99u,
    tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
)
@Serializable
enum class Baz {
    FOO,
    BAR,
}

@Serializable
data class TypesUmbrella(
    val inner: Simple,
    @Asn1Tag(
        tagNumber = 333u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    )
    val str: String,
    val i: UInt,
    val nullable: Double?,
    val list: List<String>,
    val map: Map<Int, Boolean>,
    val innersList: List<SimpleOctet>,
    val byteString: ByteArray,
    val byteArray: ByteArray,
    val innerImpl: SimpleLong,
    @Asn1Tag(
        tagNumber = 66u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    )
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
