package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.Asn1OctetString
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.Serializable
import java.security.KeyPairGenerator
import kotlin.random.Random


@OptIn(ExperimentalStdlibApi::class)
class SerializationTest : FreeSpec({

    "String" {
        val str = Asn1String.UTF8("foo")
        val serialized = encodeToDer(str).also { println(it.toHexString()) }

        decodeFromDer<Asn1String>(serialized) shouldBe str
        decodeFromDer<Asn1String.UTF8>(serialized) shouldBe str
        val strd: Asn1String = decodeFromDer<Asn1String.BMP>(serialized)


    }


    "EC-256 Key Generation and Signing" {
        // Generate EC-256 keypair using JCA
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        val ecGenParameterSpec = java.security.spec.ECGenParameterSpec("secp256r1") // P-256 curve
        keyPairGenerator.initialize(ecGenParameterSpec)
        val keyPair = keyPairGenerator.generateKeyPair()

        val privateKey = keyPair.private
        val publicKey = keyPair.public

        val signumPrivateKey = privateKey.toCryptoPrivateKey().getOrThrow()
        val signumPublicKey = publicKey.toCryptoPublicKey().getOrThrow()

        signumPrivateKey.encodeToDer() shouldBe encodeToDer<CryptoPrivateKey>(signumPrivateKey)
        decodeFromDer<CryptoPrivateKey>(signumPrivateKey.encodeToDer()) shouldBe signumPrivateKey

        signumPublicKey.encodeToDer() shouldBe encodeToDer(signumPublicKey)
        decodeFromDer<CryptoPublicKey>(signumPublicKey.encodeToDer()) shouldBe signumPublicKey

        // Generate some random data to sign
        val dataToSign = Random.nextBytes(32) // 32 bytes of random data
        println("Data to sign (hex): ${dataToSign.toHexString()}")

        // Create signature instance
        val signature = java.security.Signature.getInstance("SHA256withECDSA")

        // Sign the data
        signature.initSign(privateKey)
        signature.update(dataToSign)
        val signatureBytes = signature.sign()

        val signumSig = CryptoSignature.decodeFromDer(signatureBytes).shouldBeInstanceOf<CryptoSignature.EC>()
        decodeFromDer<CryptoSignature>(signatureBytes) shouldBe signumSig

    }

    "Annotation Order" {
        val outerOctet = encodeToDer(OuterOctetInnerTag())
        val nothing = encodeToDer(NothingOnClass("foo"))
        val outerTag = encodeToDer(OuterTagInnerOctet())

        println(nothing.toHexString())
        println(outerOctet.toHexString())
        println(outerTag.toHexString())

        decodeFromDer<OuterOctetInnerTag>(outerOctet)
    }


    "Implicit tagging" - {
        val imlNothing = encodeToDer(NothingOnClass("foo")).also { println("imlNothing " + it.toHexString()) }
        val imlClass = encodeToDer(ImplicitOnClass("foo")).also { println("imlClass " + it.toHexString()) }
        val imlProp = encodeToDer(ImplicitOnProperty("foo")).also { println("imlProp " + it.toHexString()) }
        val imlBoth = encodeToDer(ImplicitOnBoth("foo")).also { println("imlBoth " + it.toHexString()) }

        decodeFromDer<NothingOnClass>(imlNothing) shouldBe NothingOnClass("foo")
        decodeFromDer<ImplicitOnClass>(imlClass) shouldBe ImplicitOnClass("foo")
        decodeFromDer<ImplicitOnProperty>(imlProp) shouldBe ImplicitOnProperty("foo")
        decodeFromDer<ImplicitOnBoth>(imlBoth) shouldBe ImplicitOnBoth("foo")

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


        "Nested" {
            val nothingOnClassNested = encodeToDer(NothingOnClassNested(NothingOnClass("foo")))
            val nothingOnClassNestedOnClass = encodeToDer(NothingOnClassNestedOnClass(ImplicitOnClass("foo")))
            val nothingOnClassNestedOnProperty = encodeToDer(NothingOnClassNestedOnProperty(NothingOnClass("foo")))
            val nothingOnClassNestedOnPropertyOverride =
                encodeToDer(NothingOnClassNestedOnPropertyOverride(ImplicitOnClass("foo")))

            nothingOnClassNested.toHexString() shouldBe "300730050c03666f6f"
            nothingOnClassNestedOnClass.toHexString() shouldBe "3009bf8a39050c03666f6f"
            nothingOnClassNestedOnProperty.toHexString() shouldBe "3009bf8a39050c03666f6f"
            nothingOnClassNestedOnPropertyOverride.toHexString() shouldBe "3009bf851a050c03666f6f"

            println(nothingOnClassNestedOnPropertyOverride.toHexString())

            decodeFromDer<NothingOnClassNested>(nothingOnClassNested)
            //those two serialize to the same
            decodeFromDer<NothingOnClassNestedOnClass>(nothingOnClassNestedOnClass)
            decodeFromDer<NothingOnClassNestedOnClass>(nothingOnClassNestedOnProperty)
            decodeFromDer<NothingOnClassNestedOnProperty>(nothingOnClassNestedOnProperty)
            decodeFromDer<NothingOnClassNestedOnProperty>(nothingOnClassNestedOnClass)

            decodeFromDer<NothingOnClassNestedOnPropertyOverride>(nothingOnClassNestedOnPropertyOverride)


            shouldThrow<Asn1TagMismatchException> { decodeFromDer<NothingOnClassNested>(nothingOnClassNestedOnClass) }
            shouldThrow<Asn1TagMismatchException> { decodeFromDer<NothingOnClassNested>(nothingOnClassNestedOnProperty) }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNested>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }

            shouldThrow<Asn1TagMismatchException> { decodeFromDer<NothingOnClassNestedOnClass>(nothingOnClassNested) }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnClass>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }

            shouldThrow<Asn1TagMismatchException> { decodeFromDer<NothingOnClassNestedOnProperty>(nothingOnClassNested) }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnProperty>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }

            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnPropertyOverride>(
                    nothingOnClassNested
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnPropertyOverride>(
                    nothingOnClassNestedOnProperty
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnPropertyOverride>(
                    nothingOnClassNestedOnClass
                )
            }


            shouldThrow<Asn1TagMismatchException> { decodeFromDer<NothingOnClassNestedOnClassWrong>(nothingOnClassNested) }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnClassWrong>(
                    nothingOnClassNestedOnClass
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnClassWrong>(
                    nothingOnClassNestedOnProperty
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnClassWrong>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }

            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnPropertyWrong>(
                    nothingOnClassNested
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnPropertyWrong>(
                    nothingOnClassNestedOnClass
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnPropertyWrong>(
                    nothingOnClassNestedOnProperty
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnPropertyWrong>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }

            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(
                    nothingOnClassNested
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(
                    nothingOnClassNestedOnClass
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(
                    nothingOnClassNestedOnProperty
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }


        }

    }

    "SET semantics" {

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


        //  val str = decodeFromDer<String>(encodeToDer(string))


        // val complex = decodeFromDer<TypesUmbrella>(derEncoded)

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
@Asn1nnotation(
    Layer(Type.IMPLICIT_TAG, 99uL),
)
@Serializable
enum class Baz {
    FOO,
    BAR //no custom serializer supported
}

@Asn1nnotation(
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 66uL),
    Layer(Type.OCTET_STRING),
    Layer(Type.IMPLICIT_TAG, 33uL)
)
@Serializable
data class TypesUmbrella(

    //@Asn1OctetString
    val inner: Simple,
    @Asn1nnotation(
        Layer(Type.IMPLICIT_TAG, 333uL),
    )
    val str: String,
    @Asn1nnotation(
        Layer(Type.OCTET_STRING),
    )
    val i: UInt,
    @Asn1nnotation(encodeNull = true)
    val nullable: Double?,
    val list: List<String>,
    val map: Map<Int, Boolean>,

    @Asn1nnotation(
        Layer(Type.OCTET_STRING),
    )
    val innersList: List<SimpleOctet>,

    val byteString: ByteArray,
    val byteArray: ByteArray,
    val innerImpl: SimpleLong,
    @Asn1nnotation(
        Layer(Type.OCTET_STRING),
        Layer(Type.EXPLICIT_TAG, 1337uL),
        Layer(Type.OCTET_STRING),
        Layer(Type.IMPLICIT_TAG, 99uL),
        Layer(Type.IMPLICIT_TAG, 66uL),
        Layer(Type.IMPLICIT_TAG, 33uL),

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


@Serializable
data class SetSemanticsClass(val a: String, val b: List<String>)

@Serializable
data class SetSemanticsProp(val a: String, val b: List<String>)

@Serializable
data class SequenceSemantics(val a: String, val b: List<String>)

@Serializable
data class NothingOnClass(val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1337uL))
data class ImplicitOnClass(val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 7331uL))
data class ImplicitOnClassWrong(val a: String)

@Serializable
data class ImplicitOnProperty(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1338uL)) val a: String)

@Serializable
data class ImplicitOnPropertyWrong(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 8331uL)) val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1337uL))
data class ImplicitOnBoth(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1338uL)) val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 73331uL))
data class ImplicitOnBothWrong(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 8331uL)) val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 7331uL))
data class ImplicitOnBothWrongClass(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1338uL)) val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1337uL))
data class ImplicitOnBothWrongProperty(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 8331uL)) val a: String)


@Serializable
data class NothingOnClassNested(val a: NothingOnClass)

@Serializable
data class NothingOnClassNestedOnClass(val a: ImplicitOnClass)

@Serializable
data class NothingOnClassNestedOnClassWrong(val a: ImplicitOnClassWrong)

@Serializable
data class NothingOnClassNestedOnProperty(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1337uL)) val a: NothingOnClass)

@Serializable
data class NothingOnClassNestedOnPropertyWrong(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 333uL)) val a: NothingOnClass)


@Serializable
data class NothingOnClassNestedOnPropertyOverride(
    @Asn1nnotation(
        Layer(
            Type.IMPLICIT_TAG,
            666uL
        )
    ) val a: ImplicitOnClass
)

@Serializable
data class NothingOnClassNestedOnPropertyOverrideWrong(
    @Asn1nnotation(
        Layer(
            Type.IMPLICIT_TAG,
            999uL
        )
    ) val a: ImplicitOnClass
)

@Serializable
@Asn1nnotation(
    Layer(Type.IMPLICIT_TAG, 1337uL),
    Layer(Type.OCTET_STRING),
)
class OuterTagInnerOctet


@Serializable
@Asn1nnotation(
    Layer(Type.IMPLICIT_TAG, 1342uL),
    Layer(Type.EXPLICIT_TAG, 1341uL),
    Layer(Type.EXPLICIT_TAG, 1340uL),
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1339uL),
    Layer(Type.IMPLICIT_TAG, 1337uL),
    Layer(Type.IMPLICIT_TAG, 1336uL),
)
class OuterOctetInnerTag