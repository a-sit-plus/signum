package at.asitplus.signum.indispensable.asn1.serialization.api

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import at.asitplus.signum.indispensable.asn1.serialization.*
import at.asitplus.signum.indispensable.pki.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.Serializable
import java.security.KeyPairGenerator
import kotlin.random.Random


//TODO nullable tests
//test with json serializer as well

@OptIn(ExperimentalStdlibApi::class)
class SerializationTest : FreeSpec({

    "Nulls and Noughts" {

        DER.encodeToDer<Nullable?>(null) shouldBe Asn1Null.derEncoded

        val nullable: String? = null
        DER.encodeToDer(nullable) shouldBe byteArrayOf()

        DER.encodeToDer<NullableAnnotated?>(null).toHexString() shouldBe "Asn1Null.derEncoded"

    }

    "Bits and Bytes" - {
        "Bit string" {
            val empty = byteArrayOf()

            val normalEmpty = BitSetNormal(empty)

            DER.decodeFromDer<BitSetNormal>(
                DER.encodeToDer(normalEmpty).also { it.toHexString() shouldBe "3003030100" }) shouldBe normalEmpty

            val normal = BitSetNormal(byteArrayOf(1, 2, 3))

            DER.decodeFromDer<BitSetNormal>(
                DER.encodeToDer(normal).also { it.toHexString() shouldBe "3006030400010203" }) shouldBe normal


            val normalEmptyAnnotated = BitSetNormalAnnotated(empty)
            DER.decodeFromDer<BitSetNormalAnnotated>(
                DER.encodeToDer(normalEmptyAnnotated)
                    .also { it.toHexString() shouldBe "300b0409bf8a3b050403030100" }) shouldBe normalEmptyAnnotated


            val normalEmptyAnnotatedOverride = BitSetNormalAnnotatedOverride(empty)
            DER.decodeFromDer<BitSetNormalAnnotatedOverride>(
                DER.encodeToDer(normalEmptyAnnotatedOverride)
                    .also { it.toHexString() shouldBe "300d040bbf8a3b0704059f8a390100" }) shouldBe normalEmptyAnnotatedOverride


            val valueClassEmpty = BitSetValue(empty)
            val valueClass = BitSetValue(byteArrayOf(1, 2, 3))

            DER.decodeFromDer<BitSetValue>(
                DER.encodeToDer(valueClassEmpty)
                    .also { it.toHexString() shouldBe "030100" }).bytes shouldBe valueClassEmpty.bytes


            DER.decodeFromDer<BitSetValue>(
                DER.encodeToDer(valueClass)
                    .also { it.toHexString() shouldBe "030400010203" }).bytes shouldBe valueClass.bytes


            val valueClassEmptyAnnotated = BitSetValueAnnotated(empty)

            DER.decodeFromDer<BitSetValueAnnotated>(
                DER.encodeToDer(valueClassEmptyAnnotated)
                    .also { it.toHexString() shouldBe "040bbf8a3b07bf8a3903030100" }).bytes shouldBe valueClassEmptyAnnotated.bytes

            val valueClassEmptyAnnotatedOverride = BitSetValueAnnotatedOverride(empty)

            DER.decodeFromDer<BitSetValueAnnotatedOverride>(
                DER.encodeToDer(valueClassEmptyAnnotatedOverride)
                    .also { it.toHexString() shouldBe "0409bf8a3b059f8a390100" }).bytes shouldBe valueClassEmptyAnnotatedOverride.bytes


            val valueClassEmptyAnnotatedAlsoInner = BitSetValueAnnotatedOverrideAlsoInner(empty)

            DER.decodeFromDer<BitSetValueAnnotatedOverrideAlsoInner>(
                DER.encodeToDer(valueClassEmptyAnnotatedAlsoInner)
                    .also { it.toHexString() shouldBe "0409bf8a3b059f8a390100" }).bytes shouldBe valueClassEmptyAnnotatedAlsoInner.bytes

        }

        "octet string" {
            val empty = byteArrayOf()
            DER.decodeFromDer<ByteArray>(
                DER.encodeToDer(empty).also { it.toHexString() shouldBe "0400" }) shouldBe empty
            val threeBytes = byteArrayOf(1, 2, 3)
            DER.decodeFromDer<ByteArray>(
                DER.encodeToDer(threeBytes).also { it.toHexString() shouldBe "0403010203" }) shouldBe threeBytes
        }

    }


    "String" {
        val str = Asn1String.UTF8("foo")
        val serialized = DER.encodeToDer(str).also { println(it.toHexString()) }

        //showcases the string bugginess
        DER.decodeFromDer<Asn1String>(serialized) shouldBe str
        DER.decodeFromDer<Asn1String.UTF8>(serialized) shouldBe str
    }

    "ASN.1 specific extensions to overpower star projection limitations" - {

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

            signumPrivateKey.encodeToDer() shouldBe DER.encodeToDer(signumPrivateKey)
            DER.decodeFromDer<CryptoPrivateKey>(signumPrivateKey.encodeToDer()) shouldBe signumPrivateKey
            DER.decodeFromDer<CryptoPrivateKey.WithPublicKey<*>>(signumPrivateKey.encodeToDer()) shouldBe signumPrivateKey

            DER.decodeFromTlv<CryptoPrivateKey>(signumPrivateKey.encodeToTlv()) shouldBe signumPrivateKey
            DER.decodeFromTlv<CryptoPrivateKey.WithPublicKey<*>>(signumPrivateKey.encodeToTlv()) shouldBe signumPrivateKey

            signumPublicKey.encodeToDer() shouldBe DER.encodeToDer(signumPublicKey)
            DER.decodeFromDer<CryptoPublicKey>(signumPublicKey.encodeToDer()) shouldBe signumPublicKey
            DER.decodeFromTlv<CryptoPublicKey>(signumPublicKey.encodeToTlv()) shouldBe signumPublicKey


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
            DER.decodeFromDer<CryptoSignature>(signatureBytes) shouldBe signumSig
        }

        "CSR" {
            val keyPairGenerator = KeyPairGenerator.getInstance("EC")
            val ecGenParameterSpec = java.security.spec.ECGenParameterSpec("secp256r1") // P-256 curve
            keyPairGenerator.initialize(ecGenParameterSpec)
            val keyPair = keyPairGenerator.generateKeyPair()

            val privateKey = keyPair.private
            val publicKey = keyPair.public

            val signumPublicKey = publicKey.toCryptoPublicKey().getOrThrow()

            val tbsCSR = TbsCertificationRequest(
                subjectName = listOf(
                    RelativeDistinguishedName(AttributeTypeAndValue.CommonName("AT".encodeToAsn1Primitive()))
                ),
                publicKey = signumPublicKey,
                extensions = listOf(
                    X509CertificateExtension(
                        KnownOIDs.basicConstraints,
                        critical = true,
                        value = Asn1EncapsulatingOctetString(listOf(Asn1Null))
                    )
                ),
                attributes = listOf(
                    Pkcs10CertificationRequestAttribute(
                        KnownOIDs.extensions,
                        3.encodeToAsn1Primitive()
                    )
                )
            )
            val encoded = DER.encodeToDer(tbsCSR)
            encoded shouldBe tbsCSR.encodeToDer()
            DER.decodeFromDer<TbsCertificationRequest>(encoded) shouldBe tbsCSR

            // Create signature instance
            val signature = java.security.Signature.getInstance("SHA256withECDSA")

            // Sign the data
            signature.initSign(privateKey)
            signature.update(encoded)
            val signatureBytes = signature.sign()

            val signumSig = CryptoSignature.decodeFromDer(signatureBytes).shouldBeInstanceOf<CryptoSignature.EC>()

            val csr = Pkcs10CertificationRequest(
                tbsCSR, X509SignatureAlgorithm.ES256,
                signumSig
            )

            val csrEncoded = DER.encodeToDer(csr)
            csrEncoded shouldBe csr.encodeToDer()
            DER.decodeFromDer<Pkcs10CertificationRequest>(csrEncoded) shouldBe csr


        }
    }


    "Implicit tagging" - {
        val imlNothing = DER.encodeToDer(NothingOnClass("foo")).also { println("imlNothing " + it.toHexString()) }
        val imlClass = DER.encodeToDer(ImplicitOnClass("foo")).also { println("imlClass " + it.toHexString()) }
        val imlProp = DER.encodeToDer(ImplicitOnProperty("foo")).also { println("imlProp " + it.toHexString()) }
        val imlBoth = DER.encodeToDer(ImplicitOnBoth("foo")).also { println("imlBoth " + it.toHexString()) }

        DER.decodeFromDer<NothingOnClass>(imlNothing) shouldBe NothingOnClass("foo")
        DER.decodeFromDer<ImplicitOnClass>(imlClass) shouldBe ImplicitOnClass("foo")
        DER.decodeFromDer<ImplicitOnProperty>(imlProp) shouldBe ImplicitOnProperty("foo")
        DER.decodeFromDer<ImplicitOnBoth>(imlBoth) shouldBe ImplicitOnBoth("foo")

        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnProperty>(imlClass) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnProperty>(imlBoth) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnProperty>(imlNothing) }

        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnClass>(imlNothing) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnClass>(imlBoth) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnClass>(imlProp) }

        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnBoth>(imlProp) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnBoth>(imlClass) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnBoth>(imlNothing) }

        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<NothingOnClass>(imlClass) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<NothingOnClass>(imlProp) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<NothingOnClass>(imlBoth) }


        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnClassWrong>(imlClass) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnPropertyWrong>(imlProp) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnBothWrong>(imlBoth) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnBothWrongClass>(imlBoth) }
        shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<ImplicitOnBothWrongProperty>(imlBoth) }


        "Nested" {
            val nothingOnClassNested = DER.encodeToDer(NothingOnClassNested(NothingOnClass("foo")))
            val nothingOnClassNestedOnClass = DER.encodeToDer(NothingOnClassNestedOnClass(ImplicitOnClass("foo")))
            val nothingOnClassNestedOnProperty = DER.encodeToDer(NothingOnClassNestedOnProperty(NothingOnClass("foo")))
            val nothingOnClassNestedOnPropertyOverride =
                DER.encodeToDer(NothingOnClassNestedOnPropertyOverride(ImplicitOnClass("foo")))

            nothingOnClassNested.toHexString() shouldBe "300730050c03666f6f"
            nothingOnClassNestedOnClass.toHexString() shouldBe "3009bf8a39050c03666f6f"
            nothingOnClassNestedOnProperty.toHexString() shouldBe "3009bf8a39050c03666f6f"
            nothingOnClassNestedOnPropertyOverride.toHexString() shouldBe "3009bf851a050c03666f6f"

            println(nothingOnClassNestedOnPropertyOverride.toHexString())

            DER.decodeFromDer<NothingOnClassNested>(nothingOnClassNested)
            //those two serialize to the same
            DER.decodeFromDer<NothingOnClassNestedOnClass>(nothingOnClassNestedOnClass)
            DER.decodeFromDer<NothingOnClassNestedOnClass>(nothingOnClassNestedOnProperty)
            DER.decodeFromDer<NothingOnClassNestedOnProperty>(nothingOnClassNestedOnProperty)
            DER.decodeFromDer<NothingOnClassNestedOnProperty>(nothingOnClassNestedOnClass)

            DER.decodeFromDer<NothingOnClassNestedOnPropertyOverride>(nothingOnClassNestedOnPropertyOverride)


            shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<NothingOnClassNested>(nothingOnClassNestedOnClass) }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNested>(
                    nothingOnClassNestedOnProperty
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNested>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }

            shouldThrow<Asn1TagMismatchException> { DER.decodeFromDer<NothingOnClassNestedOnClass>(nothingOnClassNested) }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnClass>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }

            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnProperty>(
                    nothingOnClassNested
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnProperty>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }

            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverride>(
                    nothingOnClassNested
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverride>(
                    nothingOnClassNestedOnProperty
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverride>(
                    nothingOnClassNestedOnClass
                )
            }


            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnClassWrong>(
                    nothingOnClassNested
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnClassWrong>(
                    nothingOnClassNestedOnClass
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnClassWrong>(
                    nothingOnClassNestedOnProperty
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnClassWrong>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }

            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyWrong>(
                    nothingOnClassNested
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyWrong>(
                    nothingOnClassNestedOnClass
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyWrong>(
                    nothingOnClassNestedOnProperty
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyWrong>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }

            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(
                    nothingOnClassNested
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(
                    nothingOnClassNestedOnClass
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(
                    nothingOnClassNestedOnProperty
                )
            }
            shouldThrow<Asn1TagMismatchException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(
                    nothingOnClassNestedOnPropertyOverride
                )
            }


        }

    }

    "SET semantics" {
        val set = setOf("Foo", "Bar", "Baz")
        DER.decodeFromDer<Set<String>>(
            DER.encodeToDer(set).also { it.toHexString() shouldBe "310f0c03466f6f0c034261720c0342617a" }) shouldBe set
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


        //  val str = DER.decodeFromDer<String>(DER.encodeToDer(string))


        // val complex = DER.decodeFromDer<TypesUmbrella>(derEncoded)

        println(DER.encodeToDer(SimpleLong(666L)).toHexString())
        println(DER.encodeToDer(3.141516).toHexString())
        println(DER.encodeToDer(Simple("a")).toHexString())
        println(DER.encodeToDer(NumberTypesUmbrella(1, 2, 3.0f, 4.0, true, 'd')).toHexString())

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


@JvmInline
@Serializable
@Asn1nnotation(asBitString = true)
value class BitSetValue(val bytes: ByteArray)


@JvmInline
@Serializable
@Asn1nnotation(
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1339uL),
    Layer(Type.IMPLICIT_TAG, 1337uL),
    Layer(Type.IMPLICIT_TAG, 1336uL),
    asBitString = true,
)
value class BitSetValueAnnotatedOverride(val bytes: ByteArray)


@JvmInline
@Serializable
@Asn1nnotation(
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1339uL),
    Layer(Type.IMPLICIT_TAG, 1337uL),

    Layer(Type.EXPLICIT_TAG, 1390uL),
    asBitString = true,
)
value class BitSetValueAnnotated(val bytes: ByteArray)


//only the outer stuff counts
@JvmInline
@Serializable
@Asn1nnotation(
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1339uL),
    Layer(Type.IMPLICIT_TAG, 1337uL),
    Layer(Type.IMPLICIT_TAG, 1336uL),
    asBitString = true,
)
value class BitSetValueAnnotatedOverrideAlsoInner(
    @Asn1nnotation(
        Layer(Type.OCTET_STRING),
        Layer(Type.EXPLICIT_TAG, 999uL),
    ) val bytes: ByteArray
)


@Serializable
data class BitSetNormal(
    @Asn1nnotation(asBitString = true) val bytes: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitSetNormal) return false

        if (!bytes.contentEquals(other.bytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }
}


@Serializable
data class BitSetNormalAnnotated(
    @Asn1nnotation(
        Layer(Type.OCTET_STRING),
        Layer(Type.EXPLICIT_TAG, 1339uL),
        Layer(Type.OCTET_STRING),
        asBitString = true
    ) val bytes: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitSetNormalAnnotated) return false

        if (!bytes.contentEquals(other.bytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }
}


@Serializable
data class BitSetNormalAnnotatedOverride(
    @Asn1nnotation(
        Layer(Type.OCTET_STRING),
        Layer(Type.EXPLICIT_TAG, 1339uL),
        Layer(Type.OCTET_STRING),
        Layer(Type.IMPLICIT_TAG, 1337uL),
        asBitString = true
    ) val bytes: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitSetNormalAnnotatedOverride) return false

        if (!bytes.contentEquals(other.bytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }
}


@Serializable
@Asn1nnotation(encodeNull = true)
object Nullable

@Serializable
@Asn1nnotation(
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1339uL),
    encodeNull = true
)
object NullableAnnotated