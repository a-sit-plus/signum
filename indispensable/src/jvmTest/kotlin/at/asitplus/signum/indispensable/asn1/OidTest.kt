package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*
import io.kotest.property.checkAll
import kotlinx.datetime.Clock
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class, ExperimentalStdlibApi::class)
class OidTest : FreeSpec({
    "OID test" - {

        "manual" {
            val oid = ObjectIdentifier("1.3.311.128.1.4.99991.9311.21.20")
            val oid1 = ObjectIdentifier("1.3.311.128.1.4.99991.9311.21.20")
            val oid2 = ObjectIdentifier("1.3.312.128.1.4.99991.9311.21.20")

            ObjectIdentifier.decodeFromTlv(oid.encodeToTlv()) shouldBe oid
            oid shouldBe oid1
            oid shouldNotBe oid2
            oid.hashCode() shouldBe oid1.hashCode()
            oid.hashCode() shouldNotBe oid2.hashCode()
        }

        "Full Root Arc" - {
            withData(nameFn = { "Byte $it" }, List(127) { it }) {
                val oid = ObjectIdentifier.parse(byteArrayOf(it.toUByte().toByte()))
                val fromBC = ASN1ObjectIdentifier.fromContents(byteArrayOf(it.toByte()))
                oid.encodeToDer() shouldBe fromBC.encoded
                ObjectIdentifier(oid.toString()).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
                ObjectIdentifier(*(oid.toString().split(".").map { it.toUInt() }.toUIntArray())).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
                ObjectIdentifier(*(oid.toString().split(".").map { BigInteger.parseString(it) }.toTypedArray())).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
            }

            val stringRepesentations = mutableListOf<String>()
            repeat(39) { stringRepesentations += "0.$it" }
            repeat(39) { stringRepesentations += "1.$it" }
            repeat(47) { stringRepesentations += "2.$it" }
            withData(nameFn = { "String $it" }, stringRepesentations) {
                val oid = ObjectIdentifier(it)
                val fromBC = ASN1ObjectIdentifier(it)
                oid.encodeToDer() shouldBe fromBC.encoded
                ObjectIdentifier(oid.toString()).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
                ObjectIdentifier(*(oid.toString().split(".").map { it.toUInt() }.toUIntArray())).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
                ObjectIdentifier(*(oid.toString().split(".").map { BigInteger.parseString(it) }.toTypedArray())).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
            }

        }
        "Failing Root Arc" - {
            withData(nameFn = { "Byte $it" }, List(128) { it + 128 }) {
                shouldThrow<Asn1Exception> {
                    ObjectIdentifier.parse(byteArrayOf(it.toUByte().toByte()))
                }
            }
            val stringRepesentations = mutableListOf<String>()

            repeat(255-40) { stringRepesentations += "0.${it + 40}" }
            repeat(255-40) { stringRepesentations += "1.${it + 40}" }
            repeat(255-48) { stringRepesentations += "2.${it + 48}" }
            repeat(255-3) { stringRepesentations += "${3 + it}.${it % 40}" }

            withData(nameFn = { "String $it" }, stringRepesentations) {
                shouldThrow<Asn1Exception> {
                    ObjectIdentifier(it)
                }
            }

        }

        "Failing negative Bigints" - {
            checkAll(iterations = 50, Arb.negativeInt()) { negativeInt ->
                checkAll(iterations = 15, Arb.positiveInt(39)) { second ->
                    checkAll(iterations = 100, Arb.intArray(Arb.int(0..128), Arb.positiveInt(Int.MAX_VALUE))) { rest ->
                        listOf(0, 1, 2).forEach { first ->
                            val withNegative = intArrayOf(negativeInt, *rest).apply { shuffle() }.map { BigInteger(it) }.toTypedArray()
                            shouldThrow<Asn1Exception> {
                                ObjectIdentifier(BigInteger(first), BigInteger(second), *withNegative)
                            }
                        }
                    }
                }
            }
        }
        "Automated UInt Capped" - {
            checkAll(iterations = 15, Arb.positiveInt(39)) { second ->
                checkAll(iterations = 5000, Arb.intArray(Arb.int(0..128), Arb.positiveInt(Int.MAX_VALUE))) {
                    listOf(0, 1, 2).forEach { first ->
                        val oid = ObjectIdentifier(
                            first.toUInt(),
                            second.toUInt(),
                            *(it.map { it.toUInt() }.toUIntArray())
                        )

                        val stringRepresentation =
                            "$first.$second" + if (it.isEmpty()) "" else ("." + it.joinToString("."))


                        oid.toString() shouldBe stringRepresentation

                        val second1 = if (second > 1) second - 1 else second + 1

                        val oid1 = ObjectIdentifier(
                            first.toUInt(),
                            second1.toUInt(),
                            *(it.map { it.toUInt() }.toUIntArray())
                        )
                        val parsed = ObjectIdentifier.decodeFromTlv(oid.encodeToTlv())
                        val fromBC = ASN1ObjectIdentifier(stringRepresentation)

                        val bcEncoded = fromBC.encoded
                        val ownEncoded = oid.encodeToDer()

                        @OptIn(ExperimentalStdlibApi::class)
                        withClue(
                            "Expected: ${bcEncoded.toHexString(HexFormat.UpperCase)}\nActual: ${
                                ownEncoded.toHexString(
                                    HexFormat.UpperCase
                                )
                            }"
                        ) {
                            bcEncoded shouldBe ownEncoded
                        }
                        parsed shouldBe oid
                        parsed.hashCode() shouldBe oid.hashCode()
                        parsed shouldNotBe oid1
                        parsed.hashCode() shouldNotBe oid1.hashCode()
                    }
                }
            }
        }

        "Benchmarking fast case" - {
            val optimized = mutableListOf<Duration>()
            val repetitions= 10

            "Optimized" - {
                repeat(repetitions) {
                    val before = Clock.System.now()
                    checkAll(iterations = 15, Arb.uInt(max = 39u)) { second ->
                        checkAll(iterations = 5000, Arb.uIntArray(Arb.int(0..256), Arb.uInt(UInt.MAX_VALUE))) {
                            listOf(1u, 2u).forEach { first ->
                                val oid = ObjectIdentifier(first, second, *it.toUIntArray())
                                ObjectIdentifier.decodeFromTlv(oid.encodeToTlv())
                            }
                        }
                    }
                    val duration = Clock.System.now() - before
                    optimized += duration
                    println("Optimized: $duration")
                }
            }

            val avgOpt = (optimized.sorted().subList(1, optimized.size - 1)
                .sumOf { it.inWholeMilliseconds } / optimized.size - 2).milliseconds
            println("AvgOpt: $avgOpt")
            val simple = mutableListOf<Duration>()
            "Simple" - {
                repeat(repetitions) {
                    val before = Clock.System.now()
                    checkAll(iterations = 15, Arb.uInt(max = 39u)) { second ->
                        checkAll(iterations = 5000, Arb.uIntArray(Arb.int(0..256), Arb.uInt(UInt.MAX_VALUE))) {
                            listOf(1u, 2u).forEach { first ->
                                val oid = OldOIDObjectIdentifier(first, second, *it.toUIntArray())
                                OldOIDObjectIdentifier.decodeFromTlv(oid.encodeToTlv())
                            }
                        }
                    }
                    val duration = Clock.System.now() - before
                    simple += duration
                    println("Simple $duration")
                }
            }

            val avgSimple = (simple.sorted().subList(1, simple.size - 1)
                .sumOf { it.inWholeMilliseconds } / simple.size - 2).milliseconds
            println("AvgSimple: $avgSimple")

            avgOpt shouldBeLessThan avgSimple

        }

        "Automated BigInt" - {
            checkAll(iterations = 15, Arb.positiveInt(39)) { second ->
                checkAll(iterations = 500, Arb.bigInt(1, 358)) {
                    listOf(1, 2).forEach { first ->
                        val third = BigInteger.fromByteArray(it.toByteArray(), Sign.POSITIVE)
                        val oid = ObjectIdentifier(
                            BigInteger.fromUInt(first.toUInt()),
                            BigInteger.fromUInt(second.toUInt()),
                            third
                        )

                        val stringRepresentation =
                            "$first.$second.$third"

                        oid.toString() shouldBe stringRepresentation

                        val second1 = if (second > 1) second - 1 else second + 1

                        val oid1 = ObjectIdentifier(
                            BigInteger.fromUInt(first.toUInt()),
                            BigInteger.fromUInt(second1.toUInt()),
                        )
                        val parsed = ObjectIdentifier.decodeFromTlv(oid.encodeToTlv())
                        val fromBC = ASN1ObjectIdentifier(stringRepresentation)

                        val bcEncoded = fromBC.encoded
                        val ownEncoded = oid.encodeToDer()

                        @OptIn(ExperimentalStdlibApi::class)
                        withClue(
                            "Expected: ${bcEncoded.toHexString(HexFormat.UpperCase)}\nActual: ${
                                ownEncoded.toHexString(
                                    HexFormat.UpperCase
                                )
                            }"
                        ) {
                            bcEncoded shouldBe ownEncoded
                        }
                        parsed shouldBe oid
                        parsed.hashCode() shouldBe oid.hashCode()
                        parsed shouldNotBe oid1
                        parsed.hashCode() shouldNotBe oid1.hashCode()
                    }
                }
            }
        }

        "UUID" - {
            "550e8400-e29b-41d4-a716-446655440000" {
                val uuid = Uuid.parse("550e8400-e29b-41d4-a716-446655440000")
                val bigint = uuid.toBigInteger()
                bigint.toString() shouldBe "113059749145936325402354257176981405696"
                Uuid.fromBigintOrNull(bigint) shouldBe uuid
            }

            withData(nameFn = { it.toString() }, List(1000) { Uuid.random() }) {
                val bigint = it.toBigInteger()
                bigint shouldBe BigInteger.parseString(it.toHexString(), 16)
                Uuid.fromBigintOrNull(bigint) shouldBe it

                val oid = ObjectIdentifier(it)
                oid.nodes.size shouldBe 3
                oid.nodes.first() shouldBe  BigInteger(2)
                oid.nodes[1] shouldBe BigInteger(25)
                oid.nodes.last() shouldBe bigint

                oid.toString() shouldBe "2.25.$bigint"
            }
        }
    }
})


// old implementation for benchmarking
private val BIGINT_40 = BigInteger.fromUByte(40u)

class OldOIDObjectIdentifier @Throws(Asn1Exception::class) constructor(@Transient vararg val nodes: BigInteger) :
    Asn1Encodable<Asn1Primitive> {

    init {
        if (nodes.size < 2) throw Asn1StructuralException("at least two nodes required!")
        if ((nodes[0] * BIGINT_40) > UByte.MAX_VALUE.toUInt()) throw Asn1Exception("first node too lage!")
        //TODO more sanity checks

        if (nodes.first() > 2u) throw Asn1Exception("OID must start with either 1 or 2")
        if (nodes[1] > 39u) throw Asn1Exception("Second segment must be <40")
    }

    /**
     * Creates an OID in the 2.25 subtree that requires no formal registration.
     * E.g. the UUID `550e8400-e29b-41d4-a716-446655440000` results in the OID
     * `2.25.113059749145936325402354257176981405696`
     */
    @OptIn(ExperimentalUuidApi::class)
    constructor(uuid: Uuid) : this(
        BigInteger.fromByte(2),
        BigInteger.fromByte(25),
        uuid.toBigInteger()
    )

    /**
     * @param nodes OID Tree nodes passed in order (e.g. 1u, 2u, 96u, …)
     * @throws Asn1Exception if less than two nodes are supplied, the first node is >2 or the second node is >39
     */
    constructor(vararg ints: UInt) : this(*(ints.map { BigInteger.fromUInt(it) }.toTypedArray()))


    /**
     * @param oid in human-readable format (e.g. "1.2.96")
     */
    constructor(oid: String) : this(*(oid.split(if (oid.contains('.')) '.' else ' ')).map { BigInteger.parseString(it) }
        .toTypedArray())

    /**
     * @return human-readable format (e.g. "1.2.96")
     */
    override fun toString() = nodes.joinToString(separator = ".") { it.toString() }

    override fun equals(other: Any?): Boolean {
        if (other == null) return false
        if (other !is OldOIDObjectIdentifier) return false
        return bytes contentEquals other.bytes
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }


    /**
     * Cursed encoding of OID nodes. A sacrifice of pristine numbers requested by past gods of the netherrealm
     */
    val bytes: ByteArray by lazy {
        nodes.slice(2..<nodes.size).map { it.toAsn1VarInt() }.fold(
            byteArrayOf(
                (nodes[0] * BIGINT_40 + nodes[1]).ubyteValue(exactRequired = true).toByte()
            )
        ) { acc, bytes -> acc + bytes }
    }

    /**
     * @return an OBJECT IDENTIFIER [Asn1Primitive]
     */
    override fun encodeToTlv() = Asn1Primitive(Asn1Element.Tag.OID, bytes)

    companion object : Asn1Decodable<Asn1Primitive, ObjectIdentifier> {

        /**
         * Parses an OBJECT IDENTIFIER contained in [src] to an [ObjectIdentifier]
         * @throws Asn1Exception  all sorts of errors on invalid input
         */
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Primitive): ObjectIdentifier {
            if (src.length < 1) throw Asn1StructuralException("Empty OIDs are not supported")

            return parse(src.content)

        }

        /**
         * Casts out the evil demons that haunt OID components encoded into [rawValue]
         * @return ObjectIdentifier if decoding succeeded
         * @throws Asn1Exception all sorts of errors on invalid input
         */
        @Throws(Asn1Exception::class)
        fun parse(rawValue: ByteArray): ObjectIdentifier = runRethrowing {
            if (rawValue.isEmpty()) throw Asn1Exception("Empty OIDs are not supported")
            val (first, second) =
                if (rawValue[0] >= 80) {
                    BigInteger.fromUByte(2u) to BigInteger.fromUInt(rawValue[0].toUByte() - 80u)
                } else {
                    BigInteger.fromUInt(rawValue[0].toUByte() / 40u) to BigInteger.fromUInt(rawValue[0].toUByte() % 40u)
                }

            var index = 1
            val collected = mutableListOf(first, second)
            while (index < rawValue.size) {
                if (rawValue[index] >= 0) {
                    collected += BigInteger.fromUInt(rawValue[index].toUInt())
                    index++
                } else {
                    val currentNode = mutableListOf<Byte>()
                    while (rawValue[index] < 0) {
                        currentNode += rawValue[index] //+= parsed
                        index++
                    }
                    currentNode += rawValue[index]
                    index++
                    collected += currentNode.toByteArray().decodeAsn1VarBigInt().first
                }
            }
            return ObjectIdentifier(*collected.toTypedArray())
        }
    }
}


/**
 * Adds [oid] to the implementing class
 */
interface Identifiable {
    val oid: ObjectIdentifier
}

/**
 * decodes this [Asn1Primitive]'s content into an [ObjectIdentifier]
 *
 * @throws Asn1Exception on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readOid() = runRethrowing {
    decode(Asn1Element.Tag.OID) { OldOIDObjectIdentifier.parse(it) }
}