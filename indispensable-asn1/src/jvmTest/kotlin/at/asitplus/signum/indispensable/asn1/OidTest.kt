package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.toAsn1VarInt
import at.asitplus.testballoon.checkAll
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid
import io.kotest.property.checkAll as kotestCheckAll

@OptIn(ExperimentalUuidApi::class, ExperimentalStdlibApi::class)
val OidTest by testSuite {
    "OID test" - {

        "manual" {
            val oid = ObjectIdentifier("1.3.311.128.1.4.99991.9311.21.20")
            val oid1 = ObjectIdentifier("1.3.311.128.1.4.99991.9311.21.20")
            val oid2 = ObjectIdentifier("1.3.312.128.1.4.99991.9311.21.20")
            val oid3 = ObjectIdentifier("1.3.132.0.34")

            oid3.bytes shouldBe ObjectIdentifier.decodeFromDer(oid3.encodeToDer()).bytes
            oid.bytes shouldBe ObjectIdentifier.decodeFromDer(oid.encodeToDer()).bytes
            oid1.bytes shouldBe ObjectIdentifier.decodeFromDer(oid1.encodeToDer()).bytes
            oid2.bytes shouldBe ObjectIdentifier.decodeFromDer(oid2.encodeToDer()).bytes

            val encoded = oid.encodeToTlv()
            ObjectIdentifier.decodeFromTlv(encoded) shouldBe oid
            oid shouldBe oid1
            oid shouldNotBe oid2
            oid.hashCode() shouldBe oid1.hashCode()
            oid.hashCode() shouldNotBe oid2.hashCode()
        }

        "Full Root Arc" - {
            withData(nameFn = { "Byte $it" }, List(127) { it }) {
                val oid = ObjectIdentifier.decodeFromAsn1ContentBytes(byteArrayOf(it.toUByte().toByte()))
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
                ObjectIdentifier(oid.toString()).let {
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
                ObjectIdentifier(oid.toString()).let {
                    it shouldBe oid
                    it.encodeToDer() shouldBe fromBC.encoded
                }
            }

        }
        "Failing Root Arc" - {
            withData(nameFn = { "Byte $it" }, List(128) { it + 128 }) {
                shouldThrow<Asn1Exception> {
                    ObjectIdentifier.decodeFromAsn1ContentBytes(byteArrayOf(it.toUByte().toByte()))
                }
            }
            val stringRepesentations = mutableListOf<String>()

            repeat(255 - 40) { stringRepesentations += "0.${it + 40}" }
            repeat(255 - 40) { stringRepesentations += "1.${it + 40}" }
            repeat(255 - 48) { stringRepesentations += "2.${it + 48}" }
            repeat(255 - 3) { stringRepesentations += "${3 + it}.${it % 40}" }

            withData(nameFn = { "String $it" }, stringRepesentations) {
                shouldThrow<Asn1Exception> {
                    ObjectIdentifier(it)
                }
            }

        }

        "Failing negative Bigints" - {
            checkAll(iterations = 50, Arb.negativeInt()) - { negativeInt ->
                checkAll(iterations = 15, Arb.positiveInt(39)) - { second ->
                    checkAll(iterations = 100, Arb.intArray(Arb.int(0..128), Arb.positiveInt(Int.MAX_VALUE))) { rest ->
                        listOf(0, 1, 2).forEach { first ->
                            val withNegative =
                                intArrayOf(negativeInt, *rest).apply { shuffle() }.map { BigInteger(it) }.toTypedArray()
                            shouldThrow<Asn1Exception> {
                                ObjectIdentifier("$first.$second." + withNegative.joinToString("."))
                            }
                        }
                    }
                }
            }
        }
        "Automated UInt Capped" - {
            checkAll(iterations = 15, Arb.positiveInt(39)) - { second ->
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

        "!Benchmarking fast case" - {
            val repetitions = 10

            "Old Optimized" - {
                val oldOptimized = mutableListOf<Duration>()
                repeat(repetitions) {
                    val before = Clock.System.now()
                    checkAll(iterations = 15, Arb.uInt(max = 39u)) - { second ->
                        checkAll(iterations = 5000, Arb.uIntArray(Arb.int(0..256), Arb.uInt(UInt.MAX_VALUE))) {
                            listOf(1u, 2u).forEach { first ->
                                val oid = BigIntObjectIdentifier(first, second, *it.toUIntArray())
                                BigIntObjectIdentifier.decodeFromTlv(oid.encodeToTlv())
                            }
                        }
                    }
                    val duration = Clock.System.now() - before
                    oldOptimized += duration
                    println("Old Optimized: $duration")
                }
                val avgOldOpt = (oldOptimized.sorted().subList(1, oldOptimized.size - 1)
                    .sumOf { it.inWholeMilliseconds } / oldOptimized.size - 2).milliseconds
                println("AvgOldOpt: $avgOldOpt")
            }

            val fixture = testFixture {
                object {
                    var avgOpt = 0.seconds
                }
            }

            "Optimized"  {
                val optimized = mutableListOf<Duration>()
                repeat(repetitions) {
                    val before = Clock.System.now()
                    kotestCheckAll(iterations = 15, Arb.uInt(max = 39u))  { second ->
                        kotestCheckAll(iterations = 5000, Arb.uIntArray(Arb.int(0..256), Arb.uInt(UInt.MAX_VALUE))) {
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

                val avgOpt = (optimized.sorted().subList(1, optimized.size - 1)
                    .sumOf { it.inWholeMilliseconds } / optimized.size - 2).milliseconds
                println("AvgOpt: $avgOpt")
                fixture().avgOpt = avgOpt
            }

            "Simple" {
                val simple = mutableListOf<Duration>()
                repeat(repetitions) {
                    val before = Clock.System.now()
                    kotestCheckAll(iterations = 15, Arb.uInt(max = 39u))  { second ->
                        kotestCheckAll(iterations = 5000, Arb.uIntArray(Arb.int(0..256), Arb.uInt(UInt.MAX_VALUE))) {
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

                val avgSimple = (simple.sorted().subList(1, simple.size - 1)
                    .sumOf { it.inWholeMilliseconds } / simple.size - 2).milliseconds
                println("AvgSimple: $avgSimple")
                fixture().avgOpt shouldBeLessThan avgSimple
            }
        }


        "Benchmarking UUID" - {
            val inputs = List<Uuid>(1000000) { Uuid.random() }

            val optimized = mutableListOf<Duration>()
            val repetitions = 10



            "Optimized" - {
                repeat(repetitions) {
                    val before = Clock.System.now()
                    inputs.forEach { ObjectIdentifier(it) }
                    val duration = Clock.System.now() - before
                    optimized += duration
                    println("Optimized: $duration")
                }
                val avgOpt = (optimized.sorted().subList(1, optimized.size - 1)
                    .sumOf { it.inWholeMilliseconds } / optimized.size - 2).milliseconds
                println("AvgOpt: $avgOpt")


                "Old Bigint-Based" {
                    val oldOptimized = mutableListOf<Duration>()
                    repeat(repetitions) {
                        val before = Clock.System.now()
                        inputs.forEach { BigIntObjectIdentifier(it) }
                        val duration = Clock.System.now() - before
                        oldOptimized += duration
                        println("Old Optimized: $duration")
                    }
                    val avgOldOpt = (oldOptimized.sorted().subList(1, oldOptimized.size - 1)
                        .sumOf { it.inWholeMilliseconds } / oldOptimized.size - 2).milliseconds
                    println("AvgOldOpt: $avgOldOpt")
                    avgOpt shouldBeLessThan avgOldOpt
                }
            }
        }

        "Automated BigInt" - {
            checkAll(iterations = 15, Arb.positiveInt(39)) - { second ->
                checkAll(iterations = 500, Arb.bigInt(1, 358)) {
                    listOf(1, 2).forEach { first ->
                        val third = BigInteger.fromByteArray(it.toByteArray(), Sign.POSITIVE)
                        val oid = ObjectIdentifier("$first.$second.$third")

                        val stringRepresentation =
                            "$first.$second.$third"

                        oid.toString() shouldBe stringRepresentation

                        val second1 = if (second > 1) second - 1 else second + 1

                        val oid1 = ObjectIdentifier("$first.$second1")
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

                val oidString = "2.25.$bigint"
                val oid = ObjectIdentifier(oidString)
                oid.encodeToDer() shouldBe ASN1ObjectIdentifier(oidString).encoded
                oid.nodes.size shouldBe 3
                oid.nodes.first() shouldBe "2"
                oid.nodes[1] shouldBe "25"
                oid.nodes.last() shouldBe bigint.toString()

                oid.toString() shouldBe oidString
            }
        }
    }
}


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

    companion object : Asn1Decodable<Asn1Primitive, OldOIDObjectIdentifier> {

        /**
         * Parses an OBJECT IDENTIFIER contained in [src] to an [ObjectIdentifier]
         * @throws Asn1Exception  all sorts of errors on invalid input
         */
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Primitive): OldOIDObjectIdentifier {
            if (src.contentLength < 1) throw Asn1StructuralException("Empty OIDs are not supported")

            return parse(src.content)

        }

        /**
         * Casts out the evil demons that haunt OID components encoded into [rawValue]
         * @return ObjectIdentifier if decoding succeeded
         * @throws Asn1Exception all sorts of errors on invalid input
         */
        @Throws(Asn1Exception::class)
        fun parse(rawValue: ByteArray): OldOIDObjectIdentifier = runRethrowing {
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
            return OldOIDObjectIdentifier(*collected.toTypedArray())
        }
    }
}


class BigIntObjectIdentifier @Throws(Asn1Exception::class) private constructor(
    bytes: ByteArray?,
    nodes: List<BigInteger>?
) :
    Asn1Encodable<Asn1Primitive> {
    init {
        if ((bytes == null) && (nodes == null)) {
            //we're not even declaring this, since this is an implementation error on our end
            throw IllegalArgumentException("either nodes or bytes required")
        }
        if (bytes?.isEmpty() == true || nodes?.isEmpty() == true)
            throw Asn1Exception("Empty OIDs are not supported")

        bytes?.apply {
            if (first().toUByte() > 127u) throw Asn1Exception("OID top-level arc can only be number 0, 1 or 2")
        }
        nodes?.apply {
            if (size < 2) throw Asn1StructuralException("at least two nodes required!")
            if (first() > 2u) throw Asn1Exception("OID top-level arc can only be number 0, 1 or 2")
            if (first() < 2u) {
                if (get(1) > 39u) throw Asn1Exception("Second segment must be <40")
            } else {
                if (get(1) > 47u) throw Asn1Exception("Second segment must be <48")
            }
            forEach { if (it.isNegative) throw Asn1Exception("Negative Number encountered: $it") }
        }
    }


    /**
     * Efficient, but cursed encoding of OID nodes, see [Microsoft's KB entry on OIDs](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier)
     * for details.
     * Lazily evaluated.
     */
    val bytes: ByteArray by if (bytes != null) lazyOf(bytes) else lazy {
        this.nodes.toOidBytes()
    }

    /**
     * Lazily evaluated list of OID nodes (e.g. `[1, 2, 35, 4654]`)
     */
    val nodes by if (nodes != null) lazyOf(nodes) else lazy {
        val (first, second) =
            if (this.bytes[0] >= 80) {
                BigInteger.fromUByte(2u) to BigInteger.fromUInt(this.bytes[0].toUByte() - 80u)
            } else {
                BigInteger.fromUInt(this.bytes[0].toUByte() / 40u) to BigInteger.fromUInt(this.bytes[0].toUByte() % 40u)
            }
        var index = 1
        val collected = mutableListOf(first, second)
        while (index < this.bytes.size) {
            if (this.bytes[index] >= 0) {
                collected += BigInteger.fromUInt(this.bytes[index].toUInt())
                index++
            } else {
                val currentNode = mutableListOf<Byte>()
                while (this.bytes[index] < 0) {
                    currentNode += this.bytes[index] //+= parsed
                    index++
                }
                currentNode += this.bytes[index]
                index++
                collected += currentNode.toByteArray().decodeAsn1VarBigInt().first
            }
        }
        collected
    }

    /**
     * Creates an OID in the 2.25 subtree that requires no formal registration.
     * E.g. the UUID `550e8400-e29b-41d4-a716-446655440000` results in the OID
     * `2.25.113059749145936325402354257176981405696`
     */
    @OptIn(ExperimentalUuidApi::class)
    constructor(uuid: Uuid) : this(
        bytes = byteArrayOf((2 * 40 + 25).toUByte().toByte(), *uuid.toBigInteger().toAsn1VarInt()),
        nodes = null
    )

    /**
     * @param nodes OID Tree nodes passed in order (e.g. 1u, 2u, 96u, …)
     * @throws Asn1Exception if less than two nodes are supplied, the first node is >2 or the second node is >39
     */
    constructor(vararg nodes: UInt) : this(
        bytes = nodes.toOidBytes(),
        nodes = null
    )

    /**
     * @param nodes OID Tree nodes passed in order (e.g. 1, 2, 96, …)
     * @throws Asn1Exception if less than two nodes are supplied, the first node is >2, the second node is >39 or any node is negative
     */
    constructor(vararg nodes: BigInteger) : this(
        bytes = null,
        nodes = nodes.asList()
    )

    /**
     * @param oid OID string in human-readable format (e.g. "1.2.96" or "1 2 96")
     */
    constructor(oid: String) : this(*(oid.split(if (oid.contains('.')) '.' else ' ')).map { BigInteger.parseString(it) }
        .toTypedArray())


    /**
     * @return human-readable format (e.g. "1.2.96")
     */
    override fun toString(): String {
        return nodes.joinToString(".")
    }

    override fun equals(other: Any?): Boolean {
        if (other == null) return false
        if (other !is at.asitplus.signum.indispensable.asn1.ObjectIdentifier) return false
        return bytes contentEquals other.bytes
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }

    /**
     * @return an OBJECT IDENTIFIER [Asn1Primitive]
     */
    override fun encodeToTlv() = Asn1Primitive(Asn1Element.Tag.OID, bytes)

    companion object : Asn1Decodable<Asn1Primitive, BigIntObjectIdentifier> {

        /**
         * Parses an OBJECT IDENTIFIER contained in [src] to an [ObjectIdentifier]
         * @throws Asn1Exception  all sorts of errors on invalid input
         */
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Primitive): BigIntObjectIdentifier {
            if (src.contentLength < 1) throw Asn1StructuralException("Empty OIDs are not supported")

            return parse(src.content)

        }

        /**
         * Casts out the evil demons that haunt OID components encoded into [rawValue]
         * @return ObjectIdentifier if decoding succeeded
         * @throws Asn1Exception all sorts of errors on invalid input
         */
        @Throws(Asn1Exception::class)
        fun parse(rawValue: ByteArray): BigIntObjectIdentifier = BigIntObjectIdentifier(bytes = rawValue, nodes = null)

        private fun UIntArray.toOidBytes(): ByteArray {
            return slice(2..<size).map { it.toAsn1VarInt() }.fold(
                byteArrayOf((first() * 40u + get(1)).toUByte().toByte())
            ) { acc, bytes -> acc + bytes }
        }

        private fun List<out BigInteger>.toOidBytes(): ByteArray {
            return slice(2..<size).map { it.toAsn1VarInt() }
                .fold(
                    byteArrayOf((first().intValue() * 40 + get(1).intValue()).toUByte().toByte())
                ) { acc, bytes -> acc + bytes }
        }
    }
}
