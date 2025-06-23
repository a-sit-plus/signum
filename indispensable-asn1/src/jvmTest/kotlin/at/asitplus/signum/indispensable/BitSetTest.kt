package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.memDump
import at.asitplus.signum.indispensable.asn1.toBitSet
import at.asitplus.signum.indispensable.asn1.toBitString
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.booleanArray
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import java.util.*
import at.asitplus.signum.indispensable.asn1.BitSet as KmpBitSet

class BitSetTest : FreeSpec({

    //outer container required for checkall
    "Custom BitSet Implementation" - {
        "manual tests" {
            KmpBitSet.fromBitString("011011100101110111").toBitString() shouldBe "011011100101110111"

            val kmm = KmpBitSet(0)
            val jvm = BitSet(0)

            2.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.toBitString() shouldBe "001"
            kmm.toBitString() shouldBe "001"
            KmpBitSet.fromBitString(kmm.toBitString()) shouldBe kmm

            8.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.toBitString() shouldBe "001000001"
            kmm.toBitString() shouldBe "001000001"
            KmpBitSet.fromBitString(kmm.toBitString()) shouldBe kmm


            2.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toBitString() shouldBe "000000001"
            kmm.toBitString() shouldBe "000000001"
            KmpBitSet.fromBitString(kmm.toBitString()) shouldBe kmm

            10.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toBitString() shouldBe "000000001"
            kmm.toBitString() shouldBe "000000001"
            KmpBitSet.fromBitString(kmm.toBitString()) shouldBe kmm


            8.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toBitString() shouldBe ""
            kmm.toBitString() shouldBe ""
            KmpBitSet.fromBitString(kmm.toBitString()) shouldBe kmm


            val bits = BitSet()
            bits[2] = true; bits.memDump() shouldBe "00000100"
            bits[1] = true; bits.memDump() shouldBe "00000110"
            bits[0] = true; bits.memDump() shouldBe "00000111"
            bits[8] = true; bits.memDump() shouldBe "00000111 00000001"
        }

        "memDump manual tests" {
            byteArrayOf(4).memDump() shouldBe "00000100"
            byteArrayOf(7).memDump() shouldBe "00000111"
            byteArrayOf(17, 31).memDump() shouldBe "00010001 00011111"

            val kmm = KmpBitSet(0)
            val jvm = BitSet(0)

            2.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.memDump() shouldBe "00000100"
            kmm.memDump() shouldBe "00000100"

            8.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.memDump() shouldBe "00000100 00000001"
            kmm.memDump() shouldBe "00000100 00000001"


            2.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.memDump() shouldBe "00000000 00000001"
            kmm.memDump() shouldBe "00000000 00000001"

            10.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.memDump() shouldBe "00000000 00000001"
            kmm.memDump() shouldBe "00000000 00000001"


            8.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.memDump() shouldBe ""
            kmm.memDump() shouldBe ""
        }

        checkAll(
            iterations = 32,
            Arb.booleanArray(
                Arb.int(1..128),
                Arb.boolean()
            )
        ) { input ->
            withData(
                input.size,
                input.size / 2,
                input.size / 3,
                input.size / 4,
                input.size / 8,
                input.size / 10,
                1,
                0,
                input.size * 2,
                input.size * 4
            ) { size: Int ->
                val jvm = BitSet(size).also {
                    input.indices.shuffled().forEach { i -> it.set(i, input[i]) }
                }
                val kmm = withClue("size: $size") {
                    KmpBitSet(size.toLong()).also {
                        input.indices.shuffled().forEach { i -> it[i.toLong()] = input[i] }
                    }
                }

                withClue("\nKMM: ${kmm.toBitString()}\nJVM: ${jvm.toBitString()}") {
                    kmm.length() shouldBe jvm.length()
                }

                input.forEachIndexed { i, b ->
                    withClue("jvm[$i]") { jvm[i] shouldBe b }
                    withClue("kmm[$i]") { kmm[i.toLong()] shouldBe b }
                }

                withClue("first bit set") { kmm.nextSetBit(0).toInt() shouldBe jvm.nextSetBit(0) }

                val i = input.size - 1
                withClue(
                    "first bit set in second half\n" +
                            "KMM: ${kmm.toBitString()}\n" +
                            "JVM: ${jvm.toBitString()}"
                ) {
                    kmm.nextSetBit(i.toLong() / 2L).toInt() shouldBe jvm.nextSetBit(i / 2)
                }
                withClue(
                    "first bit set in last three quarters\n" +
                            "KMM: ${kmm.toBitString()}\n" +
                            "JVM: ${jvm.toBitString()}"
                ) {
                    kmm.nextSetBit(i.toLong() / 4L).toInt() shouldBe jvm.nextSetBit(i / 4)
                }
                withClue(
                    "first bit set in last 4/5 of bit set\n" +
                            "KMM: ${kmm.toBitString()}\n" +
                            "JVM: ${jvm.toBitString()}"
                ) {
                    kmm.nextSetBit(4L * i.toLong() / 5L).toInt() shouldBe jvm.nextSetBit(4 * i / 5)
                }
                kmm.toByteArray() shouldBe jvm.toByteArray()


                BitSet.valueOf(kmm.toByteArray()).toByteArray() shouldBe jvm.toByteArray()
                kmm.toByteArray().toBitSet().toByteArray() shouldBe jvm.toByteArray()
                jvm.toByteArray().toBitSet().toByteArray() shouldBe jvm.toByteArray()
                kmm.toByteArray().toBitSet().toByteArray() shouldBe kmm.toByteArray()

                jvm.toByteArray().toBitSet().toByteArray() shouldBe kmm.toByteArray()
                BitSet.valueOf(jvm.toByteArray()).toByteArray() shouldBe kmm.toByteArray()
                BitSet.valueOf(kmm.toByteArray()).toByteArray() shouldBe kmm.toByteArray()
                BitSet.valueOf(jvm.toByteArray()).toByteArray() shouldBe jvm.toByteArray()

            }
        }

        "toString() Tests" - {
            checkAll(
                iterations = 32,
                Arb.booleanArray(
                    Arb.int(1..128),
                    Arb.boolean()
                )
            ) { input ->
                withData(
                    input.size,
                    input.size / 2,
                    input.size / 3,
                    input.size / 4,
                    input.size / 8,
                    input.size / 10,
                    1,
                    0,
                    input.size * 2,
                    input.size * 4
                ) { size ->
                    val jvm = BitSet(size).also {
                        input.indices.shuffled().forEach { i -> it.set(i, input[i]) }
                    }
                    val kmm = withClue("size: $size") {
                        KmpBitSet(size.toLong()).also {
                            input.indices.shuffled().forEach { i -> it[i.toLong()] = input[i] }
                        }
                    }

                    input.forEachIndexed { i, b ->
                        withClue("jvm[$i]") { jvm[i] shouldBe b }
                        withClue("kmm[$i]") { kmm[i.toLong()] shouldBe b }
                    }

                    val truncated = input.dropLastWhile { !it }
                    val monotonicOrderedStr = truncated.chunked(8)
                        .map { byte ->
                            (0..<8).map { kotlin.runCatching { byte[it] }.getOrElse { false } }
                                .joinToString(separator = "") { if (it) "1" else "0" }
                        }.joinToString(separator = "") { it }.dropLastWhile { it == '0' }

                    jvm.toBitString() shouldBe monotonicOrderedStr
                    kmm.toBitString() shouldBe monotonicOrderedStr
                }
            }
        }
    }
})

fun BitSet.toBitString(): String = toByteArray().toBitString()
fun BitSet.memDump(): String = toByteArray().memDump()