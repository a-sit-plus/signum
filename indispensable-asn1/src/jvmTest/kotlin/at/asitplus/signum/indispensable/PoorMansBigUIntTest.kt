package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.BigUInt.Companion.decodeAsn1VarBigUint
import com.ionspin.kotlin.bignum.integer.Sign
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bigInt
import io.kotest.property.checkAll
import java.math.BigInteger
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
class PoorMansBigUIntTest : FreeSpec({

    "Manual" - {
        withData("1027", "256", "1", "3", "8", "127", "128", "255", "512", "1024") {
            val javaBigInt = BigInteger(it)
            val ref = javaBigInt.toString()
            val own = BigUInt(ref)
            val ownBytes = own.bytes
            val javaBytes = javaBigInt.toByteArray()
            val bigitBytes = javaBytes.dropWhile { it == 0.toByte() && javaBytes.size > 1 }.map { it.toUByte() }


            own.toString() shouldBe ref
            ownBytes shouldBe bigitBytes

            val varInt = own.toAsn1VarInt()
            val refVarint =
                com.ionspin.kotlin.bignum.integer.BigInteger.parseString(javaBigInt.toString()).toAsn1VarInt()
            varInt shouldBe refVarint
            refVarint.decodeAsn1VarBigInt()
            refVarint.decodeAsn1VarBigUint() shouldBe own

        }
    }


    "Automated" - {
        checkAll(Arb.bigInt(1, 65)) {
            val javaBigInt = it.abs()
            val ref = javaBigInt.toString()
            val own = BigUInt(ref)
            val ownBytes = own.bytes
            val javaBytes = javaBigInt.toByteArray()
            val bigitBytes = javaBytes.dropWhile { it == 0.toByte() && javaBytes.size > 1 }.map { it.toUByte() }

            own.toString() shouldBe ref
            ownBytes shouldBe bigitBytes
            own.toAsn1VarInt() shouldBe com.ionspin.kotlin.bignum.integer.BigInteger.parseString(javaBigInt.toString())
                .toAsn1VarInt()

        }
    }

    "UUIDs" - {
        withData(nameFn = { it.toHexString() }, List<Uuid>(100) { Uuid.random() }) {
            val hex = it.toHexString().uppercase()
            val bigint = com.ionspin.kotlin.bignum.integer.BigInteger.fromByteArray(it.toByteArray(), Sign.POSITIVE)
            val own = BigUInt(it.toByteArray())
        }
    }
})

