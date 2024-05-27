import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.ECPoint
import at.asitplus.crypto.ecmath.plus
import at.asitplus.crypto.ecmath.times
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class ECPointTest : FreeSpec({
    "Equals & hashCode" {
        val p1 = ECCurve.SECP_256_R_1.generator
        p1 shouldBe p1
        p1.hashCode() shouldBe p1.hashCode()

        val p11 = Json.decodeFromString<ECPoint.Normalized>(Json.encodeToString(p1))
        p1 shouldBe p11
        p1.hashCode() shouldBe p11.hashCode()

        val p2 = ECCurve.SECP_521_R_1.generator
        p2 shouldBe p2
        p2.hashCode() shouldBe p2.hashCode()

        p1 shouldNotBe p2
        p1.hashCode() shouldNotBe p2.hashCode()

        val p3 = ECPoint.fromCompressed(ECCurve.SECP_384_R_1, byteArrayOf(0x0a), Sign.POSITIVE)
        p3 shouldBe p3
        p3.hashCode() shouldBe p3.hashCode()
        p3 shouldNotBe p1
        p3.hashCode() shouldNotBe p1.hashCode()

        val p4 = ECPoint.fromCompressed(ECCurve.SECP_384_R_1, byteArrayOf(0x0a), Sign.NEGATIVE)
        p4 shouldBe p4
        p4.hashCode() shouldBe p4.hashCode()
        p4 shouldNotBe p3
        p4.hashCode() shouldNotBe p3.hashCode()

        p3 shouldNotBe ECCurve.SECP_384_R_1.generator
        p3.hashCode() shouldNotBe ECCurve.SECP_384_R_1.generator.hashCode()

        p3 shouldNotBe ECCurve.SECP_384_R_1.IDENTITY
        p3.hashCode() shouldNotBe ECCurve.SECP_384_R_1.IDENTITY.hashCode()
    }
    "Illegal points are rejected" - {
        withData(ECCurve.entries) { curve ->

            val g = curve.generator
            shouldNotThrowAny { ECPoint.fromXY(curve, g.x, g.y) }
            shouldNotThrowAny { ECPoint.fromXY(curve, g.x.residue, g.y.residue) }
            shouldNotThrowAny { ECPoint.fromXY(curve, g.x, -g.y) }
            shouldNotThrowAny { ECPoint.fromXY(curve, g.x.residue, -(g.y.residue)) }
            shouldNotThrowAny { ECPoint.fromXY(curve, g.x.residue, (-g.y).residue) }

            fun wrongMod(v: ModularBigInteger) =
                ModularBigInteger.creatorForModulo(v.modulus+1).fromBigInteger(v.residue)

            shouldThrow<IllegalArgumentException> { ECPoint.fromXY(curve, wrongMod(g.x), g.y) }
            shouldThrow<IllegalArgumentException> { ECPoint.fromXY(curve, g.x, wrongMod(g.y)) }
            shouldThrow<IllegalArgumentException> { ECPoint.fromXY(curve, wrongMod(g.x), wrongMod(g.y)) }

            shouldThrow<IllegalArgumentException> { ECPoint.fromXY(curve, g.x+1, g.y) }
            shouldThrow<IllegalArgumentException> { ECPoint.fromXY(curve, g.x, g.y+1) }
            shouldThrow<IllegalArgumentException> { ECPoint.fromXY(curve, g.x.residue+1, g.y.residue) }

            shouldNotThrowAny { ECPoint.fromUncompressed(curve, g.xBytes, g.yBytes) }
            shouldThrow<IllegalArgumentException> { ECPoint.fromUncompressed(curve, g.xBytes, byteArrayOf(0)) }
        }
    }
})
