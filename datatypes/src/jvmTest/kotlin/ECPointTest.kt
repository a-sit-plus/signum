import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.ECPoint
import com.ionspin.kotlin.bignum.integer.Sign
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class ECPointTest : FreeSpec({
    "Equals & hashCode" {
        val p1 = ECCurve.SECP_256_R_1.generator
        p1 shouldBe p1
        p1.hashCode() shouldBe p1.hashCode()

        val p11 = Json.decodeFromString<ECPoint>(Json.encodeToString(p1))
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
    }
})
