import at.asitplus.crypto.datatypes.asn1.Asn1Time
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.datetime.toKotlinInstant
import java.time.Instant
import java.util.*

class Asn1TimeTest : FreeSpec ({
    val now = Date.from(Instant.now())
    val then = Date.from(Instant.now().plusSeconds(500L))
    val later = Date.from(Instant.now().plusSeconds(824046715L))
    val asn1Time = Asn1Time(now.toInstant().toKotlinInstant())
    val asn1Time1 = Asn1Time(then.toInstant().toKotlinInstant())
    val asn1Time2 = Asn1Time(then.toInstant().toKotlinInstant(), Asn1Time.Format.UTC)
    val asn1Time3 = Asn1Time(later.toInstant().toKotlinInstant(), Asn1Time.Format.GENERALIZED)

    "Asn1Time test equals and hasCode" {
        asn1Time shouldBe asn1Time
        asn1Time.hashCode() shouldBe asn1Time.hashCode()
        asn1Time1 shouldBe asn1Time1
        asn1Time1.hashCode() shouldBe asn1Time1.hashCode()
        asn1Time2 shouldBe asn1Time2
        asn1Time2.hashCode() shouldBe asn1Time2.hashCode()
        asn1Time3 shouldBe asn1Time3
        asn1Time3.hashCode() shouldBe asn1Time3.hashCode()

        asn1Time1 shouldBe asn1Time2
        asn1Time1.hashCode() shouldBe asn1Time2.hashCode()

        asn1Time shouldNotBe asn1Time1
        asn1Time.hashCode() shouldNotBe asn1Time1.hashCode()
        asn1Time shouldNotBe asn1Time3
        asn1Time.hashCode() shouldNotBe asn1Time3.hashCode()
        asn1Time2 shouldNotBe asn1Time3
        asn1Time2.hashCode() shouldNotBe asn1Time3.hashCode()
    }

})