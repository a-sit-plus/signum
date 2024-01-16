import at.asitplus.crypto.datatypes.asn1.Asn1Time
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.instant
import io.kotest.property.checkAll
import kotlinx.datetime.toKotlinInstant
import java.time.Instant

class Asn1TimeTest : FreeSpec ({

    "Asn1Time test equals and hashCode" {
        checkAll(
            iterations = 150,
            Arb.instant(Instant.MIN, Instant.MAX.minusSeconds(824046715L))
        ) {
            val now = it
            val then = it.plusSeconds(500L)
            val later = it.plusSeconds(824046715L)

            val asn1Time = Asn1Time(now.toKotlinInstant())
            val asn1Time1 = Asn1Time(then.toKotlinInstant())
            val asn1Time2 = Asn1Time(then.toKotlinInstant(), Asn1Time.Format.UTC)
            val asn1Time3 = Asn1Time(later.toKotlinInstant(), Asn1Time.Format.GENERALIZED)

            asn1Time shouldBe asn1Time
            asn1Time.hashCode() shouldBe asn1Time.hashCode()
            asn1Time1 shouldBe asn1Time1
            asn1Time1.hashCode() shouldBe asn1Time1.hashCode()
            asn1Time2 shouldBe asn1Time2
            asn1Time2.hashCode() shouldBe asn1Time2.hashCode()
            asn1Time3 shouldBe asn1Time3
            asn1Time3.hashCode() shouldBe asn1Time3.hashCode()

            if (then.toKotlinInstant() <= kotlinx.datetime.Instant.parse("2050-01-01T00:00:00Z")) {
                asn1Time1 shouldBe asn1Time2
                asn1Time1.hashCode() shouldBe asn1Time2.hashCode()
            } else {
                asn1Time1 shouldNotBe asn1Time2
                asn1Time1.hashCode() shouldNotBe asn1Time2.hashCode()
                asn1Time1 shouldBe Asn1Time(then.toKotlinInstant(), Asn1Time.Format.GENERALIZED)
                asn1Time1.hashCode() shouldBe Asn1Time(then.toKotlinInstant(), Asn1Time.Format.GENERALIZED).hashCode()
            }

            asn1Time shouldNotBe asn1Time1
            asn1Time.hashCode() shouldNotBe asn1Time1.hashCode()
            asn1Time shouldNotBe asn1Time3
            asn1Time.hashCode() shouldNotBe asn1Time3.hashCode()
            asn1Time2 shouldNotBe asn1Time3
            asn1Time2.hashCode() shouldNotBe asn1Time3.hashCode()

        }
    }

})