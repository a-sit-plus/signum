import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.asn1.encodeToByteArray
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class CryptoSignatureTest : FreeSpec({

    val values = (Byte.MIN_VALUE..Byte.MAX_VALUE).toMutableSet()
    
    "Equals & hashCode" {
        repeat(
            15
        ) {
            val first: Int = values.random().also { values.remove(it) }
            val second: Int = values.random().also { values.remove(it) }

            val ec1 = CryptoSignature.EC(first.encodeToByteArray(), second.encodeToByteArray())
            val ec2 = CryptoSignature.EC(first.encodeToByteArray(), second.encodeToByteArray())
            val ec3 = CryptoSignature.EC(second.encodeToByteArray(), first.encodeToByteArray())
            val rsa1 = CryptoSignature.RSAorHMAC(first.encodeToByteArray())
            val rsa2 = CryptoSignature.RSAorHMAC(first.encodeToByteArray())
            val rsa3 = CryptoSignature.RSAorHMAC(second.encodeToByteArray())

            ec1 shouldBe ec1
            ec1 shouldBe ec2
            ec1 shouldNotBe ec3
            ec1 shouldNotBe rsa1
            rsa1 shouldBe rsa1
            rsa1 shouldBe rsa2
            rsa1 shouldNotBe rsa3

            ec1.hashCode() shouldBe ec1.hashCode()
            ec1.hashCode() shouldBe ec2.hashCode()
            ec1.hashCode() shouldNotBe ec3.hashCode()
            ec1.hashCode() shouldNotBe rsa1.hashCode()
            rsa1.hashCode() shouldBe rsa1.hashCode()
            rsa1.hashCode() shouldBe rsa2.hashCode()
            rsa1.hashCode() shouldNotBe rsa3.hashCode()
        }
    }
})