package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val CoseEqualsTest by testSuite() {
    "equals with byte array"  {
        checkAll(Arb.byteArray(length = Arb.int(0, 10), content = Arb.byte())) { bytes ->
            val bytesSigned1 = CoseSigned.create(
                protectedHeader = CoseHeader(),
                unprotectedHeader = null,
                payload = bytes,
                signature = CryptoSignature.RSA(bytes),
                payloadSerializer = ByteArraySerializer(),
            )
            val bytesSigned2 = CoseSigned.create(
                protectedHeader = CoseHeader(),
                unprotectedHeader = null,
                payload = bytes,
                signature = CryptoSignature.RSA(bytes),
                payloadSerializer = ByteArraySerializer(),
            )

            bytesSigned1 shouldBe bytesSigned1
            bytesSigned2 shouldBe bytesSigned1
            bytesSigned1.hashCode() shouldBe bytesSigned1.hashCode()
            bytesSigned1.hashCode() shouldBe bytesSigned2.hashCode()

            val reversed = bytes.reversedArray().let { it + it + 1 + 3 + 5 }
            val reversedSigned1 = CoseSigned.create(
                protectedHeader = CoseHeader(),
                unprotectedHeader = null,
                payload = reversed,
                signature = CryptoSignature.RSA(reversed),
                payloadSerializer = ByteArraySerializer(),
            )
            val reversedSigned2 = CoseSigned.create(
                protectedHeader = CoseHeader(),
                unprotectedHeader = null,
                payload = reversed,
                signature = CryptoSignature.RSA(reversed),
                payloadSerializer = ByteArraySerializer(),
            )

            reversedSigned2 shouldBe reversedSigned2
            reversedSigned2 shouldBe reversedSigned1

            reversedSigned1.hashCode() shouldBe reversedSigned1.hashCode()
            reversedSigned1.hashCode() shouldBe reversedSigned2.hashCode()

            bytesSigned1 shouldNotBe reversedSigned1
            bytesSigned1 shouldNotBe reversedSigned2

            bytesSigned1.hashCode() shouldNotBe reversedSigned1.hashCode()
            bytesSigned1.hashCode() shouldNotBe reversedSigned2.hashCode()

            reversedSigned1 shouldNotBe bytesSigned1
            reversedSigned1 shouldNotBe bytesSigned2

            reversedSigned1.hashCode() shouldNotBe bytesSigned1.hashCode()
            reversedSigned1.hashCode() shouldNotBe bytesSigned2.hashCode()
        }
    }

    "equals with data class" {
        checkAll(Arb.byteArray(length = Arb.int(0, 10), content = Arb.byte())) { bytes ->
            val payload = DataClass(content = bytes.encodeToString(Base16Strict))
            val bytesSigned1 = CoseSigned.create(
                protectedHeader = CoseHeader(),
                unprotectedHeader = null,
                payload = payload,
                signature = CryptoSignature.RSA(bytes),
                payloadSerializer = DataClass.serializer(),
            )
            val bytesSigned2 = CoseSigned.create(
                protectedHeader = CoseHeader(),
                unprotectedHeader = null,
                payload = payload,
                signature = CryptoSignature.RSA(bytes),
                payloadSerializer = DataClass.serializer(),
            )

            bytesSigned1 shouldBe bytesSigned1
            bytesSigned2 shouldBe bytesSigned1
            bytesSigned1.hashCode() shouldBe bytesSigned1.hashCode()
            bytesSigned1.hashCode() shouldBe bytesSigned2.hashCode()

            val reversed =
                DataClass(content = bytes.reversedArray().let { it + it + 1 + 3 + 5 }.encodeToString(Base16Strict))
            val reversedSigned1 = CoseSigned.create(
                protectedHeader = CoseHeader(),
                unprotectedHeader = null,
                payload = reversed,
                signature = CryptoSignature.RSA(bytes),
                payloadSerializer = DataClass.serializer(),
            )
            val reversedSigned2 = CoseSigned.create(
                protectedHeader = CoseHeader(),
                unprotectedHeader = null,
                payload = reversed,
                signature = CryptoSignature.RSA(bytes),
                payloadSerializer = DataClass.serializer(),
            )

            reversedSigned2 shouldBe reversedSigned2
            reversedSigned2 shouldBe reversedSigned1

            reversedSigned1.hashCode() shouldBe reversedSigned1.hashCode()
            reversedSigned1.hashCode() shouldBe reversedSigned2.hashCode()

            bytesSigned1 shouldNotBe reversedSigned1
            bytesSigned1 shouldNotBe reversedSigned2

            bytesSigned1.hashCode() shouldNotBe reversedSigned1.hashCode()
            bytesSigned1.hashCode() shouldNotBe reversedSigned2.hashCode()

            reversedSigned1 shouldNotBe bytesSigned1
            reversedSigned1 shouldNotBe bytesSigned2

            reversedSigned1.hashCode() shouldNotBe bytesSigned1.hashCode()
            reversedSigned1.hashCode() shouldNotBe bytesSigned2.hashCode()
        }

    }
}

@Serializable
data class DataClass(val content: String)