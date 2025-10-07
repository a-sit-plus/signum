package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RSAPadding
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import at.asitplus.testballoon.checkAllTests
import at.asitplus.testballoon.checkAllSuites
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

@OptIn(HazardousMaterials::class, SecretExposure::class, ExperimentalStdlibApi::class)
val RsaEncryptionTest  by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 90.minutes)) {
    "From OpenSSL" - {
        withData(nameFn = { it.toString() }, testData) {
            it.key as CryptoPrivateKey.RSA
            AsymmetricEncryptionAlgorithm.RSA(it.padding).decryptorFor(it.key).decrypt(it.enc)
                .getOrThrow() shouldBe it.plain
            val newEncrypted =
                AsymmetricEncryptionAlgorithm.RSA(it.padding).encryptorFor(it.key.publicKey).encrypt(it.plain)
                    .getOrThrow()

            AsymmetricEncryptionAlgorithm.RSA(it.padding).decryptorFor(it.key).decrypt(newEncrypted)
                .getOrThrow() shouldBe it.plain
        }
    }
}

@Serializable
class RsaTestData(
    @Serializable(PemSerializer::class) val key: CryptoPrivateKey,
    @Serializable(ByteArrayHexSerializer::class) val plain: ByteArray,
    @Serializable(ByteArrayHexSerializer::class) val enc: ByteArray,
    @Serializable(PaddingSerializer::class) val padding: RSAPadding
) {

    @OptIn(ExperimentalStdlibApi::class)
    override fun toString() = "$padding, Data=${plain.toHexString(HexFormat.Default)}, Encrypted=${enc.toHexString()}"

    companion object {
        object PemSerializer : KSerializer<CryptoPrivateKey> {
            override val descriptor: SerialDescriptor =
                PrimitiveSerialDescriptor("PemEncodedPrivateKey", PrimitiveKind.STRING)

            override fun serialize(
                encoder: Encoder,
                value: CryptoPrivateKey
            ) {
                encoder.encodeString(value.encodeToPEM().getOrThrow())
            }

            override fun deserialize(decoder: Decoder) =
                CryptoPrivateKey.decodeFromPem(decoder.decodeString()).getOrThrow()
        }

        object PaddingSerializer : KSerializer<RSAPadding> {
            override val descriptor: SerialDescriptor =
                PrimitiveSerialDescriptor("Padding", PrimitiveKind.STRING)

            override fun deserialize(decoder: Decoder) =
                decoder.decodeString().let { decoded -> RSAPadding.entries.first { it.toString() == decoded } }

            override fun serialize(
                encoder: Encoder,
                value: RSAPadding
            ) {
                encoder.encodeString(value.toString())
            }
        }

        object ByteArrayHexSerializer : KSerializer<ByteArray> {
            override val descriptor: SerialDescriptor =
                PrimitiveSerialDescriptor("ByteArrayHex", PrimitiveKind.STRING)

            @OptIn(ExperimentalStdlibApi::class)
            override fun deserialize(decoder: Decoder) = decoder.decodeString().hexToByteArray()

            @OptIn(ExperimentalStdlibApi::class)
            override fun serialize(encoder: Encoder, value: ByteArray) {
                encoder.encodeString(value.toHexString())
            }
        }
    }

}


private val testData = Json.decodeFromString<List<RsaTestData>>(rsaInputString)
