package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.PrivateKey as CryptoPrivateKey
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RSAPadding
import at.asitplus.signum.indispensable.asymmetric.NoRsaEncryptionPadding
import at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding
import at.asitplus.signum.indispensable.asymmetric.Pkcs1RsaEncryptionPadding
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionPadding
import at.asitplus.signum.indispensable.encodeToPEM
import at.asitplus.signum.indispensable.key.RsaPrivateKey
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json

@OptIn(HazardousMaterials::class, SecretExposure::class, ExperimentalStdlibApi::class)
val RsaEncryptionTest  by testSuite {
    "From OpenSSL" - {
        withData(nameFn = { it.toString().let { if (it.length <= 128) it else (it.substring(0, 125)+"..." )} }, testData) {
            it.key as RsaPrivateKey
            RsaEncryptionAlgorithm(it.padding).decryptorFor(it.key).decrypt(it.enc)
                .getOrThrow() shouldBe it.plain
            val newEncrypted =
                RsaEncryptionAlgorithm(it.padding).encryptorFor(it.key.publicKey).encrypt(it.plain)
                    .getOrThrow()

            RsaEncryptionAlgorithm(it.padding).decryptorFor(it.key).decrypt(newEncrypted)
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

        @OptIn(HazardousMaterials::class)
        object PaddingSerializer : KSerializer<RSAPadding> {
            override val descriptor: SerialDescriptor =
                PrimitiveSerialDescriptor("Padding", PrimitiveKind.STRING)

            override fun deserialize(decoder: Decoder) =
                decoder.decodeString().let { decoded ->
                    when (decoded) {
                        "PKCS1" -> Pkcs1RsaEncryptionPadding
                        "NONE" -> NoRsaEncryptionPadding
                        "OAEP_SHA1" -> OaepRsaEncryptionPadding.Sha1
                        "OAEP_SHA256" -> OaepRsaEncryptionPadding.Sha256
                        "OAEP_SHA384" -> OaepRsaEncryptionPadding.Sha384
                        "OAEP_SHA512" -> OaepRsaEncryptionPadding.Sha512
                        else -> throw IllegalArgumentException("Unsupported RSA encryption padding $decoded")
                    }
                }

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
