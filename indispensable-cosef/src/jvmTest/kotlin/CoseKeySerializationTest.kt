import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.CoseKeyParams
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.indispensable.toJcaPublicKey
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.decodeFromHexString
import kotlinx.serialization.encodeToByteArray
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

private fun CryptoPublicKey.EC.withCompressionPreference(v: Boolean) =
    if (v) CryptoPublicKey.EC.fromCompressed(curve, xBytes, yCompressed)
    else CryptoPublicKey.EC.fromUncompressed(curve, xBytes, yBytes)

class CoseKeySerializationTest : FreeSpec({
    Security.addProvider(BouncyCastleProvider())

    "Deserializing" - {
        "Docaposte" {
            val input = """
      A4                                # map(4)
         20                             # negative(0)
         01                             # unsigned(1)
         01                             # unsigned(1)
         02                             # unsigned(2)
         21                             # negative(1)
         58 20                          # bytes(32)
            E70CCC36827593AC6E8D0A4083C8EF09C0FCDA064B18E2A3D083AA5FB1B3DADB #
         22                             # negative(2)
         58 20                          # bytes(32)
            3A1F97A09D54F18BD906405448E6FE7FAB9963866A9DD69286D09C0EC7C3621F #
            """.trimIndent().split("\n").joinToString("") { it.split("#").first().replace(" ", "") }

            coseCompliantSerializer.decodeFromHexString<CoseKey>(input)
                .shouldNotBeNull()
        }
    }

    "Serializing" - {
        "Manual" - {
            Cbor {
                this.en
            }
            val compressed = coseCompliantSerializer.encodeToByteArray(
                KeyPairGenerator.getInstance("EC").apply {
                    initialize(256)
                }.genKeyPair().public.toCryptoPublicKey().getOrThrow().run {
                    this as CryptoPublicKey.EC
                    this.withCompressionPreference(true)
                }.toCoseKey(CoseAlgorithm.ES256).getOrThrow()
            )
            val coseUncompressed = KeyPairGenerator.getInstance("EC").apply {
                initialize(256)
            }.genKeyPair().public.toCryptoPublicKey().getOrThrow().toCoseKey().getOrThrow()
            val uncompressed = coseUncompressed.serialize()

            uncompressed.size shouldBeGreaterThan compressed.size

            val coseKey = CoseKey.deserialize(compressed).getOrThrow()
            coseKey.toCryptoPublicKey().getOrThrow()
                .shouldBeInstanceOf<CryptoPublicKey.EC>().preferCompressedRepresentation shouldBe true
            CoseKey.deserialize(uncompressed).getOrThrow().toCryptoPublicKey()
                .getOrThrow()
                .shouldBeInstanceOf<CryptoPublicKey.EC>().preferCompressedRepresentation shouldBe false

            "Now with autogenerated foo when encapsulating into an Array" {
                val willWorkRegardless = coseCompliantSerializer.encodeToByteArray(
                    arrayOf(
                        coseKey,
                        coseUncompressed
                    )
                )
                coseCompliantSerializer.decodeFromByteArray<Array<CoseKey>>(
                    willWorkRegardless
                ).apply {
                    first() shouldBe coseKey
                    last() shouldBe coseUncompressed
                }


            }

        }


        "EC" - {
            withData(256, 384, 521) { bits ->
                val keys = List<ECPublicKey>(25600 / bits) {
                    val ecKp = KeyPairGenerator.getInstance("EC", "BC").apply {
                        initialize(bits)
                    }.genKeyPair()
                    ecKp.public as ECPublicKey
                }
                withData(
                    nameFn = {
                        "(x: ${
                            it.w.affineX.toByteArray()
                                .encodeToString(Base64Strict)
                        } y: ${
                            it.w.affineY.toByteArray()
                                .encodeToString(Base64Strict)
                        })"
                    },
                    keys
                ) { pubKey ->

                    withClue("Uncompressed")
                    {
                        val coseKey: CoseKey =
                            pubKey.toCryptoPublicKey().getOrThrow().toCoseKey().getOrThrow()
                        val cose = coseKey.serialize()
                        val decoded = CoseKey.deserialize(cose).getOrThrow()
                        decoded.toCryptoPublicKey().getOrThrow()
                            .shouldBeInstanceOf<CryptoPublicKey.EC>().preferCompressedRepresentation shouldBe false
                        decoded.toCryptoPublicKey().getOrThrow()
                            .toJcaPublicKey()
                            .getOrThrow().encoded.encodeToString(
                                Base64Strict
                            ) shouldBe pubKey.encoded.encodeToString(Base64Strict)
                    }

                    withClue("Compressed")
                    {
                        val coseKey: CoseKey =
                            pubKey.toCryptoPublicKey()
                                .getOrThrow()
                                .run {
                                    this as CryptoPublicKey.EC
                                    this.withCompressionPreference(true)
                                }.toCoseKey()
                                .getOrThrow()

                        coseKey.keyParams.shouldBeInstanceOf<CoseKeyParams.EcYBoolParams>()
                        val cose = coseKey.serialize()
                        val decoded = CoseKey.deserialize(cose).getOrThrow()
                        decoded shouldBe coseKey
                        decoded.toCryptoPublicKey().getOrThrow()
                            .shouldBeInstanceOf<CryptoPublicKey.EC>().preferCompressedRepresentation shouldBe true
                        decoded.toCryptoPublicKey().getOrThrow()
                            .toJcaPublicKey()
                            .getOrThrow().encoded.encodeToString(
                                Base64Strict
                            ) shouldBe pubKey.encoded.encodeToString(Base64Strict)
                    }
                }
            }
        }

        "RSA" - {
            withData(512, 1024, 2048, 3072, 4096) { bits ->
                val keys = List<RSAPublicKey>(13000 / bits) {
                    val rsaKP = KeyPairGenerator.getInstance("RSA").apply {
                        initialize(bits)
                    }.genKeyPair()
                    rsaKP.public as RSAPublicKey
                }
                withData(
                    nameFn = {
                        "(n: ${
                            it.modulus.toByteArray()
                                .encodeToString(Base64Strict)
                        } e: ${it.publicExponent.toInt()})"
                    },
                    keys
                ) { pubKey ->
                    val coseKey: CoseKey =
                        pubKey.toCryptoPublicKey().getOrThrow()
                            .toCoseKey(CoseAlgorithm.RS256)
                            .getOrThrow()
                    val cose = coseKey.serialize()

                    val decoded = CoseKey.deserialize(cose).getOrThrow()
                    decoded shouldBe coseKey
                }
            }
        }
    }
})
