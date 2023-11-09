import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.cose.CoseAlgorithm
import at.asitplus.crypto.datatypes.cose.CoseKey
import at.asitplus.crypto.datatypes.cose.io.cborSerializer
import at.asitplus.crypto.datatypes.cose.toCoseCurve
import at.asitplus.crypto.datatypes.cose.toCoseKey
import at.asitplus.crypto.datatypes.fromJcaKey
import at.asitplus.crypto.datatypes.io.Base64Strict
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class CoseKeySerializationTest : FreeSpec({

    "Serializing" - {
        "Manual" {
            val cose =
                cborSerializer.encodeToByteArray(
                    arrayOf(
                        CryptoPublicKey.fromJcaKey(
                            KeyPairGenerator.getInstance("EC").apply {
                                initialize(256)
                            }.genKeyPair().public
                        ).getOrThrow().toCoseKey().getOrThrow(),
                        CryptoPublicKey.fromJcaKey(KeyPairGenerator.getInstance("EC").apply {
                            initialize(256)
                        }.genKeyPair().public).getOrThrow().toCoseKey().getOrThrow()
                    )
                )
            println(cose.encodeToString(Base16))
            val decoded = cborSerializer.decodeFromByteArray<Array<CoseKey>>(cose)
            println(decoded)
        }


        "EC" - {
            withData(256, 384, 521) { bits ->
                val keys = List<ECPublicKey>(100) {
                    val ecKp = KeyPairGenerator.getInstance("EC").apply {
                        initialize(bits)
                    }.genKeyPair()
                    ecKp.public as ECPublicKey
                }
                withData(
                    nameFn = {
                        "(x: ${
                            it.w.affineX.toByteArray().encodeToString(Base64Strict)
                        } y: ${it.w.affineY.toByteArray().encodeToString(Base64Strict)})"
                    },
                    keys
                ) {

                    val pubKey: CryptoPublicKey.Ec = CryptoPublicKey.fromJcaKey(it).getOrThrow() as CryptoPublicKey.Ec
                    val coseKey: CoseKey = pubKey.toCoseKey().getOrThrow()
                    coseKey shouldNotBe null
                    val coseKey2: CoseKey = CryptoPublicKey.Ec.fromJcaKey(it).getOrThrow().toCoseKey().getOrThrow()

                    // Test that generation is deterministic
                    coseKey2.hashCode() shouldBe coseKey.hashCode()
                    coseKey2 shouldBe coseKey
                    coseKey2.keyParams.hashCode() shouldBe coseKey.keyParams.hashCode()
                    coseKey2.keyParams shouldBe coseKey.keyParams

                    // Test conversion functions
                    val recreatedKey: CryptoPublicKey = coseKey.toCryptoPublicKey().getOrThrow()
                    recreatedKey.hashCode() shouldBe pubKey.hashCode()
                    recreatedKey shouldBe pubKey

                    // Convenience functions
                    CoseKey.fromCoordinates(pubKey.curve.toCoseCurve(), pubKey.x, pubKey.y).getOrThrow() shouldBe coseKey
                    CoseKey.fromKeyId(pubKey.keyId).getOrThrow() shouldBe coseKey
                    CoseKey.fromIosEncoded(pubKey.iosEncoded).getOrThrow() shouldBe coseKey

                    //Test de-/serialization
                    val cose: ByteArray = coseKey.serialize()
                    println(cose.encodeToString(Base16))
                    val decoded: CoseKey = CoseKey.deserialize(cose).getOrThrow()
                    decoded shouldBe coseKey
                    println(decoded)

                }
            }
        }

        "RSA" - {
            withData(512, 1024, 2048, 3072, 4096) { bits ->
                val keys = List<RSAPublicKey>(100) {
                    val rsaKP = KeyPairGenerator.getInstance("RSA").apply {
                        initialize(bits)
                    }.genKeyPair()
                    rsaKP.public as RSAPublicKey
                }
                withData(
                    nameFn = {
                        "(n: ${
                            it.modulus.toByteArray().encodeToString(Base64Strict)
                        } e: ${it.publicExponent.toInt()})"
                    },
                    keys
                ) {

                    val pubKey: CryptoPublicKey.Rsa = CryptoPublicKey.fromJcaKey(it).getOrThrow() as CryptoPublicKey.Rsa
                    val coseKey: CoseKey = pubKey.toCoseKey().getOrThrow()
                    coseKey shouldNotBe null
                    val coseKey2: CoseKey = CryptoPublicKey.Rsa.fromJcaKey(it).getOrThrow().toCoseKey().getOrThrow()

                    // Test that generation is deterministic
                    coseKey2.hashCode() shouldBe coseKey.hashCode()
                    coseKey2 shouldBe coseKey
                    coseKey2.keyParams.hashCode() shouldBe coseKey.keyParams.hashCode()
                    coseKey2.keyParams shouldBe coseKey.keyParams

                    // Test that conversion does not add or lose data
                    val recreatedKey: CryptoPublicKey = coseKey.toCryptoPublicKey().getOrThrow()
                    recreatedKey.hashCode() shouldBe pubKey.hashCode()
                    recreatedKey shouldBe pubKey

                    // Convenience functions
                    CoseKey.fromKeyId(pubKey.keyId).getOrThrow() shouldBe coseKey
                    CoseKey.fromIosEncoded(pubKey.iosEncoded).getOrThrow() shouldBe coseKey

                    //Test de-/serialization
                    val cose: ByteArray = coseKey.serialize()
                    println(cose.encodeToString(Base16))
                    val decoded: CoseKey = CoseKey.deserialize(cose).getOrThrow()
                    decoded shouldBe coseKey
                    println(decoded)

                }
            }

        }
    }
})