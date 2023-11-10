import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.asn1.Asn1Element
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.parse
import at.asitplus.crypto.datatypes.fromJcaKey
import at.asitplus.crypto.datatypes.getPublicKey
import at.asitplus.crypto.datatypes.io.Base64Strict
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERBitString
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class PublicKeyTest : FreeSpec({
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
            ) { pubKey ->

                val own: CryptoPublicKey = CryptoPublicKey.Ec.fromJcaKey(pubKey).getOrThrow() as CryptoPublicKey.Ec
                own.shouldNotBeNull()

                val pubKey2: CryptoPublicKey = CryptoPublicKey.Ec.fromJcaKey(pubKey).getOrThrow()
                val iosDerived: CryptoPublicKey = CryptoPublicKey.fromIosEncoded(own.iosEncoded)
                val keyIdDerived: CryptoPublicKey = CryptoPublicKey.fromKeyId(own.keyId)

                pubKey2.hashCode() shouldBe own.hashCode()
                pubKey2 shouldBe own
                iosDerived.hashCode() shouldBe own.hashCode()
                iosDerived shouldBe own
                keyIdDerived.hashCode() shouldBe own.hashCode()
                keyIdDerived shouldBe own

                println(Json.encodeToString(own))
                println(own.iosEncoded.encodeToString(Base16()))
                println(own.encodeToDer().encodeToString(Base16()))
                println(own.keyId)
                own.encodeToDer() shouldBe pubKey.encoded

                own.getPublicKey().encoded shouldBe pubKey.encoded
                CryptoPublicKey.decodeFromTlv(Asn1Element.parse(own.encodeToDer()) as Asn1Sequence) shouldBe own


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
            ) { pubKey ->

                val own: CryptoPublicKey.Rsa = CryptoPublicKey.fromJcaKey(pubKey).getOrThrow() as CryptoPublicKey.Rsa
                own.shouldNotBeNull()
                val pubKey2: CryptoPublicKey.Rsa = CryptoPublicKey.Rsa(
                        ByteArray((0..10).random()) { 0 } + pubKey.modulus.toByteArray(),
                        pubKey.publicExponent.toInt()
                    )
                val iosDerived: CryptoPublicKey = CryptoPublicKey.fromIosEncoded(own.iosEncoded)
                val keyIdDerived: CryptoPublicKey = CryptoPublicKey.fromKeyId(own.keyId)

                // Correctly drops leading zeros
                pubKey2.n shouldBe own.n
                pubKey2.e shouldBe own.e

                pubKey2.hashCode() shouldBe own.hashCode()
                pubKey2 shouldBe own
                iosDerived.hashCode() shouldBe own.hashCode()
                iosDerived shouldBe own
                keyIdDerived.hashCode() shouldBe own.hashCode()
                keyIdDerived shouldBe own

                println(Json.encodeToString(own))
                println(own.iosEncoded.encodeToString(Base16()))
                println(own.keyId)
                val keyBytes = ((ASN1InputStream(pubKey.encoded).readObject()
                    .toASN1Primitive() as ASN1Sequence).elementAt(1) as DERBitString).bytes
                own.iosEncoded shouldBe keyBytes //PKCS#1
                own.encodeToDer() shouldBe pubKey.encoded //PKCS#8
                CryptoPublicKey.decodeFromTlv(Asn1Element.parse(own.encodeToDer()) as Asn1Sequence) shouldBe own
                own.getPublicKey().encoded shouldBe pubKey.encoded
            }
        }

    }
})
