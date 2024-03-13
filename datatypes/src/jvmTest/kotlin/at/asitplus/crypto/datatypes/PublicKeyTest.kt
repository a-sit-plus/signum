package at.asitplus.crypto.datatypes

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.asn1.Asn1Element
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.parse
import at.asitplus.crypto.datatypes.io.Base64Strict
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class PublicKeyTest : FreeSpec({
    Security.addProvider(BouncyCastleProvider())

    "EC" - {
        withData(256, 384, 521) { bits ->
            val keys = List(25600 / bits) {
                val ecKp = KeyPairGenerator.getInstance("EC", "BC").apply {
                    initialize(bits)
                }.genKeyPair()
                ecKp.public as ECPublicKey
            }
            withData(
                nameFn = {
                    "(x: ${it.w.affineX.toByteArray().encodeToString(Base64Strict)}" +
                            " y: ${it.w.affineY.toByteArray().encodeToString(Base64Strict)})"
                },
                keys
            ) { pubKey ->

                val own = CryptoPublicKey.Ec.fromJcaPublicKey(pubKey).getOrThrow()

                withClue("Basic Conversions") {
                    own.encodeToDer() shouldBe pubKey.encoded
                    CryptoPublicKey.fromDid(own.didEncoded) shouldBe own
                    own.getJcaPublicKey().getOrThrow().encoded shouldBe pubKey.encoded
                    CryptoPublicKey.decodeFromTlv(Asn1Element.parse(own.encodeToDer()) as Asn1Sequence) shouldBe own
                }

                withClue("Compressed Test") {
                    (own as CryptoPublicKey.Ec).useCompressedRepresentation = true
                    val compressedPresentation = own.toAnsiX963Encoded()
                    val fromCompressed = CryptoPublicKey.Ec.fromAnsiX963Bytes(compressedPresentation)

                    // bouncy castle compressed representation is calculated by exposing public coordinate from key and then encode that
                    compressedPresentation shouldBe (pubKey as BCECPublicKey).q.getEncoded(true)
                    fromCompressed shouldBe own
                }
            }
        }

        "Equality tests" {
            val keyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()
            val pubKey1 = CryptoPublicKey.decodeFromDer(keyPair.public.encoded)
            val pubKey2 = CryptoPublicKey.decodeFromDer(keyPair.public.encoded)

            pubKey1.hashCode() shouldBe pubKey2.hashCode()
            pubKey1 shouldBe pubKey2
        }

        "DID Tests" {
            val listOfDidKeys = javaClass.classLoader.getResourceAsStream("did_keys.txt")?.reader()?.readLines()
                ?: throw Exception("Test vectors missing!")
            for (key in listOfDidKeys) {
                kotlin.runCatching { CryptoPublicKey.fromDid(key) }.wrap().getOrThrow()
            }
        }
    }

    "RSA" - {
        withData(512, 1024, 2048, 3072, 4096) { bits ->
            val keys = List(13000 / bits) {
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

                val own = CryptoPublicKey.Rsa(pubKey.modulus.toByteArray(), pubKey.publicExponent.toInt())
                val own1 = CryptoPublicKey.Rsa(
                    ByteArray((0..10).random()) { 0 } + pubKey.modulus.toByteArray(),
                    pubKey.publicExponent.toInt()
                )

                // Correctly drops leading zeros
                own1.n shouldBe own.n
                own1.e shouldBe own.e

                val keyBytes = ((ASN1InputStream(pubKey.encoded).readObject()
                    .toASN1Primitive() as ASN1Sequence).elementAt(1) as DERBitString).bytes
                own.pkcsEncoded shouldBe keyBytes //PKCS#1
                own.encodeToDer() shouldBe pubKey.encoded //PKCS#8
                CryptoPublicKey.decodeFromTlv(Asn1Element.parse(own.encodeToDer()) as Asn1Sequence) shouldBe own
                own.getJcaPublicKey().getOrThrow().encoded shouldBe pubKey.encoded
            }
        }
        "Equality tests" {
            val keyPair = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.genKeyPair()
            val pubKey1 = CryptoPublicKey.decodeFromDer(keyPair.public.encoded)
            val pubKey2 = CryptoPublicKey.decodeFromDer(keyPair.public.encoded)

            pubKey1.hashCode() shouldBe pubKey2.hashCode()
            pubKey1 shouldBe pubKey2
        }
    }

    "EC and RSA" - {
        withData(512, 1024, 2048, 3072, 4096) { rsaBits ->
            withData(256, 384, 521) { ecBits ->
                val keyPairEC1 = KeyPairGenerator.getInstance("EC").also { it.initialize(ecBits) }.genKeyPair()
                val keyPairEC2 = KeyPairGenerator.getInstance("EC").also { it.initialize(ecBits) }.genKeyPair()
                val keyPairRSA1 = KeyPairGenerator.getInstance("RSA").also { it.initialize(rsaBits) }.genKeyPair()
                val keyPairRSA2 = KeyPairGenerator.getInstance("RSA").also { it.initialize(rsaBits) }.genKeyPair()
                val pubKey1 = CryptoPublicKey.decodeFromDer(keyPairEC1.public.encoded)
                val pubKey2 = CryptoPublicKey.decodeFromDer(keyPairEC2.public.encoded)
                val pubKey3 = CryptoPublicKey.decodeFromDer(keyPairRSA1.public.encoded)
                val pubKey4 = CryptoPublicKey.decodeFromDer(keyPairRSA2.public.encoded)

                pubKey1.hashCode() shouldNotBe pubKey2.hashCode()
                pubKey1.hashCode() shouldNotBe pubKey3.hashCode()
                pubKey1.hashCode() shouldNotBe pubKey4.hashCode()
                pubKey3.hashCode() shouldNotBe pubKey4.hashCode()
                pubKey3.hashCode() shouldNotBe pubKey2.hashCode()
                pubKey4.hashCode() shouldNotBe pubKey2.hashCode()
                pubKey1 shouldNotBe pubKey2
                pubKey1 shouldNotBe pubKey3
                pubKey1 shouldNotBe pubKey4
                pubKey3 shouldNotBe pubKey4
                pubKey3 shouldNotBe pubKey2
                pubKey4 shouldNotBe pubKey2
            }
        }
    }
})
