package at.asitplus.signum.indispensable

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.toAsn1Integer
import at.asitplus.signum.indispensable.io.Base64Strict
import io.kotest.assertions.withClue
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

@OptIn(ExperimentalStdlibApi::class)
val KeyTest  by testSuite {
    Security.addProvider(BouncyCastleProvider())

    "EC" - {
        withDataSuites(listOf(256, 384, 521)) { bits ->
            val keys = List(25600 / bits) {
                val ecKp = KeyPairGenerator.getInstance("EC", "BC").apply {
                    initialize(bits)
                }.genKeyPair()
                ecKp.private as ECPrivateKey to ecKp.public as ECPublicKey
            }
            withData(
                nameFn = {
                    "(x: ${it.second.w.affineX.toByteArray().encodeToString(Base64Strict)}" +
                            " y: ${it.second.w.affineY.toByteArray().encodeToString(Base64Strict)})"
                },
                keys
            ) { (privKey, pubKey) ->

                val own = pubKey.toCryptoPublicKey().getOrThrow()

                val ownPrivate = CryptoPrivateKey.decodeFromDer(privKey.encoded) as CryptoPrivateKey.WithPublicKey<*>

                ownPrivate.publicKey shouldBe own
                ownPrivate.encodeToDer() shouldBe privKey.encoded
                ownPrivate.toJcaPrivateKey().getOrThrow().encoded shouldBe privKey.encoded


                withClue("Basic Conversions") {
                    own.encodeToDer() shouldBe pubKey.encoded
                    CryptoPublicKey.fromDid(own.didEncoded) shouldBe own
                    own.toJcaPublicKey().getOrThrow().encoded shouldBe pubKey.encoded
                    CryptoPublicKey.decodeFromTlv(Asn1Element.parse(own.encodeToDer()) as Asn1Sequence) shouldBe own
                }

                withClue("Compressed Test") {
                    own as CryptoPublicKey.EC
                    val compressedPresentation = own.toAnsiX963Encoded(useCompressed = true)
                    val fromCompressed = CryptoPublicKey.EC.fromAnsiX963Bytes(own.curve, compressedPresentation)

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
        withDataSuites(512, 1024, 2048, 3072, 4096) { bits ->
            val keys = List(13000 / bits) {
                val rsaKP = KeyPairGenerator.getInstance("RSA").apply {
                    initialize(bits)
                }.genKeyPair()
                rsaKP.private as RSAPrivateKey to rsaKP.public as RSAPublicKey
            }
            withData(
                nameFn = {
                    "(n: ${
                        it.second.modulus.toByteArray().encodeToString(Base64Strict)
                    } e: ${it.second.publicExponent.toInt()})"
                },
                keys
            ) { (privKey, pubKey) ->

                val own = CryptoPublicKey.RSA(pubKey.modulus.toAsn1Integer(), pubKey.publicExponent.toAsn1Integer())

                val ownPrivate =CryptoPrivateKey.decodeFromDer(privKey.encoded) as CryptoPrivateKey.WithPublicKey<*>
                ownPrivate.publicKey shouldBe own
                ownPrivate.encodeToDer() shouldBe privKey.encoded
                ownPrivate.toJcaPrivateKey().getOrThrow().encoded shouldBe privKey.encoded


                val own1 = CryptoPublicKey.RSA(
                    Asn1Integer.fromUnsignedByteArray(ByteArray((0..10).random()) { 0 } + pubKey.modulus.toByteArray()),
                    Asn1Integer.fromUnsignedByteArray(pubKey.publicExponent.toByteArray())
                )

                // Correctly drops leading zeros
                own1.n shouldBe own.n
                own1.e shouldBe own.e

                val keyBytes = ((ASN1InputStream(pubKey.encoded).readObject()
                    .toASN1Primitive() as ASN1Sequence).elementAt(1) as DERBitString).bytes
                own.pkcsEncoded shouldBe keyBytes //PKCS#1
                own.encodeToDer() shouldBe pubKey.encoded //PKCS#8
                CryptoPublicKey.decodeFromTlv(Asn1Element.parse(own.encodeToDer()) as Asn1Sequence) shouldBe own
                own.toJcaPublicKey().getOrThrow().encoded shouldBe pubKey.encoded
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
        withDataSuites(512, 1024, 2048, 3072, 4096) { rsaBits ->
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
}