package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.PemHeader
import at.asitplus.awesn1.decodeFromPem
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.Asn1Decoders
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.RsaPrivateKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import at.asitplus.signum.indispensable.sign.asn1
import at.asitplus.signum.indispensable.sign.fromAsn1
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.SerializationException
import java.security.KeyPairGenerator

private data class KeyPemSample(
    val key: WithSourceRepresentation,
    val specificPem: String,
    val canonicalPem: String,
    val decoder: Asn1Decoders.WithPEM<*, WithSourceRepresentation>,
)

val PemKeyRegressionTest by matrixSuite {
    val rsa by lazy { KeyPairGenerator.getInstance("RSA").apply { initialize(512) }.generateKeyPair() }

    listOf("RSA PUBLIC KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY").asData() - { label ->
        val sample by lazy {
            when (label) {
                "RSA PUBLIC KEY" -> RsaPublicKey.fromAsn1(rsa.public.encoded).let {
                    KeyPemSample(it, it.asn1.pkcs1.toPem(), it.asn1.toPem(), CryptoPublicKey.fromAsn1)
                }
                "RSA PRIVATE KEY" -> RsaPrivateKey.fromAsn1(rsa.private.encoded).let {
                    KeyPemSample(it, it.asn1.pkcs1.toPem(), it.asn1.toPem(), CryptoPrivateKey.fromAsn1)
                }
                else -> EcdsaPrivateKey.WithPublicKey(BigInteger.ONE, ECCurve.SECP_256_R_1).let {
                    KeyPemSample(it, it.asn1.sec1.toPem(), it.asn1.toPem(), CryptoPrivateKey.fromAsn1)
                }
            }
        }

        test("Algorithm-specific label selects PKCS1 or SEC1 before conversion to SPKI or PKCS8") {
            sample.decoder(sample.specificPem) shouldBe sample.key
        }
        test("Canonical SPKI or PKCS8 PEM still decodes to the same key") {
            sample.decoder(sample.canonicalPem) shouldBe sample.key
        }
        test("Bundles choose the ASN1 structure separately for every block") {
            val bundle = listOf(sample.specificPem, sample.canonicalPem, sample.specificPem).joinToString("\n")
            sample.decoder.list(bundle).toList() shouldBe listOf(sample.key, sample.key, sample.key)
        }
        test("Single-key decoding rejects a bundle instead of returning its first key") {
            shouldThrow<IllegalArgumentException> {
                sample.decoder(sample.specificPem + "\n" + sample.canonicalPem)
            }.message shouldContain "Multiple PEM blocks"
        }
        test("PKCS1 or SEC1 payload cannot simply be relabeled as SPKI or PKCS8") {
            val mislabeled = PemBlock.decodeFromPem(sample.specificPem).copy(
                pemLabel = PemBlock.decodeFromPem(sample.canonicalPem).pemLabel).encodeToPem()
            shouldThrow<SerializationException> { sample.decoder(mislabeled) }
            shouldThrow<SerializationException> {
                sample.decoder.list(sample.canonicalPem + "\n" + mislabeled).toList()
            }
        }
        test("SPKI or PKCS8 payload cannot simply be relabeled as PKCS1 or SEC1") {
            val mislabeled = PemBlock.decodeFromPem(sample.canonicalPem).copy(pemLabel = label).encodeToPem()
            shouldThrow<SerializationException> { sample.decoder(mislabeled) }
        }
        test("Unsupported labels fail even when the payload contains a valid key") {
            val unsupported = PemBlock.decodeFromPem(sample.canonicalPem).copy(pemLabel = "UNKNOWN KEY").encodeToPem()
            shouldThrow<IllegalArgumentException> {
                sample.decoder(unsupported)
            }.message shouldContain "Unexpected PEM label"
            shouldThrow<IllegalArgumentException> {
                sample.decoder.list(sample.canonicalPem + "\n" + unsupported).toList()
            }.message shouldContain "Unexpected PEM label"
        }
        listOf("Algorithm-specific", "Canonical").asData() - { format ->
            test("Unsupported PEM headers fail for single keys and bundles") {
                val pem = if (format == "Canonical") sample.canonicalPem else sample.specificPem
                val withHeaders = PemBlock.decodeFromPem(pem).copy(
                    headers = listOf(PemHeader("Comment", "Unsupported header"))).encodeToPem()
                shouldThrow<Asn1Exception> {
                    sample.decoder(withHeaders)
                }.message shouldContain "Expected empty PEM headers"
                shouldThrow<Asn1Exception> {
                    sample.decoder.list(sample.canonicalPem + "\n" + withHeaders).toList()
                }.message shouldContain "Expected empty PEM headers"
            }
        }
    }
}
