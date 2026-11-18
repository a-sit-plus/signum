package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo.Companion.from
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeSameInstanceAs
import kotlinx.io.Buffer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.Json

@Serializable
private data class DigestMetadata(
    val supportedDigests: Set<@Serializable(with = WellKnownDigest.Serializer::class) WellKnownDigest?>,
)

val AlgorithmPublicKeyEncodingTest by matrixSuite {
    "Digest instances have value semantics" - {
        WellKnownDigest.entries.flatMap { first ->
            WellKnownDigest.entries.filter { it.name != first.name }.map { second -> first to second }
        }.asData(nameFn = { (first, second) -> "${first.name} vs ${second.name}" }) - { (first, second) ->
            test("Different algorithm names are unequal") {
                first shouldNotBe second
            }
        }
    }

    "Digest JSON metadata stays names while DER uses contextual algorithm identifiers" {
        val metadata = DigestMetadata(linkedSetOf(WellKnownDigest.SHA256, null))
        val json = "{\"supportedDigests\":[\"SHA256\",null]}"
        Json.encodeToString(metadata) shouldBe json
        Json.decodeFromString<DigestMetadata>(json) shouldBe metadata
        val digest: WellKnownDigest = WellKnownDigest.SHA256
        val bytes = digest.asn1.toDer()
        Digest.fromAsn1(bytes) shouldBe digest
        shouldThrowAny { DER {}.encodeToByteArray(digest) }
    }
    "Contextual signature algorithms work through interface and concrete types" {
        for (source in EcdsaAlgorithm.entries + RsaAlgorithm.entries) {
            val algorithm: SignatureAlgorithm = source
            val bytes = algorithm.asn1.toDer()
            SignatureAlgorithm.fromAsn1(bytes) shouldBe source
            SignatureAlgorithm.fromAsn1(algorithm.asn1.toTlv()) shouldBe source
            val sink = Buffer()
            algorithm.asn1.toDer(sink)
            SignatureAlgorithm.fromAsn1(sink) shouldBe source
        }
        val ec = EcdsaAlgorithm.withSHA256
        EcdsaAlgorithm.fromAsn1(ec.asn1.toDer()) shouldBe ec
        val rsa = RsaAlgorithm.withSHA256andPSSPadding
        RsaAlgorithm.fromAsn1(rsa.asn1.toDer()) shouldBe rsa
    }

    "Opaque signature algorithm equality compares retained sources without a certificate fallback" {
        val oid = ObjectIdentifier("1.2.3.4")
        val algorithms = listOf(null, Asn1Null, Asn1.Sequence {}).map { parameters ->
            val source = X509AlgorithmIdentifier(oid, parameters)
            val bytes = DER.encodeToByteArray(source)
            val first = SignatureAlgorithm.fromAsn1(source)
            val second = SignatureAlgorithm.fromAsn1(bytes)

            first.shouldBeInstanceOf<SignatureAlgorithm.Unknown>()
            second.shouldBeInstanceOf<SignatureAlgorithm.Unknown>()
            first shouldNotBeSameInstanceAs second
            first shouldBe second
            second shouldBe first
            first.hashCode() shouldBe second.hashCode()
            first.asn1.toRepresentation().element shouldBeSameInstanceAs source.element
            first.asn1.toDer() shouldBe bytes
            second.asn1.toDer() shouldBe bytes
            first
        }
        algorithms.toSet().size shouldBe 3
    }

    "ECDSA signature identifiers accept absent or NULL parameters and preserve encoding" {
        for (digest in listOf(Digest.SHA1, Digest.SHA256, Digest.SHA384, Digest.SHA512)) {
            val expected = EcdsaAlgorithm(digest)
            val canonical = expected.asn1.toRepresentation()
            canonical.parameters shouldBe null
            val decoded = listOf(null, Asn1Null).map { parameters ->
                val source = X509AlgorithmIdentifier(canonical.oid, parameters)
                val concrete = EcdsaAlgorithm.fromAsn1(source)
                val generic = SignatureAlgorithm.fromAsn1(source)
                concrete shouldBe expected
                generic shouldBe expected
                concrete.hashCode() shouldBe expected.hashCode()
                concrete.asn1.toRepresentation().element shouldBeSameInstanceAs source.element
                generic.asn1.toRepresentation().element shouldBeSameInstanceAs source.element
                val bytes = DER.encodeToByteArray(source)
                val reparsed = EcdsaAlgorithm.fromAsn1(bytes)
                val genericReparsed = SignatureAlgorithm.fromAsn1(bytes)
                reparsed shouldBe expected
                genericReparsed shouldBe expected
                reparsed.asn1.toDer() shouldBe bytes
                genericReparsed.asn1.toDer() shouldBe bytes
                concrete
            }
            decoded[0] shouldBe decoded[1]
            expected.asn1.toRepresentation() shouldBe canonical
            EcdsaAlgorithm(digest).asn1.toRepresentation().parameters shouldBe null
            shouldThrowAny {
                EcdsaAlgorithm.fromAsn1(X509AlgorithmIdentifier(canonical.oid, Asn1.OctetString(byteArrayOf(1))))
            }
        }
    }

    "RSA PKCS1 signature identifiers accept absent or NULL parameters and preserve encoding" {
        for (digest in listOf(Digest.SHA1, Digest.SHA256, Digest.SHA384, Digest.SHA512)) {
            val expected = RsaAlgorithm(RsaAlgorithm.Padding.PKCS1, digest)
            val oid = expected.asn1.toRepresentation().oid
            for (parameters in listOf(null, Asn1Null)) {
                val source = X509AlgorithmIdentifier(oid, parameters)
                val decoded = RsaAlgorithm.fromAsn1(source)
                decoded shouldBe expected
                decoded.asn1.toRepresentation().parameters shouldBe parameters
                val bytes = decoded.asn1.toDer()
                val reparsed = SignatureAlgorithm.fromAsn1(bytes)
                reparsed shouldBe expected
                reparsed.asn1.toDer() shouldBe bytes
            }
            shouldThrowAny { RsaAlgorithm.fromAsn1(X509AlgorithmIdentifier(oid, Asn1.OctetString(byteArrayOf(1)))) }
        }
    }

    "Public key interface and concrete serializers preserve compressed SPKI" {
        val ec = ECCurve.SECP_256_R_1.generator.asPublicKey()
        val original = SubjectPublicKeyInfo.from(Sec1EcPublicKeyInfo.Compressed(ec.curve.oid, ec.xBytes, true))
        val key: CryptoPublicKey = CryptoPublicKey.fromAsn1(original)
        key.asn1.toRepresentation() shouldBeSameInstanceAs original
        val rsa = RsaPublicKey(Asn1Integer.fromUnsignedByteArray(ByteArray(64).apply { this[0] = 0x80.toByte() }), Asn1Integer(65537))

        RsaPublicKey.fromAsn1(rsa.asn1.toDer()) shouldBe rsa
        val rsaInterface: CryptoPublicKey = rsa
        CryptoPublicKey.fromAsn1(rsaInterface.asn1.toDer()) shouldBe rsa
    }
}
