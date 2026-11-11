package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo.Companion.from
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
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
        data class Case(val preset: WellKnownDigest, val create: () -> WellKnownDigest)
        listOf(
            Case(WellKnownDigest.SHA1) { WellKnownDigest.SHA1() },
            Case(WellKnownDigest.SHA256) { WellKnownDigest.SHA256() },
            Case(WellKnownDigest.SHA384) { WellKnownDigest.SHA384() },
            Case(WellKnownDigest.SHA512) { WellKnownDigest.SHA512() },
        ).asData(nameFn = { it.preset.name }) - { (preset, create) ->
            test("Fresh and decoded instances compare and hash by algorithm, independent of source") {
                val first = create()
                val second = create()
                val withNull = Digest.fromAsn1(X509AlgorithmIdentifier(preset.oid, Asn1Null))
                val withoutParameters = Digest.fromAsn1(X509AlgorithmIdentifier(preset.oid, null))

                first shouldNotBeSameInstanceAs second
                first.sourceRepresentation shouldNotBeSameInstanceAs second.sourceRepresentation
                withNull shouldNotBeSameInstanceAs preset
                withNull.sourceRepresentation shouldNotBeSameInstanceAs withoutParameters.sourceRepresentation
                withNull.asn1.toRepresentation() shouldNotBe withoutParameters.asn1.toRepresentation()
                withNull shouldBe withoutParameters
                withNull.hashCode() shouldBe withoutParameters.hashCode()
                first.hashCode() shouldBe preset.name.hashCode()
                setOf(preset, first, second, withNull, withoutParameters).size shouldBe 1
                first.hashCode() shouldBe withNull.hashCode()
                first.toString() shouldBe preset.name
                when (withNull) {
                    Digest.SHA1 -> "SHA1"
                    Digest.SHA256 -> "SHA256"
                    Digest.SHA384 -> "SHA384"
                    Digest.SHA512 -> "SHA512"
                    else -> error("Decoded digest did not match its preset")
                } shouldBe preset.name
            }
            test("String deserialization creates independent instances and preserves the wire name") {
                val json = "\"${preset.name}\""
                val first = Json.decodeFromString(WellKnownDigest.Serializer, json)
                val second = Json.decodeFromString(WellKnownDigest.Serializer, json)

                first shouldBe preset
                first shouldNotBeSameInstanceAs preset
                first shouldNotBeSameInstanceAs second
                first.sourceRepresentation shouldNotBeSameInstanceAs second.sourceRepresentation
                Json.encodeToString(WellKnownDigest.Serializer, first) shouldBe json
            }
            test("HMAC factory creates value-equal instances with independent source storage") {
                val first = HMAC.byDigest(preset)
                val second = HMAC.byDigest(preset)

                first shouldBe second
                first.hashCode() shouldBe second.hashCode()
                first shouldNotBeSameInstanceAs second
                first.sourceRepresentation shouldNotBeSameInstanceAs second.sourceRepresentation
            }
        }
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
