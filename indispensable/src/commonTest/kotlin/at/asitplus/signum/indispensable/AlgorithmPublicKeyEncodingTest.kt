package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo.Companion.from
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.io.Buffer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest

@Serializable
private data class DigestMetadata(
    val supportedDigests: Set<@Serializable(with = WellKnownDigest.Serializer::class) WellKnownDigest?>,
)

val AlgorithmPublicKeyEncodingTest by matrixSuite {
    "Digest JSON metadata stays names while DER uses contextual algorithm identifiers" {
        val metadata = DigestMetadata(linkedSetOf(WellKnownDigest.SHA256, null))
        val json = "{\"supportedDigests\":[\"SHA256\",null]}"
        Json.encodeToString(metadata) shouldBe json
        Json.decodeFromString<DigestMetadata>(json) shouldBe metadata
        val der = DER { serializersModule = signumX509Serializers }
        val digest: WellKnownDigest = WellKnownDigest.SHA256
        val bytes = der.encodeToByteArray(digest)
        der.decodeFromByteArray<WellKnownDigest>(bytes) shouldBe digest
        der.decodeFromByteArray<Digest>(bytes) shouldBe digest
        shouldThrowAny { DER {}.encodeToByteArray(digest) }
    }
    "Contextual signature algorithms work through interface and concrete types" {
        for (source in EcdsaAlgorithm.entries + RsaAlgorithm.entries) {
            val algorithm: SignatureAlgorithm = source
            val bytes = DER.encodeToByteArray(algorithm)
            DER.decodeFromByteArray<SignatureAlgorithm>(bytes) shouldBe source
            DER.decodeFromTlv<SignatureAlgorithm>(DER.encodeToTlv(algorithm)) shouldBe source
            val sink = Buffer()
            DER.encodeToSink(algorithm, sink)
            DER.decodeFromSource<SignatureAlgorithm>(sink) shouldBe source
        }
        val ec = EcdsaAlgorithm.withSHA256
        DER.decodeFromByteArray<EcdsaAlgorithm>(DER.encodeToByteArray(ec)) shouldBe ec
        val rsa = RsaAlgorithm.withSHA256andPSSPadding
        DER.decodeFromByteArray<RsaAlgorithm>(DER.encodeToByteArray(rsa)) shouldBe rsa
    }

    "Absent RSA signature parameters survive structural and byte conversion" {
        val normal = RsaAlgorithm.withSHA256andPKCS1Padding.asn1Representation
        val original = X509AlgorithmIdentifier(normal.oid, null)
        val algorithm = SignatureAlgorithm.fromAsn1Representation(original)
        algorithm.asn1Representation shouldBe original
        algorithm.representations[X509] shouldBe original
        val bytes = DER.encodeToByteArray(original)
        DER.encodeToByteArray(DER.decodeFromByteArray<SignatureAlgorithm>(bytes)) shouldBe bytes
    }

    "Public key interface and concrete serializers preserve compressed SPKI" {
        val ec = ECCurve.SECP_256_R_1.generator.asPublicKey()
        val original = SubjectPublicKeyInfo.from(Sec1EcPublicKeyInfo.Compressed(ec.curve.oid, ec.xBytes, true))
        val key: CryptoPublicKey = CryptoPublicKey.fromAsn1Representation(original)
        key.asn1Representation shouldBeSameInstanceAs original
        val bytes = DER.encodeToByteArray(original)
        DER.encodeToByteArray(key) shouldBe bytes
        val decoded = DER.decodeFromByteArray<CryptoPublicKey>(bytes)
        decoded.asn1Representation shouldBeSameInstanceAs decoded.representations[X509]
        DER.encodeToByteArray(decoded) shouldBe bytes
        DER.encodeToByteArray(DER.decodeFromByteArray<EcdsaPublicKey>(bytes)) shouldBe bytes
        DER.decodeFromByteArray<EcdsaPublicKey>(DER.encodeToByteArray(ec)) shouldBe ec
        val buffer = Buffer()
        DER.encodeToSink(key, buffer)
        DER.encodeToByteArray(DER.decodeFromSource<CryptoPublicKey>(buffer)) shouldBe bytes
        val rsa = RsaPublicKey(Asn1Integer.fromUnsignedByteArray(ByteArray(64).apply { this[0] = 0x80.toByte() }), Asn1Integer(65537))
        DER.decodeFromByteArray<RsaPublicKey>(DER.encodeToByteArray(rsa)) shouldBe rsa
        val rsaInterface: CryptoPublicKey = rsa
        DER.decodeFromByteArray<CryptoPublicKey>(DER.encodeToByteArray(rsaInterface)) shouldBe rsa
    }

    "Contextual registration and limits are local to a configured Der" {
        val algorithm: SignatureAlgorithm = EcdsaAlgorithm.withSHA256
        val key: CryptoPublicKey = ECCurve.SECP_256_R_1.generator.asPublicKey()
        val empty = DER {}
        shouldThrowAny { empty.encodeToByteArray(algorithm) }
        shouldThrowAny { empty.encodeToByteArray(key) }
        val registered = DER { serializersModule = signumX509Serializers }
        registered.decodeFromByteArray<SignatureAlgorithm>(registered.encodeToByteArray(algorithm)) shouldBe algorithm
        registered.decodeFromByteArray<CryptoPublicKey>(registered.encodeToByteArray(key)) shouldBe key
        val limited = DER { serializersModule = signumX509Serializers; maxInputLength = 1 }
        shouldThrowAny { limited.decodeFromByteArray<SignatureAlgorithm>(registered.encodeToByteArray(algorithm)) }
        shouldThrowAny { limited.decodeFromByteArray<CryptoPublicKey>(registered.encodeToByteArray(key)) }
    }
}
