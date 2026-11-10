package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo.Companion.from
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.io.Buffer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.Json

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
        key.toAsn1() shouldBeSameInstanceAs original
        val rsa = RsaPublicKey(Asn1Integer.fromUnsignedByteArray(ByteArray(64).apply { this[0] = 0x80.toByte() }), Asn1Integer(65537))

        RsaPublicKey.fromAsn1(rsa.asn1.toDer()) shouldBe rsa
        val rsaInterface: CryptoPublicKey = rsa
        CryptoPublicKey.fromAsn1(rsaInterface.asn1.toDer()) shouldBe rsa
    }
}
