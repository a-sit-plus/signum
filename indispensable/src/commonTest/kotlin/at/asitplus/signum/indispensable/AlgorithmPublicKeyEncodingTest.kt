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
import at.asitplus.signum.Signum
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
import kotlinx.serialization.decodeFromByteArray
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
        val bytes = digest.toAsn1.DER()
        Digest.fromAsn1(bytes) shouldBe digest
        shouldThrowAny { DER {}.encodeToByteArray(digest) }
    }
    "Contextual signature algorithms work through interface and concrete types" {
        for (source in EcdsaAlgorithm.entries + RsaAlgorithm.entries) {
            val algorithm: SignatureAlgorithm = source
            val bytes = Signum.Der.encodeToByteArray(algorithm)
            Signum.Der.decodeFromByteArray<SignatureAlgorithm>(bytes) shouldBe source
            Signum.Der.decodeFromTlv<SignatureAlgorithm>(Signum.Der.encodeToTlv(algorithm)) shouldBe source
            val sink = Buffer()
            Signum.Der.encodeToSink(algorithm, sink)
            Signum.Der.decodeFromSource<SignatureAlgorithm>(sink) shouldBe source
        }
        val ec = EcdsaAlgorithm.withSHA256
        Signum.Der.decodeFromByteArray<EcdsaAlgorithm>(Signum.Der.encodeToByteArray(ec)) shouldBe ec
        val rsa = RsaAlgorithm.withSHA256andPSSPadding
        Signum.Der.decodeFromByteArray<RsaAlgorithm>(Signum.Der.encodeToByteArray(rsa)) shouldBe rsa
    }

    "Absent RSA signature parameters survive structural and byte conversion" {
        val normal = RsaAlgorithm.withSHA256andPKCS1Padding.asn1Representation
        val original = X509AlgorithmIdentifier(normal.oid, null)
        val algorithm = SignatureAlgorithm.fromAsn1(original)
        algorithm.toAsn1() shouldBe original
    }

    "Public key interface and concrete serializers preserve compressed SPKI" {
        val ec = ECCurve.SECP_256_R_1.generator.asPublicKey()
        val original = SubjectPublicKeyInfo.from(Sec1EcPublicKeyInfo.Compressed(ec.curve.oid, ec.xBytes, true))
        val key: CryptoPublicKey = CryptoPublicKey.fromAsn1(original)
        key.toAsn1() shouldBeSameInstanceAs original
        val rsa = RsaPublicKey(Asn1Integer.fromUnsignedByteArray(ByteArray(64).apply { this[0] = 0x80.toByte() }), Asn1Integer(65537))

        Signum.Der.decodeFromByteArray<RsaPublicKey>(Signum.Der.encodeToByteArray(rsa)) shouldBe rsa
        val rsaInterface: CryptoPublicKey = rsa
        CryptoPublicKey.fromAsn1(rsaInterface.toAsn1.DER()) shouldBe rsa
    }
}
