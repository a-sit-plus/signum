package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.serialization.DER
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.time.Instant

val CertificateExtensionEncodingTest by matrixSuite {
    "An extension without X.509 data is representable in core but cannot be DER encoded" {
        val extension: CertificateExtension = object : CertificateExtension {
            override val oid = ObjectIdentifier("1.2.3.4")
            override val critical = true
            override val representations = emptyMap<Encodable.Representation, Any>()
        }
        extension.asn1Representation shouldBe null
        val tbs = TbsCertificate(
            serialNumber = Asn1Integer.ONE,
            signatureAlgorithm = EcdsaAlgorithm.withSHA256,
            issuerName = X500Name.EMPTY,
            subjectName = X500Name.EMPTY,
            validFrom = Instant.fromEpochSeconds(1_700_000_000),
            validUntil = Instant.fromEpochSeconds(1_800_000_000),
            publicKey = ECCurve.SECP_256_R_1.generator.asPublicKey(),
            extensions = listOf(extension),
        )
        val certificate = Certificate(tbs, EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO))
        certificate.tbsCertificate.extensions.single() shouldBeSameInstanceAs extension
        catchingUnwrapped { DER.encodeToByteArray(extension) }.isFailure shouldBe true
        catchingUnwrapped { DER.encodeToByteArray(tbs) }.isFailure shouldBe true
        catchingUnwrapped { DER.encodeToByteArray(certificate) }.isFailure shouldBe true
    }

    "Representation maps work without an X.509 marker or base class" {
        val original = X509CertificateExtension(ObjectIdentifier("1.2.3.4"), value = byteArrayOf(1, 2, 3)).asn1Representation
        val extension: CertificateExtension = object : CertificateExtension {
            override val oid = original.oid
            override val critical = original.critical
            override val representations: Map<Encodable.Representation, Any> = mapOf(X509 to original)
        }
        extension.asn1Representation shouldBeSameInstanceAs original
        // Interface-typed lookup selects the registered bridge, including for user-defined implementations.
        val value: CertificateExtension = extension
        val der = DER { serializersModule = signumX509Serializers }
        val bytes = der.encodeToByteArray(value)
        val decoded = der.decodeFromByteArray<CertificateExtension>(bytes)
        decoded.asn1Representation shouldBeSameInstanceAs decoded.representations[X509]
        der.encodeToByteArray(decoded) shouldBe bytes
        val generic = X509CertificateExtension(original)
        der.encodeToByteArray(der.decodeFromByteArray<X509CertificateExtension>(der.encodeToByteArray(generic))) shouldBe bytes
    }
}
