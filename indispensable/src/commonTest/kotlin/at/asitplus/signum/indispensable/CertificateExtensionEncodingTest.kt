package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlin.time.Instant

val CertificateExtensionEncodingTest by matrixSuite {
    "An extension without X.509 data is representable in core but cannot be DER encoded" {
        val extension: CertificateExtension = object : CertificateExtension {
            override val oid = ObjectIdentifier("1.2.3.4")
            override val critical = true
            @OptIn(SignumInternals::class)
            override val sourceRepresentation = SourceRepresentationStorage()
        }
        shouldThrow<Asn1Exception> { extension.asn1.toRepresentation() }
        val tbs = TbsCertificate(
            serialNumber = BigInteger.ONE,
            signatureAlgorithm = EcdsaAlgorithm.withSHA256,
            issuerName = Name.EMPTY,
            subjectName = Name.EMPTY,
            validFrom = Instant.fromEpochSeconds(1_700_000_000),
            validUntil = Instant.fromEpochSeconds(1_800_000_000),
            publicKey = ECCurve.SECP_256_R_1.generator.asPublicKey(),
            extensions = listOf(extension),
        )
        val certificate = Certificate(tbs, EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO))
        certificate.tbsCertificate.extensions.single() shouldBeSameInstanceAs extension
        shouldThrow<Asn1Exception> { tbs.asn1.toDer() }
        shouldThrow<Asn1Exception> { certificate.asn1.toDer() }
    }
}
