package at.asitplus.signum.supreme.validate

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.signum.indispensable.pki.BundledTrustStore
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificateExpiredException
import at.asitplus.signum.indispensable.pki.CertificateNotYetValidException
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.TrustAnchor
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Instant

@OptIn(ExperimentalPkiApi::class)
val TimeValidityValidatorTest by matrixSuite {
    val template = BundledTrustStore.anchors.first().cert!!
    val validator = TimeValidityValidator()
    val validationTime = Instant.parse("2025-01-01T00:00:00Z")

    fun Certificate.withValidity(validFrom: String, validUntil: String): Certificate {
        val tbs = tbsCertificate
        return Certificate(
            TbsCertificate(
                serialNumber = tbs.serialNumber as Asn1Integer.Positive,
                signatureAlgorithm = tbs.signatureAlgorithm,
                issuerName = tbs.issuerName,
                validFrom = Instant.parse(validFrom),
                validUntil = Instant.parse(validUntil),
                subjectName = tbs.subjectName,
                publicKey = tbs.publicKey,
                issuerUniqueID = tbs.issuerUniqueID,
                subjectUniqueID = tbs.subjectUniqueID,
                extensions = tbs.extensions,
            ),
            signature,
        )
    }

    suspend fun validate(vararg path: Certificate, anchor: Certificate = template) = runCatching {
        validator.validate(
            AnchoredCertificateChain(path.toList(), TrustAnchor.Certificate(anchor)),
            CertificateValidationContext(date = validationTime),
        )
    }

    "validates every path certificate at the requested time" {
        validate(
            template.withValidity("2022-01-01T00:00:00Z", "2028-01-01T00:00:00Z"),
            template.withValidity("2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
        ).isSuccess shouldBe true

        // A certificate's notBefore is not its issuance time.
        validate(
            template.withValidity("2020-01-01T00:00:00Z", "2028-01-01T00:00:00Z"),
            template.withValidity("2024-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
        ).isSuccess shouldBe true
    }

    "rejects expired and not-yet-valid path certificates" {
        validate(
            template.withValidity("2021-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
            template.withValidity("2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
        ).exceptionOrNull().shouldBeInstanceOf<CertificateExpiredException>()

        validate(
            template.withValidity("2021-01-01T00:00:00Z", "2028-01-01T00:00:00Z"),
            template.withValidity("2020-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
        ).exceptionOrNull().shouldBeInstanceOf<CertificateExpiredException>()

        validate(
            template.withValidity("2026-01-01T00:00:00Z", "2028-01-01T00:00:00Z"),
            template.withValidity("2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
        ).exceptionOrNull().shouldBeInstanceOf<CertificateNotYetValidException>()

        validate(
            template.withValidity("2020-01-01T00:00:00Z", "2028-01-01T00:00:00Z"),
            template.withValidity("2026-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
        ).exceptionOrNull().shouldBeInstanceOf<CertificateNotYetValidException>()
    }

    "treats validity boundaries as inclusive" {
        validate(template.withValidity("2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z")).isSuccess shouldBe true
    }

    "does not apply certificate validity to the trust anchor" {
        validate(
            template.withValidity("2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
            anchor = template.withValidity("2000-01-01T00:00:00Z", "2001-01-01T00:00:00Z"),
        ).isSuccess shouldBe true
    }
}
