package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.CertificateValidityException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.AuthorityKeyIdentifierExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.SubjectKeyIdentifierExtension
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Instant

/**
 * Checks whether the certificate is constructed correctly, since some components are decoded too leniently
 * */
class CertValidityValidator(
    val date: Instant
) : CertificateValidator {
    @ExperimentalPkiApi
    override suspend fun check(
        currCert: X509Certificate,
        remainingCriticalExtensions: MutableSet<ObjectIdentifier>
    ) {
        checkSerialNumber(currCert)
        isSanCriticalWhenNameIsEmpty(currCert)
        checkTimeValidity(currCert)
    }

    @Throws(Asn1StructuralException::class)
    fun checkSerialNumber(cert: X509Certificate) {
        if (cert.tbsCertificate.serialNumber.size > 20) throw Asn1StructuralException("Serial number too long")
        if (cert.tbsCertificate.serialNumber[0] < 0) throw Asn1StructuralException("Serial number must be positive")
        if (cert.tbsCertificate.serialNumber.all { it == 0.toByte() }) throw Asn1StructuralException("Serial number must not be zero")
    }

    @Throws(CertificateChainValidatorException::class)
    private fun isSanCriticalWhenNameIsEmpty(cert: X509Certificate) {
        val sanExtension = cert.tbsCertificate.extensions?.find { it.oid == KnownOIDs.subjectAltName_2_5_29_17 }
        if (cert.tbsCertificate.subjectName.relativeDistinguishedNames.isEmpty() && sanExtension?.critical == false)
            throw CertificateChainValidatorException("SAN extension is not critical, which is required when subject is empty.")

    }

    @Throws(Asn1StructuralException::class)
    private fun checkTimeValidity(cert: X509Certificate) {
        if (cert.tbsCertificate.validFrom.instant > cert.tbsCertificate.validUntil.instant)
            throw Asn1StructuralException("notBefore is later then notAfter.")
    }
}