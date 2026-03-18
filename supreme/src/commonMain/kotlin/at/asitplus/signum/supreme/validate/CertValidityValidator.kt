package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateSerialNumberException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.InvalidCertificateValidityPeriodException
import at.asitplus.signum.SanNotCriticalWithEmptySubjectException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate

/**
 * Checks whether the certificate is constructed correctly, since some components are decoded too leniently
 * */
class CertValidityValidator: CertificateValidator {
    @ExperimentalPkiApi
    override suspend fun check(
        currCert: X509Certificate,
    ): Set<ObjectIdentifier> {
        checkSerialNumber(currCert)
        isSanCriticalWhenNameIsEmpty(currCert)
        checkTimeValidity(currCert)
        return setOf(KnownOIDs.subjectAltName_2_5_29_17)
    }

    @Throws(CertificateSerialNumberException::class)
    fun checkSerialNumber(cert: X509Certificate) {
        if (cert.tbsCertificate.serialNumber.size > 20) throw CertificateSerialNumberException("Serial number too long")
        if (cert.tbsCertificate.serialNumber[0] < 0) throw CertificateSerialNumberException("Serial number must be positive")
        if (cert.tbsCertificate.serialNumber.all { it == 0.toByte() }) throw CertificateSerialNumberException("Serial number must not be zero")
    }

    @Throws(SanNotCriticalWithEmptySubjectException::class)
    private fun isSanCriticalWhenNameIsEmpty(cert: X509Certificate) {
        val sanExtension = cert.tbsCertificate.extensions?.find { it.oid == KnownOIDs.subjectAltName_2_5_29_17 }
        if (cert.tbsCertificate.subjectName.relativeDistinguishedNames.isEmpty() && sanExtension?.critical == false)
            throw SanNotCriticalWithEmptySubjectException("SAN extension is not critical, which is required when subject is empty.")

    }

    @Throws(InvalidCertificateValidityPeriodException::class)
    private fun checkTimeValidity(cert: X509Certificate) {
        if (cert.tbsCertificate.validFrom.instant > cert.tbsCertificate.validUntil.instant)
            throw InvalidCertificateValidityPeriodException("notBefore is later then notAfter.")
    }
}