package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.CertificateSerialNumberException
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.InvalidCertificateValidityPeriodException
import at.asitplus.signum.indispensable.pki.SanNotCriticalWithEmptySubjectException
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.awesn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate

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
        val serialNumber = cert.tbsCertificate.serialNumber
        if (serialNumber.encodeToAsn1ContentBytes().size > 20) throw CertificateSerialNumberException("Serial number too long")
        if (serialNumber.sign == Asn1Integer.Sign.NEGATIVE) throw CertificateSerialNumberException("Serial number must be positive")
        if (serialNumber.isZero()) throw CertificateSerialNumberException("Serial number must not be zero")
    }

    @Throws(SanNotCriticalWithEmptySubjectException::class)
    private fun isSanCriticalWhenNameIsEmpty(cert: X509Certificate) {
        val sanExtension = cert.tbsCertificate.extensions?.find { it.oid == KnownOIDs.subjectAltName_2_5_29_17 }
        if (cert.tbsCertificate.subjectName.relativeDistinguishedNames.isEmpty() && sanExtension?.critical == false)
            throw SanNotCriticalWithEmptySubjectException("SAN extension is not critical, which is required when subject is empty.")

    }

    @Throws(InvalidCertificateValidityPeriodException::class)
    private fun checkTimeValidity(cert: X509Certificate) {
        if (cert.tbsCertificate.validFrom > cert.tbsCertificate.validUntil)
            throw InvalidCertificateValidityPeriodException("notBefore is later then notAfter.")
    }
}