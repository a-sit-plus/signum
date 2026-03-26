package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CRLRevocationException
import at.asitplus.signum.CertificateException
import at.asitplus.signum.CrlDistributionPointMismatchException
import at.asitplus.signum.CrlInvalidSignatureAlgorithmException
import at.asitplus.signum.CrlIssuerMismatchException
import at.asitplus.signum.CrlMissingPublicKeyException
import at.asitplus.signum.CrlScopeViolationException
import at.asitplus.signum.CrlSignatureException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.IndirectCrlNotSupportedException
import at.asitplus.signum.MissingCrlDistributionPointsException
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.authorityKeyIdentifier_2_5_29_35
import at.asitplus.signum.indispensable.asn1.cRLDistributionPoints_2_5_29_31
import at.asitplus.signum.indispensable.asn1.cRLReason
import at.asitplus.signum.indispensable.asn1.certificateIssuer
import at.asitplus.signum.indispensable.asn1.deltaCRLIndicator
import at.asitplus.signum.indispensable.asn1.freshestCRL
import at.asitplus.signum.indispensable.asn1.invalidityDate
import at.asitplus.signum.indispensable.asn1.issuingDistributionPoint_2_5_29_28
import at.asitplus.signum.indispensable.pki.CRLEntry
import at.asitplus.signum.indispensable.pki.CertificateList
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.generalNames.GeneralName
import at.asitplus.signum.indispensable.pki.generalNames.GeneralNameOption
import at.asitplus.signum.indispensable.pki.generalNames.X500Name
import at.asitplus.signum.indispensable.pki.pkiExtensions.BasicConstraintsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.CRLDistributionPointsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.CRLReason
import at.asitplus.signum.indispensable.pki.pkiExtensions.CRLReasonCodeExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.CertificateIssuerExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.DistributionPointName
import at.asitplus.signum.indispensable.pki.pkiExtensions.IssuingDistributionPointExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.ReasonFlag
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify

class CrlRevocationValidator(
    private val crlProvider: CrlProvider = DirectoryCrlProvider()
) : CertificateChainValidator {

    @OptIn(ExperimentalPkiApi::class)
    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {

        if (!context.supportRevocationChecking) return emptyMap()
        var currentCertIndex = 0
        val checkedExtensions = mutableMapOf<X509Certificate, MutableSet<ObjectIdentifier>>()
        val processingChain = anchoredChain.trustAnchor.cert?.let { anchoredChain.chain + it }
            ?: anchoredChain.chain

        for (currCert in processingChain.dropLast(1)) {
            val issuerCert = processingChain.find { it.tbsCertificate.subjectName == currCert.tbsCertificate.issuerName }
                ?: throw CertificateException("Cannot find issuer in chain for certificate with index $currentCertIndex")
            val remainingReasons = CRLReason.entries
                .filter { it != CRLReason.UNUSED_7 &&
                        it != CRLReason.REMOVE_FROM_CRL &&
                        it != CRLReason.UNSPECIFIED }
                .toMutableSet()

            val possibleCrls = mutableListOf<CertificateList>()

            crlProvider.getCrl(currCert, issuerCert).let { possibleCrls.addAll(it) }
            val cdpExtension = currCert.findExtension<CRLDistributionPointsExtension>()
            cdpExtension?.distributionPoints?.forEach { dp ->
                val crlIssuer = dp.crlIssuer?.let { name ->
                    processingChain.find { it.tbsCertificate.subjectName == name.name }
                } ?: issuerCert

                val crlsFromIssuer = crlProvider.getCrl(currCert, crlIssuer)
                possibleCrls.addAll(crlsFromIssuer)
            }

            runCatching {
                possibleCrls.addAll(crlProvider.getCrlsFromDistributionPoints(currCert))
            }

            val approvedCrls = mutableListOf<CertificateList>()

            for (crl in possibleCrls) {
                try {
                    val crlSignerCert = processingChain.findLast { chainCert ->
                        chainCert.tbsCertificate.subjectName == crl.tbsCertList.issuer
                    } ?: throw CertificateException("No certificate in the chain matches CRL issuer")

                    verifyCrl(crl, currCert, crlSignerCert, context)

                    val coveredReasons = getCoveredReasons(crl, currCert)
                    approvedCrls.add(crl)

                    val newCoverage = coveredReasons.intersect(remainingReasons)
                    remainingReasons.removeAll(newCoverage)

                    if (remainingReasons.isEmpty()) break

                } catch (_: Throwable) {}
            }

            if (remainingReasons.isNotEmpty()) {
                try {
                    val dpCrls = crlProvider.getCrlsFromDistributionPoints(currCert)

                    for (crl in dpCrls) {
                        try {
                            verifyCrl(crl, currCert, issuerCert, context)

                            val coveredReasons = getCoveredReasons(crl, currCert)
                            val newCoverage = coveredReasons.intersect(remainingReasons)

                            if (newCoverage.isNotEmpty()) {
                                approvedCrls.add(crl)
                                remainingReasons.removeAll(newCoverage)
                            }

                            if (remainingReasons.isEmpty()) break

                        } catch (_: Exception) {}
                    }

                } catch (_: Throwable) {
                    // ignore DP failure
                }
            }

            checkRevocationInCrls(approvedCrls, currCert, context)

            if (remainingReasons.isNotEmpty()) {
                throw CertificateException(
                    "Could not determine revocation status. Missing reasons: $remainingReasons"
                )
            }

            checkedExtensions.getOrPut(currCert) { mutableSetOf() }
                .addAll(
                    listOf(
                        KnownOIDs.cRLDistributionPoints_2_5_29_31,
                        KnownOIDs.freshestCRL
                    )
                )
            currentCertIndex++
        }

        return checkedExtensions
    }

    private suspend fun verifyCrl(
        crl: CertificateList,
        cert: X509Certificate,
        issuerCert: X509Certificate,
        context: CertificateValidationContext
    ) {
        validateCrlIntegrity(crl, cert, issuerCert, context)
        validateCrlExtensions(crl)
        validateIssuingDistributionPoint(crl, cert)
    }

    private fun checkRevocationInCrls(
        crls: List<CertificateList>,
        cert: X509Certificate,
        context: CertificateValidationContext
    ) {
        val serial = cert.tbsCertificate.serialNumber
        val certIssuer = cert.tbsCertificate.issuerName

        for (crl in crls) {

            for (entry in crl.tbsCertList.revokedCertificates ?: emptyList()) {
                val entryIssuer = entry.findExtension<CertificateIssuerExtension>()?.issuer
                    ?.firstOrNull { it.name.type == GeneralNameOption.NameType.DIRECTORY }
                    ?.name as? X500Name ?: crl.tbsCertList.issuer

                if (entryIssuer != certIssuer) continue
                if (!entry.certSerialNumber.contentEquals(serial)) continue

                validateCrlEntryExtensions(entry)

                val reason = getReasonCode(entry) ?: CRLReason.UNSPECIFIED

                if (reason == CRLReason.REMOVE_FROM_CRL) continue

                val coveredReasons = getCoveredReasons(crl, cert)

                if (reason !in coveredReasons) continue

                val revocationDate = entry.revocationTime.instant
                if (revocationDate <= context.date) {
                    throw CRLRevocationException(
                        "Certificate revoked. Reason: $reason"
                    )
                }
            }
        }
    }

    private fun getCoveredReasons(
        crl: CertificateList,
        cert: X509Certificate
    ): Set<CRLReason> {

        val idp = crl.findExtension<IssuingDistributionPointExtension>()

        validateIssuingDistributionPoint(crl, cert)

        val restricted = idp?.onlySomeReasons
        return if (restricted != null) {
            ReasonFlag.parseReasons(restricted).map { it.crlReason }.toSet()
        } else {
            CRLReason.entries
                .filter { it != CRLReason.UNUSED_7 &&
                        it != CRLReason.REMOVE_FROM_CRL &&
                        it != CRLReason.UNSPECIFIED }
                .toSet()
        }
    }

    private suspend fun validateCrlIntegrity(
        crl: CertificateList,
        currCert: X509Certificate,
        issuerCert: X509Certificate,
        context: CertificateValidationContext
    ) {
        crl.checkValidityAt(context.date)
        crl.checkValidityAt(context.date)

        val certIssuer = currCert.tbsCertificate.issuerName
        val crlIssuer = crl.tbsCertList.issuer

        val idp = crl.findExtension<IssuingDistributionPointExtension>()

        val isIndirectUsage = crlIssuer != certIssuer

        if (isIndirectUsage) {
            if (idp == null || !idp.indirectCRL) {
                throw CertificateException(
                    "CRL is used as indirect but IssuingDistributionPoint is missing"
                )
            }
        } else {
            if (idp?.indirectCRL == false &&
                crlIssuer != issuerCert.tbsCertificate.subjectName
            ) {
                throw CrlIssuerMismatchException("CRL issuer mismatch")
            }
        }

        val publicKey = issuerCert.decodedPublicKey.getOrNull()
            ?: throw CrlMissingPublicKeyException("Missing public key")

        val sigAlg = crl.signatureAlgorithm as? X509SignatureAlgorithm
            ?: throw CrlInvalidSignatureAlgorithmException("Invalid signature algorithm")

        val verified = sigAlg.verifierFor(publicKey)
            .getOrThrow()
            .verify(
                crl.tbsCertList.encodeToDer(),
                crl.decodedSignature.getOrThrow()
            ).isSuccess

        if (!verified) throw CrlSignatureException("Invalid CRL signature")
    }

    private fun validateIssuingDistributionPoint(crl: CertificateList, cert: X509Certificate) {
        val issuingDistPoint = crl.findExtension<IssuingDistributionPointExtension>() ?: return
        val isCa = cert.findExtension<BasicConstraintsExtension>()?.ca ?: false

        if (issuingDistPoint.onlyContainsUserCerts && isCa) {
            throw CrlScopeViolationException("CRL only contains user certs, but cert is a CA")
        }
        if (issuingDistPoint.onlyContainsCACerts && !isCa) {
            throw CrlScopeViolationException("CRL only contains CA certs, but cert is an end-entity")
        }

        if (issuingDistPoint.onlyContainsAttributeCerts) {
            throw CrlScopeViolationException(
                "CRL only contains attribute certificates and cannot be used for X.509 certificates"
            )
        }

        val idpName = issuingDistPoint.distributionPointName ?: return

        val certDpExtension = cert.findExtension<CRLDistributionPointsExtension>()
            ?: throw MissingCrlDistributionPointsException("CRL has restricted scope (IDP), but Certificate has no CDP extension")

        val matchFound = certDpExtension.distributionPoints.any { certDp ->
            val namesMatch = matchesDistributionPointNames(idpName,certDp.distributionPointName, crl)
            val issuerMatches = if (issuingDistPoint.indirectCRL) {
                true
            } else {
                crl.tbsCertList.issuer == cert.tbsCertificate.issuerName
            }
            namesMatch && issuerMatches
        }

        if (!matchFound) {
            throw CrlDistributionPointMismatchException("CRL IssuingDistributionPoint name does not match any name in Certificate CDP")
        }
    }

    private fun validateCrlExtensions(crl: CertificateList) {
        crl.tbsCertList.extensions?.forEach {
            if (it.critical && !isSupportedCrlExtension(it.oid)) {
                throw CRLRevocationException("Unsupported CRL extension: ${it.oid}")
            }
        }
    }

    private fun validateCrlEntryExtensions(entry: CRLEntry) {
        entry.crlEntryExtensions?.forEach {
            if (it.critical && !isSupportedEntryExtension(it.oid)) {
                throw CRLRevocationException("Unsupported CRL entry extension: ${it.oid}")
            }
        }
    }

    private fun isSupportedCrlExtension(oid: ObjectIdentifier) = when (oid) {
        KnownOIDs.issuingDistributionPoint_2_5_29_28,
        KnownOIDs.authorityKeyIdentifier_2_5_29_35,
        KnownOIDs.deltaCRLIndicator -> true
        else -> false
    }

    private fun isSupportedEntryExtension(oid: ObjectIdentifier) = when (oid) {
        KnownOIDs.cRLReason,
        KnownOIDs.certificateIssuer,
        KnownOIDs.invalidityDate -> true
        else -> false
    }
    private fun getReasonCode(entry: CRLEntry): CRLReason? =
        entry.findExtension<CRLReasonCodeExtension>()?.reason
}

@OptIn(ExperimentalPkiApi::class)
fun matchesDistributionPointNames(
    idpName: DistributionPointName,
    cdpName: DistributionPointName?,
    crl: CertificateList
): Boolean {

    if (cdpName == null) return false

    val issuer = crl.tbsCertList.issuer

    val idpFullNames = idpName.toGeneralNames(issuer)
    val cdpFullNames = cdpName.toGeneralNames(issuer)

    return idpFullNames.any { idpGn ->
        cdpFullNames.any { cdpGn ->
            idpGn.name.constrains(cdpGn.name) ==
                    GeneralNameOption.ConstraintResult.MATCH
        }
    }
}

private fun DistributionPointName.toGeneralNames(
    issuer: X500Name
): List<GeneralName> = when (this) {

    is DistributionPointName.FullName -> names

    is DistributionPointName.NameRelativeToCrlIssuer ->
        listOf(resolveRelativeToFullName(this, issuer))
}

private fun resolveRelativeToFullName(
    relative: DistributionPointName.NameRelativeToCrlIssuer,
    issuer: X500Name
): GeneralName {
    val newRdns = issuer.relativeDistinguishedNames + RelativeDistinguishedName(
        listOf(relative.name)
    )
    return GeneralName(X500Name(newRdns))
}

