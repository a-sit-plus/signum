package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.authorityKeyIdentifier_2_5_29_35
import at.asitplus.signum.indispensable.asn1.cRLDistributionPoints_2_5_29_31
import at.asitplus.signum.indispensable.asn1.cRLReason
import at.asitplus.signum.indispensable.asn1.certificateIssuer
import at.asitplus.signum.indispensable.asn1.crlExtReason
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

        val checkedExtensions = mutableMapOf<X509Certificate, MutableSet<ObjectIdentifier>>()
        val chain = anchoredChain.trustAnchor.cert?.let { anchoredChain.chain + it }
            ?: anchoredChain.chain

        for (i in 0 until chain.size - 1) {
            val cert = chain[i]
            val issuerCert = chain[i + 1]

            val remainingReasons = CRLReason.entries
                .filter { it != CRLReason.UNUSED_7 &&
                        it != CRLReason.REMOVE_FROM_CRL &&
                        it != CRLReason.UNSPECIFIED }
                .toMutableSet()

            val possibleCrls = mutableListOf<CertificateList>()

            crlProvider.getCrl(cert, issuerCert).let { possibleCrls.addAll(it) }

            runCatching {
                possibleCrls.addAll(crlProvider.getCrlsFromDistributionPoints(cert))
            }

            val approvedCrls = mutableListOf<CertificateList>()

            for (crl in possibleCrls) {
                try {
                    val crlSignerCert = chain.findLast { chainCert ->
                        chainCert.tbsCertificate.subjectName == crl.tbsCertList.issuer
                    } ?: throw CertificateException("No certificate in the chain matches CRL issuer")

                    verifyCrl(crl, cert, crlSignerCert, context)

                    val coveredReasons = getCoveredReasons(crl, cert)
                    approvedCrls.add(crl)

                    val newCoverage = coveredReasons.intersect(remainingReasons)
                    remainingReasons.removeAll(newCoverage)

                    if (remainingReasons.isEmpty()) break

                } catch (_: Exception) {
                }
            }

            if (remainingReasons.isNotEmpty()) {
                try {
                    val dpCrls = crlProvider.getCrlsFromDistributionPoints(cert)

                    for (crl in dpCrls) {
                        try {
                            verifyCrl(crl, cert, issuerCert, context)

                            val coveredReasons = getCoveredReasons(crl, cert)
                            val newCoverage = coveredReasons.intersect(remainingReasons)

                            if (newCoverage.isNotEmpty()) {
                                approvedCrls.add(crl)
                                remainingReasons.removeAll(newCoverage)
                            }

                            if (remainingReasons.isEmpty()) break

                        } catch (_: Exception) {}
                    }

                } catch (_: Exception) {
                    // ignore DP failure
                }
            }

            checkRevocationInCrls(approvedCrls, cert, context)

            if (remainingReasons.isNotEmpty()) {
                throw CertificateException(
                    "Could not determine revocation status. Missing reasons: $remainingReasons"
                )
            }

            checkedExtensions.getOrPut(cert) { mutableSetOf() }
                .addAll(
                    listOf(
                        KnownOIDs.cRLDistributionPoints_2_5_29_31,
                        KnownOIDs.freshestCRL
                    )
                )
        }

        return checkedExtensions
    }

    private suspend fun verifyCrl(
        crl: CertificateList,
        cert: X509Certificate,
        issuerCert: X509Certificate,
        context: CertificateValidationContext
    ) {
        validateCrlIntegrity(crl, issuerCert, context)
        validateCrlExtensions(crl)
        validateIssuingDistributionPoint(crl, cert)
    }

    private fun checkRevocationInCrls(
        crls: List<CertificateList>,
        cert: X509Certificate,
        context: CertificateValidationContext
    ) {
        val serial = cert.tbsCertificate.serialNumber

        for (crl in crls) {

            val entry = crl.tbsCertList.revokedCertificates
                ?.find { it.certSerialNumber.contentEquals(serial) }
                ?: continue

            validateCrlEntryExtensions(entry)

            val reason = getReasonCode(entry) ?: CRLReason.UNSPECIFIED

            if (reason == CRLReason.REMOVE_FROM_CRL) continue

            val coveredReasons = getCoveredReasons(crl, cert)

            if (reason !in coveredReasons) {
                continue
            }

            val revocationDate = entry.revocationTime.instant
            if (revocationDate <= context.date) {
                throw CertificateException(
                    "Certificate revoked. Reason: $reason"
                )
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
            ?.let { ReasonFlag.parseReasons(it) }
            ?: return CRLReason.entries.toSet()

        return restricted.map {
            when (it) {
                ReasonFlag.UNSPECIFIED -> CRLReason.UNSPECIFIED
                ReasonFlag.KEY_COMPROMISE -> CRLReason.KEY_COMPROMISE
                ReasonFlag.CA_COMPROMISE -> CRLReason.CA_COMPROMISE
                ReasonFlag.AFFILIATION_CHANGED -> CRLReason.AFFILIATION_CHANGED
                ReasonFlag.SUPERSEDED -> CRLReason.SUPERSEDED
                ReasonFlag.CESSATION_OF_OPERATION -> CRLReason.CESSATION_OF_OPERATION
                ReasonFlag.CERTIFICATE_HOLD -> CRLReason.CERTIFICATE_HOLD
                ReasonFlag.PRIVILEGE_WITHDRAWN -> CRLReason.PRIVILEGE_WITHDRAWN
                ReasonFlag.AA_COMPROMISE -> CRLReason.AA_COMPROMISE
            }
        }.toSet()
    }

    private suspend fun validateCrlIntegrity(
        crl: CertificateList,
        issuerCert: X509Certificate,
        context: CertificateValidationContext
    ) {
        val now = context.date

        if (now < crl.tbsCertList.thisUpdate.instant) {
            throw CertificateException("CRL not yet valid")
        }

        crl.tbsCertList.nextUpdate?.instant?.let {
            if (now > it) throw CertificateException("CRL expired")
        }

        if (crl.tbsCertList.issuer != issuerCert.tbsCertificate.subjectName) {
            throw CertificateException("CRL issuer mismatch")
        }

        val publicKey = issuerCert.decodedPublicKey.getOrNull()
            ?: throw CertificateException("Missing public key")

        val sigAlg = crl.signatureAlgorithm as? X509SignatureAlgorithm
            ?: throw CertificateException("Invalid signature algorithm")

        val verified = sigAlg.verifierFor(publicKey)
            .getOrThrow()
            .verify(
                crl.tbsCertList.encodeToDer(),
                crl.decodedSignature.getOrThrow()
            ).isSuccess

        if (!verified) throw CertificateException("Invalid CRL signature")
    }

    private fun validateIssuingDistributionPoint(crl: CertificateList, cert: X509Certificate) {
        val issuingDistPoint = crl.findExtension<IssuingDistributionPointExtension>() ?: return
        val isCa = cert.findExtension<BasicConstraintsExtension>()?.ca ?: false

        if (issuingDistPoint.onlyContainsUserCerts && isCa) {
            throw CertificateException("CRL only contains user certs, but cert is a CA")
        }
        if (issuingDistPoint.onlyContainsCACerts && !isCa) {
            throw CertificateException("CRL only contains CA certs, but cert is an end-entity")
        }

        if (issuingDistPoint.onlyContainsAttributeCerts) {
            throw CertificateException(
                "CRL only contains attribute certificates and cannot be used for X.509 certificates"
            )
        }

        if (issuingDistPoint.indirectCRL) {
            if (crl.tbsCertList.issuer != cert.tbsCertificate.issuerName) {
                throw CertificateException("True Indirect CRLs (different issuer) not supported")
            }
        }

        val idpName = issuingDistPoint.distributionPointName ?: return

        val certDpExtension = cert.findExtension<CRLDistributionPointsExtension>()
            ?: throw CertificateException("CRL has restricted scope (IDP), but Certificate has no CDP extension")

        val matchFound = certDpExtension.distributionPoints.any { certDp ->
            val namesMatch = matchesDistributionPointNames(idpName,certDp.distributionPointName, crl)

            val issuerMatches = if (certDp.crlIssuer != null) {
                val expectedIssuer = when (certDp.crlIssuer!!.name.type) {
                    GeneralNameOption.NameType.DIRECTORY -> certDp.crlIssuer!!.name
                    else -> null
                }
                crl.tbsCertList.issuer == expectedIssuer
            } else {
                crl.tbsCertList.issuer == cert.tbsCertificate.issuerName
            }
            namesMatch && issuerMatches
        }

        if (!matchFound) {
            throw CertificateException("CRL IssuingDistributionPoint name does not match any name in Certificate CDP")
        }
    }

    private fun validateCrlExtensions(crl: CertificateList) {
        crl.tbsCertList.extensions?.forEach {
            if (it.critical && !isSupportedCrlExtension(it.oid)) {
                throw CertificateException("Unsupported CRL extension: ${it.oid}")
            }
        }
    }

    private fun validateCrlEntryExtensions(entry: CRLEntry) {
        entry.crlEntryExtensions?.forEach {
            if (it.critical && !isSupportedEntryExtension(it.oid)) {
                throw CertificateException("Unsupported CRL entry extension: ${it.oid}")
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
private fun generalNamesMatch(a: GeneralName, b: GeneralName): Boolean {
    if (a.name.type != b.name.type) return false

    return when (a.name.type) {
        GeneralNameOption.NameType.DIRECTORY -> {
            val aName = a.name as X500Name
            val bName = b.name as X500Name

            aName.constrains(bName) == GeneralNameOption.ConstraintResult.MATCH
        }

        else -> {
            a == b
        }
    }
}

fun matchesDistributionPointNames(
    idpName: DistributionPointName,
    cdpName: DistributionPointName?,
    crl: CertificateList
): Boolean {

    if (cdpName == null) return false

    val crlIssuer = crl.tbsCertList.issuer

    return when (idpName) {

        is DistributionPointName.FullName -> {
            when (cdpName) {

                is DistributionPointName.FullName -> {
                    idpName.names.any { idpGn ->
                        cdpName.names.any { cdpGn ->
                            generalNamesMatch(idpGn, cdpGn)
                        }
                    }
                }

                is DistributionPointName.NameRelativeToCrlIssuer -> {
                    val resolved = resolveRelativeToFullName(cdpName, crlIssuer)

                    idpName.names.any { idpGn ->
                        generalNamesMatch(idpGn, resolved)
                    }
                }
            }
        }

        is DistributionPointName.NameRelativeToCrlIssuer -> {
            when (cdpName) {

                is DistributionPointName.NameRelativeToCrlIssuer -> {
                    idpName.name == cdpName.name
                }

                is DistributionPointName.FullName -> {
                    val resolved = resolveRelativeToFullName(idpName, crlIssuer)

                    cdpName.names.any { cdpGn ->
                        generalNamesMatch(resolved, cdpGn)
                    }
                }
            }
        }
    }
}

private fun resolveRelativeToFullName(
    relative: DistributionPointName.NameRelativeToCrlIssuer,
    issuer: X500Name
): GeneralName {

    val newRdns = issuer.relativeDistinguishedNames + RelativeDistinguishedName(
        listOf(relative.name)
    )

    val fullName = X500Name(newRdns)

    return GeneralName(fullName)
}

