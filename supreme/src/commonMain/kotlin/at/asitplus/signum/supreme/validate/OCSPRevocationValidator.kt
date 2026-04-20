package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.OCSPCertRevokedException
import at.asitplus.signum.OCSPCertUnknownException
import at.asitplus.signum.OCSPDelegatedResponderException
import at.asitplus.signum.OCSPExpiredException
import at.asitplus.signum.OCSPMissingAiaExtensionException
import at.asitplus.signum.OCSPMissingBasicResponseException
import at.asitplus.signum.OCSPMissingOcspUrlException
import at.asitplus.signum.OCSPNoMatchingResponseException
import at.asitplus.signum.OCSPNonceMismatchException
import at.asitplus.signum.OCSPNotYetValidException
import at.asitplus.signum.OCSPResponderMismatchException
import at.asitplus.signum.OCSPResponseSignatureException
import at.asitplus.signum.OCSPStatusException
import at.asitplus.signum.OCSPUnauthorizedResponderException
import at.asitplus.signum.OCSPUnsupportedCriticalExtensionException
import at.asitplus.signum.OCSPUnsupportedVersionException
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.DigestAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.authorityInfoAccess
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.ocsp
import at.asitplus.signum.indispensable.asn1.ocspNonce
import at.asitplus.signum.indispensable.asn1.ocspSigning
import at.asitplus.signum.indispensable.pki.BasicOCSPResponse
import at.asitplus.signum.indispensable.pki.CertId
import at.asitplus.signum.indispensable.pki.OCSPRequest
import at.asitplus.signum.indispensable.pki.OCSPResponse
import at.asitplus.signum.indispensable.pki.SingleRequest
import at.asitplus.signum.indispensable.pki.SingleResponse
import at.asitplus.signum.indispensable.pki.TbsRequest
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.pki.generalNames.UriName
import at.asitplus.signum.indispensable.pki.pkiExtensions.AuthorityInfoAccessExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.ExtendedKeyUsageExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.OCSPNonceExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.SubjectKeyIdentifierExtension
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * OCSP revocation validator
 */
class OCSPRevocationValidator(
    private val provider: OcspProvider = HttpOCSPProvider(),
): CertificateChainValidator {

    private val DEFAULT_NONCE_BYTES = 16
    private val MAX_CLOCK_SKEW = 15.minutes

    @ExperimentalPkiApi
    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        if (!context.supportRevocationChecking) return emptyMap()
        var currentCertIndex = 0
        val checkedCriticalExtensions = mutableMapOf<X509Certificate, MutableSet<ObjectIdentifier>>()
        val processingChain = anchoredChain.trustAnchor.cert?.let { anchoredChain.chain + it }
            ?: anchoredChain.chain

        for (currCert in processingChain.dropLast(1)) {
            checkedCriticalExtensions
                .getOrPut(currCert) { mutableSetOf() }
                .add(KnownOIDs.authorityInfoAccess)

            val issuerCert = processingChain[currentCertIndex + 1]
            val ocspUrl = extractOcspUrl(currCert) ?: throw OCSPMissingOcspUrlException("No OCSP URL found in AIA extension")
            val certId = buildCertId(currCert, issuerCert)
            val nonce = generateNonce()
            val request = buildOcspRequest(certId, nonce)
            val responseBody = provider.fetchOcspResponse(ocspUrl, request)

            val basicResponse = parseOcspResponse(responseBody).responseBytes?.basicOCSPResponse
                ?: throw OCSPMissingBasicResponseException("No basic response data")

            verifyResponseSignature(basicResponse, issuerCert)
            verifyCriticalExtensions(basicResponse.tbsResponseData.responsesExtensions)
            verifyOcspResponseVersion(basicResponse)
            verifyNonce(basicResponse, nonce)

            val singleResponse = basicResponse.tbsResponseData.responses.firstOrNull { it.certId == certId }
                ?: throw OCSPNoMatchingResponseException("Responder did not include status for the requested certificate")

            verifyCriticalExtensions(singleResponse.singleExtensions)
            verifyResponseTime(singleResponse, context.date)

            when (singleResponse.certStatus) {
                SingleResponse.CertStatus.GOOD -> Unit
                SingleResponse.CertStatus.REVOKED -> throw OCSPCertRevokedException("Certificate is REVOKED")
                SingleResponse.CertStatus.UNKNOWN -> throw OCSPCertUnknownException("Certificate status UNKNOWN")
            }

            currentCertIndex++
        }

        return checkedCriticalExtensions
    }

    fun extractOcspUrl(cert: X509Certificate): String? {
        val aia = cert.findExtension<AuthorityInfoAccessExtension>() ?: throw OCSPMissingAiaExtensionException(
            "Missing Authority Info Access extension"
        )

        return aia.accessDescriptions.firstOrNull {
            it.accessMethod == KnownOIDs.ocsp
        }?.accessLocation?.let { (it.name as UriName).toString() }
    }

    suspend fun buildCertId(cert: X509Certificate, issuer: X509Certificate): CertId {
        return CertId(
            hashAlgorithms = DigestAlgorithm.SHA1,
            issuerNameHash = Digest.SHA1.digest(issuer.tbsCertificate.subjectName.encodeToDer()),
            issuerKeyHash = Digest.SHA1.digest(issuer.decodedPublicKey.getOrThrow().iosEncoded),
            serialNumber = cert.tbsCertificate.serialNumber
        )
    }

    fun buildOcspRequest(certId: CertId, nonce: ByteArray): OCSPRequest {
        val nonceExt = OCSPNonceExtension(
            oid = KnownOIDs.ocspNonce,
            critical = false,
            value = Asn1EncapsulatingOctetString(
                listOf(Asn1.OctetString(nonce))
            ),
            nonce = nonce
        )

        val singleRequest = SingleRequest(
            reqCert = certId,
            singleRequestExtensions = null
        )

        val tbsRequest = TbsRequest(
            version = 0,
            requestorName = null,
            requestList = listOf(singleRequest),
            requestExtensions = listOf(nonceExt)
        )

        return OCSPRequest(
            tbsRequest = tbsRequest,
            rawSignature = null
        )
    }

    fun parseOcspResponse(bytes: ByteArray): OCSPResponse {
        val response = OCSPResponse.decodeFromDer(bytes)

        if (response.status != OCSPResponse.OCSPResponseStatus.SUCCESSFUL) {
            throw OCSPStatusException("OCSP error: ${response.status}")
        }

        return response
    }

    fun verifyResponseTime(
        response: SingleResponse,
        validationDate: Instant
    ) {
        val nowPlusSkew = validationDate + MAX_CLOCK_SKEW
        val nowMinusSkew = validationDate - MAX_CLOCK_SKEW

        val thisUpdate = response.thisUpdate.instant

        val upperBound =
            response.nextUpdate?.instant?.let {
                if (it > thisUpdate) it else thisUpdate
            } ?: thisUpdate

        if (nowPlusSkew < thisUpdate) {
            throw OCSPNotYetValidException(
                "OCSP response is not yet valid"
            )
        }

        if (nowMinusSkew > upperBound) {
            throw OCSPExpiredException(
                "OCSP response has expired"
            )
        }
    }


    suspend fun verifyResponseSignature(
        basicResponse: BasicOCSPResponse,
        issuerCert: X509Certificate
    ) {
        val responderCert = basicResponse.certs?.firstOrNull()?.let { candidate ->
            if (!candidate.tbsCertificate.serialNumber
                    .contentEquals(issuerCert.tbsCertificate.serialNumber)
            ) {
                verifyDelegatedResponder(candidate, issuerCert)
            }
            candidate
        } ?: issuerCert

        verifyResponderId(basicResponse, responderCert)

        val publicKey = responderCert.decodedPublicKey.getOrThrow()
        val sigAlg = basicResponse.signatureAlgorithm as X509SignatureAlgorithm
        val verifier = sigAlg.verifierFor(publicKey).getOrThrow()

        val dataToVerify = basicResponse.tbsResponseData.encodeToDer()
        val signature = basicResponse.decodedSignature.getOrThrow()

        if (!verifier.verify(dataToVerify, signature).isSuccess) {
            throw OCSPResponseSignatureException("OCSP Response signature verification failed.")
        }
    }

    suspend fun verifyDelegatedResponder(responderCert: X509Certificate, issuerCert: X509Certificate) {
        val sigAlg = responderCert.signatureAlgorithm as X509SignatureAlgorithm
        val verifier = sigAlg.verifierFor(issuerCert.decodedPublicKey.getOrThrow()).getOrThrow()

        if (!verifier.verify(responderCert.tbsCertificate.encodeToDer(), responderCert.decodedSignature.getOrThrow()).isSuccess) {
            throw OCSPDelegatedResponderException("Delegated OCSP responder certificate was not signed by the CA.")
        }

        val issuerInChildPrincipal = responderCert.tbsCertificate.issuerName
        val subjectInIssuerPrincipal = issuerCert.tbsCertificate.subjectName
        if (issuerInChildPrincipal != subjectInIssuerPrincipal) {
            throw OCSPResponderMismatchException("Subject of issuer cert and issuer of child certificate mismatch.")
        }

        val eku = responderCert.findExtension<ExtendedKeyUsageExtension>()
            ?: throw OCSPUnauthorizedResponderException("Delegated OCSP responder missing Extended Key Usage extension.")

        val isAuthorized = eku.keyUsages.any { it == KnownOIDs.ocspSigning }
        if (!isAuthorized) {
            throw OCSPUnauthorizedResponderException("Responder certificate is not authorized for OCSP signing (missing id-kp-OCSPSigning).")
        }
    }

    suspend fun verifyResponderId(
        basicResponse: BasicOCSPResponse,
        responderCert: X509Certificate
    ) {
        val responderId = basicResponse.tbsResponseData.responderID

        val matches = when {
            responderId.byName != null -> {
                responderCert.tbsCertificate.subjectName.relativeDistinguishedNames == responderId.byName
            }

            responderId.byKey != null -> {
                val skid = responderCert.findExtension<SubjectKeyIdentifierExtension>()
                    ?.keyIdentifier

                val matchesSkid =
                    skid?.contentEquals(responderId.byKey) == true

                val matchesDerived =
                    Digest.SHA1.digest(
                        responderCert.decodedPublicKey.getOrThrow().iosEncoded
                    ).contentEquals(responderId.byKey)

                matchesSkid || matchesDerived
            }

            else -> false
        }

        if (!matches) {
            throw OCSPResponderMismatchException("OCSP responder ID does not match signing certificate")
        }
    }

    fun verifyCriticalExtensions(
        extensions: List<X509CertificateExtension>?
    ) {
        val unsupported = extensions
            ?.firstOrNull { it.critical && it.oid !in X509CertificateExtension.registeredExtensionDecoders }

        if (unsupported != null) {
            throw OCSPUnsupportedCriticalExtensionException(
                "Unsupported CRITICAL OCSP extension: ${unsupported.oid}"
            )
        }
    }

    fun verifyOcspResponseVersion(basicResponse: BasicOCSPResponse) {
        basicResponse.tbsResponseData.version?.let { version ->
            if (version != 0) {
                throw OCSPUnsupportedVersionException(
                    "Unsupported OCSP response version: $version"
                )
            }
        }
    }

    private fun generateNonce(): ByteArray {
        return Random.Default.nextBytes(DEFAULT_NONCE_BYTES)
    }

    fun verifyNonce(
        basicResponse: BasicOCSPResponse,
        requestNonce: ByteArray
    ) {
        val responseNonce = basicResponse.tbsResponseData.responsesExtensions
            ?.filterIsInstance<OCSPNonceExtension>()
            ?.firstOrNull()
            ?.nonce

        if (responseNonce != null &&
            !responseNonce.contentEquals(requestNonce)) {
            throw OCSPNonceMismatchException("OCSP nonce mismatch")
        }
    }
}