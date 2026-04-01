package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.DigestAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ocsp
import at.asitplus.signum.indispensable.asn1.ocspSigning
import at.asitplus.signum.indispensable.pki.BasicOCSPResponse
import at.asitplus.signum.indispensable.pki.CertId
import at.asitplus.signum.indispensable.pki.OCSPRequest
import at.asitplus.signum.indispensable.pki.OCSPResponse
import at.asitplus.signum.indispensable.pki.SingleRequest
import at.asitplus.signum.indispensable.pki.SingleResponse
import at.asitplus.signum.indispensable.pki.TbsRequest
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.generalNames.UriName
import at.asitplus.signum.indispensable.pki.pkiExtensions.AuthorityInfoAccessExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.ExtendedKeyUsageExtension
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import kotlin.time.Clock

class OCSPRevocationValidator(
    private val provider: OcspProvider = HttpOCSPProvider()
): CertificateChainValidator {

    @ExperimentalPkiApi
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
            val issuerCert = processingChain[currentCertIndex + 1]
            val ocspUrl = extractOcspUrl(currCert) ?: "http://127.0.0.1:2560"
            val certId = buildCertId(currCert, issuerCert)
            val request = buildOcspRequest(certId)

            val responseBody = provider.fetchOcspResponse(ocspUrl, request)

            val ocspResponse = parseOcspResponse(responseBody)

            val basicResponse = ocspResponse.responseBytes?.basicOCSPResponse
                ?: throw Throwable("No basic response data")

            verifyResponseSignature(basicResponse, issuerCert)

            val singleResponse = basicResponse.tbsResponseData.responses.firstOrNull { it.certId == certId }
                ?: throw Throwable("Responder did not include status for the requested certificate")

            val now = Clock.System.now()
            if (singleResponse.thisUpdate.instant > now) throw Throwable("Response is not yet valid")
            singleResponse.nextUpdate?.let {
                if (it.instant < now) throw Throwable("OCSP response has expired")
            }

            when (singleResponse.certStatus) {
                SingleResponse.CertStatus.GOOD -> { /* Continue */ }
                SingleResponse.CertStatus.REVOKED -> throw Throwable("Certificate is REVOKED")
                SingleResponse.CertStatus.UNKNOWN -> throw Throwable("Certificate status UNKNOWN")
            }

            currentCertIndex++
        }

        return emptyMap()
    }

    fun extractOcspUrl(cert: X509Certificate): String? {
        val aia = cert.findExtension<AuthorityInfoAccessExtension>() ?: return null

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

    fun buildOcspRequest(certId: CertId): OCSPRequest {
        val singleRequest = SingleRequest(
            reqCert = certId,
            singleRequestExtensions = null
        )

        val tbsRequest = TbsRequest(
            version = 0,
            requestorName = null,
            requestList = listOf(singleRequest),
            requestExtensions = null
        )

        return OCSPRequest(
            tbsRequest = tbsRequest,
            rawSignature = null
        )
    }

    fun parseOcspResponse(bytes: ByteArray): OCSPResponse {
        val response = OCSPResponse.decodeFromDer(bytes)

        if (response.status != OCSPResponse.OCSPResponseStatus.SUCCESSFUL) {
            throw CertificateException("OCSP error: ${response.status}")
        }

        return response
    }

    suspend fun verifyResponseSignature(
        basicResponse: BasicOCSPResponse,
        issuerCert: X509Certificate
    ) {
        val responderCert = if (basicResponse.certs.isNullOrEmpty()) {
            issuerCert
        } else {
            val candidate = basicResponse.certs?.first()

            if (!candidate?.tbsCertificate?.serialNumber.contentEquals(issuerCert.tbsCertificate.serialNumber)) {
                verifyDelegatedResponder(candidate!!, issuerCert)
            }
            candidate
        }

        val publicKey = responderCert?.decodedPublicKey?.getOrThrow()
        val sigAlg = basicResponse.signatureAlgorithm as X509SignatureAlgorithm
        val verifier = sigAlg.verifierFor(publicKey!!).getOrThrow()

        // 3. Perform Verification on tbsResponseData
        val dataToVerify = basicResponse.tbsResponseData.encodeToTlv().derEncoded
        val signature = basicResponse.decodedSignature.getOrThrow()

        if (!verifier.verify(dataToVerify, signature).isSuccess) {
            throw Throwable("OCSP Response signature verification failed.")
        }
    }

    suspend fun verifyDelegatedResponder(responderCert: X509Certificate, issuerCert: X509Certificate) {
        val sigAlg = responderCert.signatureAlgorithm as X509SignatureAlgorithm
        val verifier = sigAlg.verifierFor(issuerCert.decodedPublicKey.getOrThrow()).getOrThrow()

        if (!verifier.verify(responderCert.tbsCertificate.encodeToDer(), responderCert.decodedSignature.getOrThrow()).isSuccess) {
            throw CertificateException("Delegated OCSP responder certificate was not signed by the CA.")
        }

        val eku = responderCert.findExtension<ExtendedKeyUsageExtension>()
            ?: throw CertificateException("Delegated OCSP responder missing Extended Key Usage extension.")

        val isAuthorized = eku.keyUsages.any { it == KnownOIDs.ocspSigning }
        if (!isAuthorized) {
            throw CertificateException("Responder certificate is not authorized for OCSP signing (missing id-kp-OCSPSigning).")
        }
    }
}