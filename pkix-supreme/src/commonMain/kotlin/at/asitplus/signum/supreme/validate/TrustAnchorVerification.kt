package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate
import at.asitplus.signum.indispensable.pki.TrustAnchor
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify

/**
 * Signature-verification behaviour for [TrustAnchor]. The anchor itself is a pure data type living
 * in `indispensable-pkix`; the actual crypto (verifying that [cert] is signed by this anchor's key)
 * is the supreme layer's job and therefore lives here as an extension.
 *
 * Returns `true` iff [cert]'s issuer matches this anchor's principal, the issuer/subject unique IDs
 * line up (for certificate-backed anchors), and [cert]'s signature verifies against the anchor key.
 */
suspend fun TrustAnchor.isIssuerOf(cert: X509Certificate): Boolean {
    if (cert.tbsCertificate.issuerName != principal) return false

    // If trust anchor is certificate based, check issuerUniqueID
    this.cert?.let { anchorCert ->
        if (!cert.tbsCertificate.issuerUniqueID.contentEquals(anchorCert.tbsCertificate.subjectUniqueID)) return false
    }

    val verifier = cert.signatureAlgorithm.verifierFor(publicKey).getOrElse { return false }

    return verifier.verify(
        cert.tbsCertificate.encodeToDer(),
        cert.signature
    ).isSuccess
}
