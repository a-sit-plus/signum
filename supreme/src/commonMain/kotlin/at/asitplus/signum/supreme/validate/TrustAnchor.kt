package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.X500Name
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify

/**
 * Represents a trusted certificate authority (TrustAnchor), which can be specified either
 * as an X509Certificate, or as a distinguished name (in RFC 2253 format) along with a public key.
 * */
class TrustAnchor private constructor(
    val publicKey: CryptoPublicKey,
    val principle: X500Name?,
    private val name: String?,
    val cert: X509Certificate?
) {
    constructor(cert: X509Certificate) : this(
        cert.decodedPublicKey.getOrThrow(),
        cert.tbsCertificate.subjectName,
        cert.tbsCertificate.subjectName.toRfc2253String(),
        cert
    )

    constructor(publicKey: CryptoPublicKey, principle: X500Name) : this(
        publicKey,
        principle,
        principle.toRfc2253String(),
        null
    )

    constructor(publicKey: CryptoPublicKey, name: String) : this(
        publicKey,
        null,
        name,
        null
    )

    fun isIssuerOf(cert: X509Certificate): Boolean {
        val verifier = (cert.signatureAlgorithm as X509SignatureAlgorithm).verifierFor(publicKey).getOrThrow()
        val signatureValid = verifier.verify(
            cert.tbsCertificate.encodeToDer(),
            cert.decodedSignature.getOrThrow()
        ).isSuccess

        val issuerName = cert.tbsCertificate.issuerName.toRfc2253String()
        return signatureValid && issuerName == name
    }
}