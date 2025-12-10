package at.asitplus.signum.supreme.validate

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.generalNames.X500Name
import at.asitplus.signum.indispensable.pki.pkiExtensions.NameConstraintsExtension
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify

/**
 * Represents a trusted certificate authority (TrustAnchor), which can be specified either
 * as an X509Certificate, or as a distinguished name (in RFC 2253 format) along with a public key.
 */
sealed class TrustAnchor {

    abstract val publicKey: CryptoPublicKey
    abstract val principal: X500Name?
    abstract val nameConstraints: NameConstraintsExtension?
    open val cert: X509Certificate? = null

    class Certificate(
        override val cert: X509Certificate
    ) : TrustAnchor() {

        override val publicKey: CryptoPublicKey = cert.decodedPublicKey.getOrThrow()

        override val principal: X500Name = cert.tbsCertificate.subjectName

        override val nameConstraints: NameConstraintsExtension? = cert.findExtension<NameConstraintsExtension>()
    }

    class PublicKey(
        override val publicKey: CryptoPublicKey,
        override val principal: X500Name?,
        override val nameConstraints: NameConstraintsExtension? = null
    ) : TrustAnchor() {

        @HazardousMaterials("Unnamed trust anchor: only use when a raw key truly makes sense.")
        constructor(publicKey: CryptoPublicKey) : this(publicKey, null)
    }

    fun isIssuerOf(cert: X509Certificate): Boolean {
        val verifier = (cert.signatureAlgorithm as X509SignatureAlgorithm).verifierFor(publicKey).getOrElse { return false }
        val signatureValid = verifier.verify(
            cert.tbsCertificate.encodeToDer(),
            cert.decodedSignature.getOrThrow()
        ).isSuccess

        val issuerName = cert.tbsCertificate.issuerName
        return signatureValid && issuerName == principal
    }
}