package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate
import at.asitplus.signum.indispensable.pki.extn.NameConstraints

/**
 * Represents a trusted certificate authority (TrustAnchor), which can be specified either
 * as an [X509Certificate], or as a distinguished name along with a public key.
 *
 * Both forms supply trusted input to path validation; the certificate is not itself a path member:
 * [RFC 5280 6.1.1(d)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.1).
 * Certificate-form anchors also expose name constraints as initial inputs, a local policy allowed by
 * [RFC 6818 section 4](https://www.rfc-editor.org/rfc/rfc6818.html#section-4).
 * Extra anchor/issuance checks can be imposed by custom validators.
 *
 * This is the pure data model; the signature-verification behaviour (`isIssuerOf`) is provided as
 * an extension in `pkix-supreme`, mirroring the rest of the architecture (lean data here, crypto
 * heavy-lifting in the supreme layer).
 */
sealed class TrustAnchor {

    abstract val publicKey: CryptoPublicKey
    abstract val principal: Name?
    abstract val nameConstraints: NameConstraints?
    open val cert: X509Certificate? = null

    class Certificate(
        override val cert: X509Certificate
    ) : TrustAnchor() {

        override val publicKey: CryptoPublicKey = cert.publicKey

        override val principal: Name = cert.tbsCertificate.subjectName

        override val nameConstraints: NameConstraints? = cert.findExtension<NameConstraints>()
    }

    class PublicKey(
        override val publicKey: CryptoPublicKey,
        override val principal: Name?,
        override val nameConstraints: NameConstraints? = null
    ) : TrustAnchor() {

        @HazardousMaterials("Unnamed trust anchor: only use when a raw key truly makes sense.")
        constructor(publicKey: CryptoPublicKey) : this(publicKey, null)
    }

    fun matchesCertificate(cert: X509Certificate): Boolean {
        this.cert?.let { return it == cert }

        val sameKey = runCatching { this.publicKey == cert.publicKey }.getOrElse { false }
        //TODO: probably should not match on raw pubkey
        val samePrincipal = this.principal == cert.tbsCertificate.subjectName
        return sameKey && samePrincipal
    }
}
