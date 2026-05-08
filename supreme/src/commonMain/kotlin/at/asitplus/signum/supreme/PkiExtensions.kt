package at.asitplus.signum.supreme

import at.asitplus.KmmResult
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.catching
import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.indispensable.pki.CertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.sign.Signer

/**
 * Shorthand helper to create an [X509Certificate] by signing [tbsCertificate]
 */
suspend fun Signer.sign(tbsCertificate: TbsCertificate): KmmResult<X509Certificate> = catching {
    val sigAlgMatch = signatureAlgorithm == tbsCertificate.signatureAlgorithm

    if (!sigAlgMatch) throw Asn1StructuralException("The signer's signature algorithm does not match the TbsCertificate's.")
    val encoded = tbsCertificate.encodeToDer()
    X509Certificate(tbsCertificate = tbsCertificate, signature = sign(encoded).signature)
}

/**
 * Shorthand helper to create a [CertificationRequest] by signing [tbsCsr]
 */
suspend fun Signer.sign(tbsCsr: TbsCertificationRequest): KmmResult<CertificationRequest> = catching {
    if (!tbsCsr.publicKey.equalsCryptographically(this.publicKey))
        throw Asn1StructuralException("The signer's public key does not match the TbsCSR's.")
    CertificationRequest(tbsCsr = tbsCsr, signatureAlgorithm = signatureAlgorithm, sign(tbsCsr.encodeToDer()).signature)
}