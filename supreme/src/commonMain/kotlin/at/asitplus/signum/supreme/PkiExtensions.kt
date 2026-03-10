package at.asitplus.signum.supreme

import at.asitplus.KmmResult
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificateInfo
import at.asitplus.signum.indispensable.pki.CertificationRequest
import at.asitplus.signum.indispensable.pki.CertificationRequestInfo
import at.asitplus.signum.indispensable.toSignatureAlgorithmIdentifier
import at.asitplus.signum.supreme.sign.Signer

/**
 * Shorthand helper to create a [Certificate] by signing [tbsCertificate]
 */
suspend fun Signer.sign(tbsCertificate: CertificateInfo): KmmResult<Certificate> {
    val signatureAlgorithm =
        this.signatureAlgorithm.toSignatureAlgorithmIdentifier().getOrElse { return KmmResult.failure(it) }
    if (signatureAlgorithm != tbsCertificate.signatureAlgorithm)
        return KmmResult.failure(Asn1StructuralException("The signer's signature algorithm does not match the TbsCertificate's."))
    return sign(tbsCertificate.encodeToDer()).asKmmResult().map {
        Certificate(tbsCertificate, signatureAlgorithm, it)
    }
}

/**
 * Shorthand helper to create a [CertificationRequest] by signing [tbsCsr]
 */
suspend fun Signer.sign(tbsCsr: CertificationRequestInfo): KmmResult<CertificationRequest> {
    val signatureAlgorithm =
        this.signatureAlgorithm.toSignatureAlgorithmIdentifier().getOrElse { return KmmResult.failure(it) }
    if (!tbsCsr.publicKey.equalsCryptographically(this.publicKey))
        return KmmResult.failure(Asn1StructuralException("The signer's public key does not match the TbsCSR's."))
    return sign(tbsCsr.encodeToDer()).asKmmResult().map {
        CertificationRequest(tbsCsr, signatureAlgorithm, it)
    }
}
