package at.asitplus.signum.supreme

import at.asitplus.KmmResult
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.indispensable.integrity.SignatureVerifier
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.supreme.sign.Signer

/**
 * Shorthand helper to create an [Certificate] by signing [tbsCertificate]
 */
suspend fun Signer.sign(tbsCertificate: TbsCertificate): Certificate {
    if (signatureAlgorithm != tbsCertificate.signatureAlgorithm)
        throw Asn1StructuralException("The signer's signature algorithm does not match the TbsCertificate's.")
    return Certificate(
        tbsCertificate = tbsCertificate,
        signature = sign(tbsCertificate.encodeToDer()).signature)
}

/**
 * Shorthand helper to create a [CertificationRequest] by signing [tbsCsr]
 */
suspend fun Signer.sign(tbsCsr: TbsCertificationRequest): CertificationRequest {
    if (!tbsCsr.publicKey.equalsCryptographically(this.publicKey))
        throw Asn1StructuralException("The signer's public key does not match the TbsCSR's.")
    return CertificationRequest(
        tbsCsr = tbsCsr, signatureAlgorithm = signatureAlgorithm,
        signature = sign(tbsCsr.encodeToDer()).signature)
}

suspend inline fun <reified T> SignatureVerifier.verify(input: DerEncodable<T>, signature: CryptoSignature) =
    verify(input.encodeToDer(), signature)

suspend fun SignatureVerifier.verify(input: Certificate): KmmResult<SignatureVerifier.Success> {
    require(this.signatureAlgorithm == input.signatureAlgorithm)
    return verify(input.tbsCertificate, input.signature)
}

suspend fun SignatureVerifier.verify(input: CertificationRequest): KmmResult<SignatureVerifier.Success> {
    require(this.signatureAlgorithm == input.signatureAlgorithm)
    return verify(input.tbsCsr, input.signature)
}
