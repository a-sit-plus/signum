package at.asitplus.signum.supreme

import at.asitplus.KmmResult
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.indispensable.isKnown
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.sign.Signer

/**
 * Shorthand helper to create an [X509Certificate] by signing [tbsCertificate]
 */
suspend fun Signer.sign(tbsCertificate: TbsCertificate): KmmResult<X509Certificate> {
    val toX509SignatureAlgorithm =
        this.signatureAlgorithm.toX509SignatureAlgorithm().getOrElse { return KmmResult.failure(it) }
    val algorithm = tbsCertificate.signatureAlgorithm
    if(!algorithm.isKnown()) return KmmResult.failure(UnsupportedCryptoException("Signature algorithm not supported: ${algorithm.oid}"))
    if (toX509SignatureAlgorithm != algorithm)
        return KmmResult.failure(Asn1StructuralException("The signer's signature algorithm does not match the TbsCertificate's."))
    return sign(tbsCertificate.encodeToDer()).asKmmResult().map {
        X509Certificate(tbsCertificate, algorithm, it)
    }
}

/**
 * Shorthand helper to create a [Pkcs10CertificationRequest] by signing [tbsCsr]
 */
suspend fun Signer.sign(tbsCsr: TbsCertificationRequest): KmmResult<Pkcs10CertificationRequest> {
    val toX509SignatureAlgorithm =
        this.signatureAlgorithm.toX509SignatureAlgorithm().getOrElse { return KmmResult.failure(it) }
    if (!tbsCsr.publicKey.equalsCryptographically(this.publicKey))
        return KmmResult.failure(Asn1StructuralException("The signer's public key does not match the TbsCSR's."))
    return sign(tbsCsr.encodeToDer()).asKmmResult().map {
        Pkcs10CertificationRequest(tbsCsr, toX509SignatureAlgorithm, it)
    }
}