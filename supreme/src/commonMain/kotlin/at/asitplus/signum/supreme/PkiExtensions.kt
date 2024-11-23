package at.asitplus.signum.supreme

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.KeyType
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.sign.Signer

/**
 * Shorthand helper to create an [X509Certificate] by signing [tbsCertificate]
 */
suspend inline fun <reified K: KeyType>Signer<K>.sign(tbsCertificate: TbsCertificate<K>): KmmResult<X509Certificate<K>> {
    val toX509SignatureAlgorithm =
        this.signatureAlgorithm.toX509SignatureAlgorithm().getOrElse { return KmmResult.failure(it) }
    if (toX509SignatureAlgorithm != tbsCertificate.signatureAlgorithm)
        return KmmResult.failure(Asn1StructuralException("The signer's signature algorithm does not match the TbsCertificate's."))
    return sign(tbsCertificate.encodeToDer()).asKmmResult().map {
        X509Certificate<K>(tbsCertificate, tbsCertificate.signatureAlgorithm, it)
    }
}

/**
 * Shorthand helper to create a [Pkcs10CertificationRequest] by signing [tbsCsr]
 */
suspend inline fun <reified K: KeyType>Signer<K>.sign(tbsCsr: TbsCertificationRequest<K>): KmmResult<Pkcs10CertificationRequest<K>> {
    val toX509SignatureAlgorithm =
        this.signatureAlgorithm.toX509SignatureAlgorithm().getOrElse { return KmmResult.failure(it) }
    if (!tbsCsr.publicKey.equalsCryptographically(this.publicKey))
        return KmmResult.failure(Asn1StructuralException("The signer's public key does not match the TbsCSR's."))
    return sign(tbsCsr.encodeToDer()).asKmmResult().map {
        Pkcs10CertificationRequest<K>(tbsCsr, toX509SignatureAlgorithm, it)
    }
}