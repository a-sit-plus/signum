package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.allDistinctByOids
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.asn1Representation

val Certificate.asn1Representation: X509Certificate
    get() = representations[X509] as? X509Certificate ?: X509Certificate(
        tbsCertificate.asn1Representation,
        signatureAlgorithm.asn1Representation,
        signature.asn1Representation,
    )

operator fun Certificate.Companion.invoke(src: X509Certificate): Certificate =
    fromAsn1Representation(src)

/** Validates and retains the original model without requiring a DER instance. */
fun Certificate.Companion.fromAsn1Representation(src: X509Certificate): Certificate {
    require(src.signatureAlgorithm == src.tbsCertificate.signatureAlgorithm) {
        "Inner TBS certificate signature algorithm ${src.tbsCertificate.signatureAlgorithm} != certificate outer " +
            "signature algorithm ${src.signatureAlgorithm}, that earns the whole certificate with serial " +
            "${src.tbsCertificate.serialNumber} a spot on my naughty list!"
    }
    require(src.tbsCertificate.extensions.orEmpty().allDistinctByOids()) {
        "Multiple extensions with the same OID found"
    }
    return Certificate(
        TbsCertificate.fromAsn1Representation(src.tbsCertificate),
        { CryptoSignature(src.signatureAlgorithm, src.signatureValue) },
        mapOf(X509 to src),
    )
}
