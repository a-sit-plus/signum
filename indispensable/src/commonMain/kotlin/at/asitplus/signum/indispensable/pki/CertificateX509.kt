package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.allDistinctByOids
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.signum.indispensable.*

val Certificate.asn1Representation: X509Certificate
    get() = representations[X509] as? X509Certificate ?: X509Certificate(
        tbsCertificate.asn1Representation,
        signatureAlgorithm.asn1Representation,
        signature.asn1Representation,
    )

operator fun Certificate.Companion.invoke(src: X509Certificate, der: Der = DER): Certificate {
    require(src.signatureAlgorithm == src.tbsCertificate.signatureAlgorithm) {
        "Inner TBS certificate signature algorithm ${src.tbsCertificate.signatureAlgorithm} != certificate outer " +
            "signature algorithm ${src.signatureAlgorithm}, that earns the whole certificate with serial " +
            "${src.tbsCertificate.serialNumber} a spot on my naughty list!"
    }
    require(src.tbsCertificate.extensions.orEmpty().allDistinctByOids()) {
        "Multiple extensions with the same OID found"
    }
    return Certificate(
        { TbsCertificate(src.tbsCertificate, der) },
        { CryptoSignature(src.signatureAlgorithm, src.signatureValue) },
        mapOf(X509 to src),
    )
}

internal object CertificateDerCodec : DerCodec<Certificate> {
    override val type = Certificate::class
    override fun encode(value: Certificate, der: Der): ByteArray = value.encodeToTlv(der).derEncoded
    override fun decode(bytes: ByteArray, der: Der): Certificate =
        Certificate(der.decodeFromDer<X509Certificate>(bytes), der)
}
