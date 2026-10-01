package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm

//Internal for testing
/** The X.509 structural representation retained by this prototype. */
internal object X509 : Encodable.Representation

val TbsCertificate.asn1Representation: X509TbsCertificate
    get() = representations[X509] as? X509TbsCertificate ?: run {
        runRethrowing {
            require(serialNumber.encodeToAsn1ContentBytes().size <= 20) {
                "Serial Number too long for X.509. Limit = 20 value octets"
            }
        }
        X509TbsCertificate(
            serialNumber = serialNumber,
            signatureAlgorithm = signatureAlgorithm.asn1Representation,
            issuerName = issuerName.requireX509().asn1Representation,
            validFrom = Asn1Time.SecondsCapped(validFrom),
            validUntil = Asn1Time.SecondsCapped(validUntil),
            subjectName = subjectName.requireX509().asn1Representation,
            subjectPublicKeyInfo = publicKey.asn1Representation,
            issuerUniqueID = issuerUniqueID?.let { Asn1BitString(BitSet(it)) },
            subjectUniqueID = subjectUniqueID?.let { Asn1BitString(BitSet(it)) },
            extensions = extensions.map { it.requireX509().asn1Representation },
        )
    }

operator fun TbsCertificate.Companion.invoke(src: X509TbsCertificate, der: Der = DER): TbsCertificate =
    TbsCertificate({ TbsCertificate.ContentContainer(
        serialNumber = src.serialNumber,
        signatureAlgorithm = SignatureAlgorithm.decodeFromTlv(src.signatureAlgorithm, der),
        issuerName = X500Name(src.issuerName.map(::RelativeDistinguishedName), false),
        validFrom = src.validity.validFrom.instant,
        validUntil = src.validity.validUntil.instant,
        subjectName = X500Name(src.subjectName.map(::RelativeDistinguishedName), false),
        publicKey = CryptoPublicKey.decodeFromTlv(src.subjectPublicKeyInfo, der),
        issuerUniqueID = src.issuerUniqueID?.toLsb0ByteArray(),
        subjectUniqueID = src.subjectUniqueID?.toLsb0ByteArray(),
        extensions = src.extensions?.map { CertificateExtension(it) }.orEmpty(),
    ) }, mapOf(X509 to src))

/** Existing X.509 consumers can still request the structural TLV directly. */
fun TbsCertificate.encodeToTlv(der: Der = DER): Asn1Element =
    der.encodeToTlv(X509TbsCertificate.serializer(), asn1Representation)

internal object TbsCertificateDerCodec : DerCodec<TbsCertificate> {
    override val type = TbsCertificate::class
    override fun encode(value: TbsCertificate, der: Der): ByteArray =
        value.encodeToTlv(der).derEncoded
    override fun decode(bytes: ByteArray, der: Der): TbsCertificate =
        TbsCertificate(der.decodeFromDer<X509TbsCertificate>(bytes), der)
}
