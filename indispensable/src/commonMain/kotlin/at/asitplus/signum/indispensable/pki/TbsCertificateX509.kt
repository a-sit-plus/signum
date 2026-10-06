package at.asitplus.signum.indispensable.pki
import at.asitplus.signum.indispensable.Encodable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.asn1Representation
import at.asitplus.signum.indispensable.sign.fromAsn1Representation
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm

/** The X.509 structural representation retained by this prototype. */
object X509 : Encodable.Representation

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
            issuerName = requireNotNull(issuerName.asn1Representation) { "Issuer has no X.509 representation" },
            validFrom = Asn1Time.SecondsCapped(validFrom),
            validUntil = Asn1Time.SecondsCapped(validUntil),
            subjectName = requireNotNull(subjectName.asn1Representation) { "Subject has no X.509 representation" },
            subjectPublicKeyInfo = publicKey.asn1Representation,
            issuerUniqueID = issuerUniqueID?.let { Asn1BitString(BitSet(it)) },
            subjectUniqueID = subjectUniqueID?.let { Asn1BitString(BitSet(it)) },
            extensions = extensions.map { it.asn1Representation
                ?: throw Asn1Exception("Certificate extension ${it.oid} has no X.509/DER representation") },
        )
    }

operator fun TbsCertificate.Companion.invoke(src: X509TbsCertificate): TbsCertificate =
    fromAsn1Representation(src)

/** Retains the original model; interpretation is deferred until semantic access. */
fun TbsCertificate.Companion.fromAsn1Representation(
    src: X509TbsCertificate,
): TbsCertificate =
    TbsCertificate(
        serialNumberProvider = { src.serialNumber },
        signatureAlgorithmProvider = { SignatureAlgorithm.fromAsn1Representation(src.signatureAlgorithm) },
        issuerNameProvider = { X500Name(src.issuerName.map { RelativeDistinguishedName(it) }, false) },
        validFromProvider = { src.validity.validFrom.instant },
        validUntilProvider = { src.validity.validUntil.instant },
        subjectNameProvider = { X500Name(src.subjectName.map { RelativeDistinguishedName(it) }, false) },
        publicKeyProvider = { CryptoPublicKey.fromAsn1Representation(src.subjectPublicKeyInfo) },
        issuerUniqueIDProvider = { src.issuerUniqueID?.toLsb0ByteArray() },
        subjectUniqueIDProvider = { src.subjectUniqueID?.toLsb0ByteArray() },
        extensionsProvider = { src.extensions?.map { CertificateExtension(it) }.orEmpty() },
        representations = mapOf(X509 to src),
    )
