package at.asitplus.signum.indispensable.pki

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.asn1.PemDecodable
import at.asitplus.signum.indispensable.asn1.PemEncodable
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decode
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.runRethrowing
import at.asitplus.signum.indispensable.pki.TbsCertList.Companion.Tags.EXTENSIONS
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

/**
 * TBSCertList
 * The structure that gets signed
 */
data class TbsCertList @Throws(Asn1Exception::class) constructor(
    val version: Int? = 2,
    val signature: X509SignatureAlgorithm,
    val issuer: List<RelativeDistinguishedName>,
    val thisUpdate: Asn1Time,
    val nextUpdate: Asn1Time,
    val revokedCertificates: List<CRLEntry>?,
    val extensions: List<X509CertificateExtension>? = null
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        version?.let { +Asn1.Int(version) }
        +signature
        +Asn1.Sequence { issuer.forEach { +it } }
        +thisUpdate
        +nextUpdate

        revokedCertificates?.let {
            if (it.isNotEmpty()) {
                +Asn1.Sequence {
                    it.forEach { revCert -> +revCert }
                }
            }
        }

        extensions?.let {
            if (it.isNotEmpty()) {
                +Asn1.ExplicitlyTagged(EXTENSIONS.tagValue) {
                    +Asn1.Sequence {
                        it.forEach { ext -> +ext }
                    }
                }
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as TbsCertList

        if (version != other.version) return false
        if (signature != other.signature) return false
        if (issuer != other.issuer) return false
        if (thisUpdate != other.thisUpdate) return false
        if (nextUpdate != other.nextUpdate) return false
        if (revokedCertificates != other.revokedCertificates) return false
        if (extensions != other.extensions) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version ?: 0
        result = 31 * result + signature.hashCode()
        result = 31 * result + issuer.hashCode()
        result = 31 * result + thisUpdate.hashCode()
        result = 31 * result + nextUpdate.hashCode()
        result = 31 * result + revokedCertificates.hashCode()
        result = 31 * result + (extensions?.hashCode() ?: 0)
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsCertList> {

        object Tags {
            val EXTENSIONS = Asn1.ExplicitTag(0uL)
        }

        override fun doDecode(src: Asn1Sequence): TbsCertList = runRethrowing {
            val version = src.peek().let {
                if (it is Asn1Primitive) {
                    (it.asPrimitive()).decodeToInt()
                        .also { src.nextChild() }
                } else {
                    null
                }
            }

            val sigAlg = X509SignatureAlgorithm.decodeFromTlv(src.nextChild().asSequence())
            val issuerNames = (src.nextChild().asSequence()).children.map {
                RelativeDistinguishedName.decodeFromTlv(it.asSet())
            }

            val thisUpdateTime = Asn1Time.decodeFromTlv(src.nextChild().asPrimitive())
            val nextUpdateTime = Asn1Time.decodeFromTlv(src.nextChild().asPrimitive())

            val certs = if (src.hasMoreChildren() && src.peek() is Asn1Sequence) {
                src.nextChild().asSequence().children.map {
                    CRLEntry.decodeFromTlv(it.asSequence())
                }
            } else null

            val extensions = if (src.hasMoreChildren()) {
                ((src.nextChild().asExplicitlyTagged()).verifyTag(EXTENSIONS.tagValue)
                    .single().asSequence()).children.map {
                    X509CertificateExtension.decodeFromTlv(it.asSequence())
                }
            } else null

            TbsCertList(
                version,
                sigAlg,
                issuerNames,
                thisUpdateTime,
                nextUpdateTime,
                certs,
                extensions
            )
        }
    }
}

/**
 * CRLEntry represents revoked certificate
 * */
data class CRLEntry @Throws(Asn1Exception::class) constructor(
    val certSerialNumber: ByteArray,
    val revocationTime: Asn1Time,
    val crlEntryExtensions: List<X509CertificateExtension>? = null
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence{
        +Asn1Primitive(Asn1Element.Tag.INT, certSerialNumber)
        +revocationTime

        crlEntryExtensions?.let {
            if (it.isNotEmpty()) {
                +Asn1.Sequence {
                    it.forEach { ext -> +ext }
                }
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CRLEntry

        if (!certSerialNumber.contentEquals(other.certSerialNumber)) return false
        if (revocationTime != other.revocationTime) return false
        if (crlEntryExtensions != other.crlEntryExtensions) return false

        return true
    }

    override fun hashCode(): Int {
        var result = certSerialNumber.contentHashCode()
        result = 31 * result + revocationTime.hashCode()
        result = 31 * result + (crlEntryExtensions?.hashCode() ?: 0)
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, CRLEntry> {

        override fun doDecode(src: Asn1Sequence): CRLEntry = runRethrowing {
            val serialNumber = (src.nextChild().asPrimitive()).decode(Asn1Element.Tag.INT) { it }

            val revocationTime = Asn1Time.decodeFromTlv(src.nextChild().asPrimitive())

            val extensions = if (src.hasMoreChildren()) {
                src.nextChild().asSequence().children.map {
                    X509CertificateExtension.decodeFromTlv(it.asSequence())
                }
            } else null

            CRLEntry(
                serialNumber,
                revocationTime,
                extensions
            )
        }
    }
}

/**
 * X509 CRL (Certificate List)
 * */
data class CertificateList @Throws(Asn1Exception::class) constructor(
    val tbsCertList: TbsCertList,
    val signatureAlgorithm: X509SignatureAlgorithm,
    val signature: CryptoSignature
) : PemEncodable<Asn1Sequence> {

    override val canonicalPEMBoundary: String = EB_STRINGS.DEFAULT

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence{
        +tbsCertList
        +signatureAlgorithm
        +signature.x509Encoded
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CertificateList

        if (tbsCertList != other.tbsCertList) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCertList.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }

    companion object : PemDecodable<Asn1Sequence, CertificateList>(EB_STRINGS.DEFAULT) {

        private object EB_STRINGS {
            const val DEFAULT = "X509 CRL"
        }

        override fun doDecode(src: Asn1Sequence): CertificateList = runRethrowing {
            val tbsCertList = TbsCertList.decodeFromTlv(src.nextChild().asSequence())
            val sigAlg = X509SignatureAlgorithm.decodeFromTlv(src.nextChild().asSequence())
            val signature = CryptoSignature.fromX509Encoded(sigAlg, src.nextChild().asPrimitive())

            CertificateList(
                tbsCertList,
                sigAlg,
                signature
            )
        }

        /**
         * Tries to decode [src] into an [CertificateList], by parsing the bytes directly as ASN.1 structure,
         * or by decoding from Base64, or by decoding to a String, stripping PEM headers
         * (`-----BEGIN X509 CRL-----`) and then decoding from Base64.
         */
        fun decodeFromByteArray(src: ByteArray): CertificateList? = catchingUnwrapped {
            CertificateList.decodeFromTlv(Asn1Element.parse(src) as Asn1Sequence)
        }.getOrNull() ?: catchingUnwrapped {
            CertificateList.decodeFromTlv(Asn1Element.parse(src.decodeToByteArray(Base64())) as Asn1Sequence)
        }.getOrNull() ?: CertificateList.decodeFromPem(src.decodeToString()).getOrNull()
    }
}

