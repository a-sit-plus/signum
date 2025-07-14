package at.asitplus.signum.indispensable.pki

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.PemDecodable
import at.asitplus.signum.indispensable.asn1.PemEncodable
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.asn1.encoding.parse
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray


data class Request(
    val reqCert: CertId,
    val singleRequestExtensions: List<X509CertificateExtension>? = null
) : Asn1Encodable<Asn1Sequence> {

    init {
        if (singleRequestExtensions?.distinctBy { it.oid }?.size != singleRequestExtensions?.size) throw Asn1StructuralException("Multiple extensions with the same OID found")
    }

    override fun encodeToTlv() = Asn1.Sequence {
        +reqCert
        singleRequestExtensions?.let {
            if (it.isNotEmpty()) {
                +Asn1.ExplicitlyTagged(Tags.EXTENSIONS.tagValue) {
                    +Asn1.Sequence {
                        it.forEach { ext -> +ext }
                    }
                }
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, Request> {

        object Tags {
            val EXTENSIONS = Asn1.ExplicitTag(0uL)
        }

        override fun doDecode(src: Asn1Sequence): Request {
            val certId = CertId.decodeFromTlv(src.nextChild().asSequence())
            val extensions = if (src.hasMoreChildren()) {
                src.nextChild().asSequence().children.map {
                    X509CertificateExtension.decodeFromTlv(it.asSequence())
                }
            } else null
            return Request(certId, extensions)
        }
    }
}

data class TbsRequest(
    val version: Int? = 2,
    val requestorName: List<RelativeDistinguishedName>? = null,
    val requestList: List<Request>,
    val requestExtensions: List<X509CertificateExtension>? = null
) : Asn1Encodable<Asn1Sequence> {

    init {
        if (requestExtensions?.distinctBy { it.oid }?.size != requestExtensions?.size) throw Asn1StructuralException("Multiple extensions with the same OID found")
    }

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        version?.let { Asn1.ExplicitlyTagged(Tags.VERSION.tagValue) { +Asn1.Int(version) } }
        requestorName?.let {
            if (it.isNotEmpty()) {
                +Asn1.ExplicitlyTagged(Tags.GENERAL_NAME.tagValue) {
                    +Asn1.Sequence {
                        it.forEach { reqName -> +reqName }
                    }
                }
            }
        }
        +Asn1.Sequence { requestList.forEach { +it } }
        requestExtensions?.let {
            if (it.isNotEmpty()) {
                +Asn1.ExplicitlyTagged(Tags.EXTENSIONS.tagValue) {
                    +Asn1.Sequence {
                        it.forEach { ext -> +ext }
                    }
                }
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsRequest> {

        object Tags {
            val GENERAL_NAME = Asn1.ImplicitTag(1uL)
            val EXTENSIONS = Asn1.ExplicitTag(2uL)
            val VERSION = Asn1.ExplicitTag(0uL)
        }

        override fun doDecode(src: Asn1Sequence): TbsRequest {
            val version = src.peek().let {
                if (it is Asn1ExplicitlyTagged) {
                    (it.verifyTag(Tags.VERSION).single().asPrimitive()).decodeToInt()
                        .also { src.nextChild() }
                } else {
                    null
                }
            }

            val name = src.peek().let { it ->
                if (it is Asn1ExplicitlyTagged) {
                    (it.verifyTag(Tags.GENERAL_NAME).single().asSequence()).children.map {
                        RelativeDistinguishedName.decodeFromTlv(it.asSet()).also { src.nextChild() }
                    }
                } else {
                    null
                }
            }

            val requests = src.nextChild().asSequence().children.map {
                    Request.decodeFromTlv(it.asSequence())
            }

            val extensions = if (src.hasMoreChildren()) {
                ((src.nextChild().asExplicitlyTagged()).verifyTag(Tags.EXTENSIONS.tagValue)
                    .single().asSequence()).children.map {
                    X509CertificateExtension.decodeFromTlv(it.asSequence())
                }
            } else null

            return TbsRequest(version, name, requests, extensions)
        }
    }
}

data class OCSPRequest (
    val tbsRequest: TbsRequest
) : PemEncodable<Asn1Sequence> {

    override val canonicalPEMBoundary: String = EB_STRINGS.DEFAULT

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence{
        +tbsRequest
    }

    companion object : PemDecodable<Asn1Sequence, OCSPRequest>(EB_STRINGS.DEFAULT) {

        private object EB_STRINGS {
            const val DEFAULT = "OCSP REQUEST"
        }

        override fun doDecode(src: Asn1Sequence): OCSPRequest = OCSPRequest(TbsRequest.decodeFromTlv(src.nextChild().asSequence()))

        fun decodeFromByteArray(src: ByteArray): OCSPRequest? = catchingUnwrapped {
            OCSPRequest.decodeFromTlv(Asn1Element.parse(src) as Asn1Sequence)
        }.getOrNull() ?: catchingUnwrapped {
            OCSPRequest.decodeFromTlv(Asn1Element.parse(src.decodeToByteArray(Base64())) as Asn1Sequence)
        }.getOrNull() ?: OCSPRequest.decodeFromPem(src.decodeToString()).getOrNull()
    }
}