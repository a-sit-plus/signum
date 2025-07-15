package at.asitplus.signum.indispensable.pki

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.PemDecodable
import at.asitplus.signum.indispensable.asn1.PemEncodable
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decode
import at.asitplus.signum.indispensable.asn1.encoding.decodeFromAsn1ContentBytes
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.signum.indispensable.asn1.encoding.parse
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray


data class RevokedInfo(
    val revocationTime: Asn1Time,
    val revocationReason: Asn1Element?
) : Asn1Encodable<Asn1ExplicitlyTagged> {

    override fun encodeToTlv(): Asn1ExplicitlyTagged = Asn1.ExplicitlyTagged(SingleResponse.CertStatus.REVOKED.tag) {
        +revocationTime
        revocationReason?.let { +it }
    }

    companion object : Asn1Decodable<Asn1ExplicitlyTagged, RevokedInfo> {

        override fun doDecode(src: Asn1ExplicitlyTagged): RevokedInfo {
            src.verifyTag(SingleResponse.CertStatus.REVOKED.tag)
            val time = Asn1Time.decodeFromTlv(src.nextChild().asPrimitive())
            val reason = if (src.hasMoreChildren()) {
                src.nextChild()
            } else null
            return RevokedInfo(time, reason)
        }
    }
}

data class SingleResponse(
    val certId: CertId,
    val certStatus: CertStatus,
    val certStatusData: Asn1Element,
    val thisUpdate: Asn1Time,
    val nextUpdate: Asn1Time? = null,
    val singleExtensions: List<X509CertificateExtension>? = null
) : Asn1Encodable<Asn1Sequence> {

    val revokedInfo by lazy {
        return@lazy RevokedInfo.decodeFromTlv(certStatusData.asExplicitlyTagged())
    }

    enum class CertStatus(val tag: ULong) {
        GOOD(0uL),
        REVOKED(1uL),
        UNKNOWN(2uL);

        companion object {
            private val tagToStatus = entries.associateBy { it.tag }

            fun fromTag(tag: ULong): CertStatus =
                tagToStatus[tag] ?: throw Asn1StructuralException("Unknown CertStatus tag: $tag")
        }
    }

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence{
        +certId
        +certStatusData
        +thisUpdate
        nextUpdate?.let {
            +Asn1.ExplicitlyTagged(Tags.NEXT_UPDATE.tagValue) {
                +nextUpdate
            }
        }
        singleExtensions?.let {
            if (it.isNotEmpty()) {
                +Asn1.ExplicitlyTagged(Tags.EXTENSIONS.tagValue) {
                    +Asn1.Sequence {
                        it.forEach { ext -> +ext }
                    }
                }
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, SingleResponse> {

        object Tags {
            val NEXT_UPDATE = Asn1.ExplicitTag(0uL)
            val EXTENSIONS = Asn1.ExplicitTag(1uL)
        }

        override fun doDecode(src: Asn1Sequence): SingleResponse {
            val certId = CertId.decodeFromTlv(src.nextChild().asSequence())
            val data = src.nextChild()
            val status = CertStatus.fromTag(data.tag.tagValue)

            val update = Asn1Time.decodeFromTlv(src.nextChild().asPrimitive())

            val nextUpdate = if (src.hasMoreChildren() && src.peek()?.tag == Tags.NEXT_UPDATE) {
                Asn1Time.decodeFromTlv(src.nextChild().asExplicitlyTagged().nextChild().asPrimitive())
            } else null

            val extensions = if (src.hasMoreChildren()) {
                (src.nextChild().asExplicitlyTagged().verifyTag(Tags.EXTENSIONS.tagValue)
                    .single().asSequence()).children.map {
                        X509CertificateExtension.decodeFromTlv(it.asSequence())
                    }
            } else null

            return SingleResponse(
                certId,
                status,
                data,
                update,
                nextUpdate, extensions
            )
        }

    }
}

data class ResponseData(
    val version: Int? = 2,
    val byName: List<RelativeDistinguishedName>? = null,
    val byKey: ByteArray? = null,
    val producedAt: Asn1Time,
    val responses: List<SingleResponse>,
    val responsesExtensions: List<X509CertificateExtension>? = null
) : Asn1Encodable<Asn1Sequence> {

    init {
        if (byName == null && byKey == null) throw Asn1StructuralException("Invalid ResponderID in Response Data.")
    }

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence{
        version?.let { Asn1.ExplicitlyTagged(Tags.VERSION.tagValue) { +Asn1.Int(version) } }
        byName?.let {
            +Asn1.ExplicitlyTagged(1uL) {
                +Asn1.Sequence {
                    byName.forEach { +it }
                }
            }
        }
        byKey?.let {
            +Asn1.ExplicitlyTagged(2uL) {
                +Asn1Primitive(Asn1Element.Tag.OCTET_STRING, byKey)
            }
        }
        +producedAt
        +Asn1.Sequence { responses.forEach { +it } }
        responsesExtensions?.let {
            if (it.isNotEmpty()) {
                +Asn1.ExplicitlyTagged(Tags.EXTENSIONS.tagValue) {
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

        other as ResponseData

        if (version != other.version) return false
        if (byName != other.byName) return false
        if (byKey != null) {
            if (other.byKey == null) return false
            if (!byKey.contentEquals(other.byKey)) return false
        } else if (other.byKey != null) return false
        if (producedAt != other.producedAt) return false
        if (responses != other.responses) return false
        if (responsesExtensions != other.responsesExtensions) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version ?: 0
        result = 31 * result + (byName?.hashCode() ?: 0)
        result = 31 * result + (byKey?.contentHashCode() ?: 0)
        result = 31 * result + producedAt.hashCode()
        result = 31 * result + responses.hashCode()
        result = 31 * result + (responsesExtensions?.hashCode() ?: 0)
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, ResponseData> {

        object Tags {
            val VERSION = Asn1.ExplicitTag(0uL)
            val EXTENSIONS = Asn1.ExplicitTag(1uL)
        }

        override fun doDecode(src: Asn1Sequence): ResponseData {
            val version = src.peek().let {
                if (it is Asn1ExplicitlyTagged && runCatching { it.verifyTag(Tags.VERSION) }.isSuccess) {
                    it.asPrimitive().decodeToInt()
                        .also { src.nextChild() }
                } else {
                    null
                }
            }

            val responderId = src.nextChild()
            val byName: List<RelativeDistinguishedName>?
            val byKey: ByteArray?
            when (responderId) {
                is Asn1ExplicitlyTagged -> {
                    when (responderId.tag.tagValue) {
                        1uL -> {
                            byName = responderId.nextChild().asSequence().children.map {
                                RelativeDistinguishedName.decodeFromTlv(it.asSet())
                            }
                            byKey = null
                        }
                        2uL -> {
                            byKey = responderId.nextChild().asPrimitive().decode(
                                Asn1Element.Tag.OCTET_STRING
                            ) { it }
                            byName = null
                        }
                        else -> throw Asn1StructuralException("Invalid tag for ResponderID: ${responderId.tag}")
                    }
                }
                else -> throw Asn1StructuralException("ResponderID must be explicitly tagged")
            }

            val time = Asn1Time.decodeFromTlv(src.nextChild().asPrimitive())

            val responses = src.nextChild().asSequence().children.map { SingleResponse.decodeFromTlv(it.asSequence()) }

            val extensions = if (src.hasMoreChildren()) {
                src.nextChild().asExplicitlyTagged().verifyTag(Tags.EXTENSIONS.tagValue)
                    .single().asSequence().children.map {
                        X509CertificateExtension.decodeFromTlv(it.asSequence())
                    }
            } else null

            return ResponseData(
                version,
                byName,
                byKey,
                time,
                responses,
                extensions
            )
        }
    }
}

data class BasicOCSPResponse(
    val tbsResponseData: ResponseData,
    val signatureAlgorithm: X509SignatureAlgorithm,
    val signature: CryptoSignature,
    val certs: List<X509Certificate>? = null
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +tbsResponseData
        +signatureAlgorithm
        +signature.x509Encoded
        certs?.let {
            if (it.isNotEmpty()) {
                +Asn1.ExplicitlyTagged(Tags.CERTS.tagValue) {
                    +Asn1.Sequence {
                        it.forEach { cert -> +cert }
                    }
                }
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, BasicOCSPResponse> {

        object Tags {
            val CERTS = Asn1.ExplicitTag(0uL)
        }
        override fun doDecode(src: Asn1Sequence): BasicOCSPResponse {
            val responseData = ResponseData.decodeFromTlv(src.nextChild().asSequence())
            val alg = X509SignatureAlgorithm.decodeFromTlv(src.nextChild().asSequence())
            val signature = CryptoSignature.fromX509Encoded(alg, src.nextChild().asPrimitive())
            val certs = if (src.hasMoreChildren()) {
                src.nextChild().asExplicitlyTagged().verifyTag(Tags.CERTS.tagValue)
                    .single().asSequence().children.map {
                        X509Certificate.decodeFromTlv(it.asSequence())
                    }
            } else null

            return BasicOCSPResponse(
                responseData,
                alg,
                signature,
                certs
            )
        }
    }
}

data class ResponseBytes(
    override val oid: ObjectIdentifier,
    val basicOCSPResponse: BasicOCSPResponse
) : Identifiable, Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +oid
        +Asn1.OctetStringEncapsulating { +basicOCSPResponse }
    }

    companion object : Asn1Decodable<Asn1Sequence, ResponseBytes> {

        override fun doDecode(src: Asn1Sequence): ResponseBytes {
            val oid = ObjectIdentifier.decodeFromTlv(src.nextChild().asPrimitive())
            if (oid != KnownOIDs.ocspBasic) throw Asn1StructuralException("Invalid Basic OCSP Response.")

            val response = BasicOCSPResponse.decodeFromDer(src.nextChild().asOctetString().content)
            return ResponseBytes(oid, response)
        }

    }
}


data class OCSPResponse(
    val status: OCSPResponseStatus,
    val responseBytes: ResponseBytes? = null
) : PemEncodable<Asn1Sequence> {

    enum class OCSPResponseStatus(val tag: ULong) {
        SUCCESSFUL(0uL),
        MALFORMED_REQUEST(1uL),
        INTERNAL_ERROR(2uL),
        TRY_LATER(3uL),
        SIG_REQUIRED(5uL),
        UNAUTHORIZED(6uL);

        companion object {
            private val tagToStatus = entries.associateBy { it.tag }

            fun parseStatus(element: Asn1Primitive): OCSPResponseStatus {
                if (element.tag != Asn1Element.Tag.ENUM) throw Asn1StructuralException("Invalid OCSP Response Status")

                return tagToStatus[ULong.decodeFromAsn1ContentBytes(element.content)]
                        ?: throw Asn1StructuralException("Invalid status choice.")
            }
        }

    }

    override val canonicalPEMBoundary: String = EB_STRINGS.DEFAULT

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +Asn1Primitive(Asn1Element.Tag.ENUM, status.tag.encodeToAsn1ContentBytes())
        responseBytes?.let {
            +Asn1.ExplicitlyTagged(Tags.RESPONSE_BYTES.tagValue) {
                +responseBytes
            }
        }
    }

    companion object : PemDecodable<Asn1Sequence, OCSPResponse>(EB_STRINGS.DEFAULT) {

        private object EB_STRINGS {
            const val DEFAULT = "OCSP RESPONSE"
        }

        object Tags {
            val RESPONSE_BYTES = Asn1.ExplicitTag(0uL)
        }

        override fun doDecode(src: Asn1Sequence): OCSPResponse {
            val status = OCSPResponseStatus.parseStatus(src.nextChild().asPrimitive())
            val response = if (src.hasMoreChildren())
                ResponseBytes.decodeFromTlv(src.nextChild().asExplicitlyTagged().verifyTag(Tags.RESPONSE_BYTES.tagValue).single().asSequence())
            else null

            return OCSPResponse(status, response)
        }

        fun decodeFromByteArray(src: ByteArray): OCSPResponse? = catchingUnwrapped {
            OCSPResponse.decodeFromTlv(Asn1Element.parse(src) as Asn1Sequence)
        }.getOrNull() ?: catchingUnwrapped {
            OCSPResponse.decodeFromTlv(Asn1Element.parse(src.decodeToByteArray(Base64())) as Asn1Sequence)
        }.getOrNull() ?: OCSPResponse.decodeFromPem(src.decodeToString()).getOrNull()
    }
}