package at.asitplus.signum.indispensable.pki

import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithmDescription
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
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decode
import at.asitplus.signum.indispensable.asn1.encoding.decodeFromAsn1ContentBytes
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.signum.indispensable.asn1.encoding.parse
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.requireSupported


data class RevokedInfo(
    val revocationTime: Asn1Time,
    val revocationReason: Asn1Element?
) : Asn1Encodable<Asn1ExplicitlyTagged> {

    override fun encodeToTlv(): Asn1ExplicitlyTagged = Asn1.ExplicitlyTagged(SingleResponse.CertStatus.REVOKED.tag) {
        +revocationTime
        revocationReason?.let { +it }
    }

    companion object : Asn1Decodable<Asn1ExplicitlyTagged, RevokedInfo> {

        override fun doDecode(src: Asn1ExplicitlyTagged): RevokedInfo = src.decodeRethrowing {
            src.verifyTag(SingleResponse.CertStatus.REVOKED.tag)
            val time = Asn1Time.decodeFromTlv(next().asPrimitive())
            val reason = if (hasNext()) {
                next()
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

        override fun doDecode(src: Asn1Sequence): SingleResponse = src.decodeRethrowing {
            val certId = CertId.decodeFromTlv(next().asSequence())
            val data = next()
            val status = CertStatus.fromTag(data.tag.tagValue)

            val update = Asn1Time.decodeFromTlv(next().asPrimitive())

            val nextUpdate = if (hasNext() && peek()?.tag == Tags.NEXT_UPDATE) {
                Asn1Time.decodeFromTlv(next().asExplicitlyTagged().decodeRethrowing { next().asPrimitive() })
            } else null

            val extensions = if (hasNext()) {
                (next().asExplicitlyTagged().verifyTag(Tags.EXTENSIONS.tagValue)
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

data class ResponderID(
    val byName: List<RelativeDistinguishedName>? = null,
    val byKey: ByteArray? = null
) : Asn1Encodable<Asn1ExplicitlyTagged> {

    init {
        if (byName == null && byKey == null) throw Asn1StructuralException("Invalid ResponderID in Response Data.")
    }

    override fun encodeToTlv(): Asn1ExplicitlyTagged {
        return when {
            byName != null -> Asn1.ExplicitlyTagged(1uL) {
                +Asn1.Sequence {
                    byName.forEach { +it }
                }
            }
            byKey != null -> Asn1.ExplicitlyTagged(2uL) {
                +Asn1Primitive(Asn1Element.Tag.OCTET_STRING, byKey)
            }
            else -> throw IllegalStateException("Either byName or byKey must be set")
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ResponderID

        if (byName != other.byName) return false
        if (byKey != null) {
            if (other.byKey == null) return false
            if (!byKey.contentEquals(other.byKey)) return false
        } else if (other.byKey != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = byName?.hashCode() ?: 0
        result = 31 * result + (byKey?.contentHashCode() ?: 0)
        return result
    }

    companion object : Asn1Decodable<Asn1ExplicitlyTagged, ResponderID> {

        override fun doDecode(src: Asn1ExplicitlyTagged): ResponderID = src.decodeRethrowing {
            when (src.tag.tagValue) {
                1uL -> ResponderID(
                    byName = next().asSequence().children.map {
                        RelativeDistinguishedName.decodeFromTlv(it.asSet())
                    },
                    byKey = null
                )
                2uL -> ResponderID(
                    byName = null,
                    byKey = next().asPrimitive().decode(Asn1Element.Tag.OCTET_STRING) { it }
                )
                else -> throw Asn1StructuralException("Invalid tag for ResponderID: ${src.tag}")
            }
        }
    }
}

data class ResponseData(
    val version: Int? = 2,
    val responderID: ResponderID,
    val producedAt: Asn1Time,
    val responses: List<SingleResponse>,
    val responsesExtensions: List<X509CertificateExtension>? = null
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence{
        version?.let { Asn1.ExplicitlyTagged(Tags.VERSION.tagValue) { +Asn1.Int(version) } }
        +responderID
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

    companion object : Asn1Decodable<Asn1Sequence, ResponseData> {

        object Tags {
            val VERSION = Asn1.ExplicitTag(0uL)
            val EXTENSIONS = Asn1.ExplicitTag(1uL)
        }

        override fun doDecode(src: Asn1Sequence): ResponseData = src.decodeRethrowing {
            val version = peek().let {
                if (it is Asn1ExplicitlyTagged && runCatching { it.verifyTag(Tags.VERSION) }.isSuccess) {
                    it.asPrimitive().decodeToInt()
                        .also { next() }
                } else {
                    null
                }
            }

            val responderId = ResponderID.decodeFromTlv(next().asExplicitlyTagged())

            val time = Asn1Time.decodeFromTlv(next().asPrimitive())

            val responses = next().asSequence().children.map { SingleResponse.decodeFromTlv(it.asSequence()) }

            val extensions = if (hasNext()) {
                next().asExplicitlyTagged().verifyTag(Tags.EXTENSIONS.tagValue)
                    .single().asSequence().children.map {
                        X509CertificateExtension.decodeFromTlv(it.asSequence())
                    }
            } else null

            return ResponseData(
                version,
                responderId,
                time,
                responses,
                extensions
            )
        }
    }
}

data class BasicOCSPResponse(
    val tbsResponseData: ResponseData,
    val signatureAlgorithm: X509SignatureAlgorithmDescription,
    val rawSignature: Asn1Primitive,
    val certs: List<X509Certificate>? = null
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +tbsResponseData
        +signatureAlgorithm
        +rawSignature
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

    val decodedSignature by lazy { catching {
        signatureAlgorithm.requireSupported()
        CryptoSignature.Companion.fromX509Encoded(signatureAlgorithm, rawSignature)
    }}

    companion object : Asn1Decodable<Asn1Sequence, BasicOCSPResponse> {

        object Tags {
            val CERTS = Asn1.ExplicitTag(0uL)
        }
        override fun doDecode(src: Asn1Sequence): BasicOCSPResponse = src.decodeRethrowing {
            val responseData = ResponseData.decodeFromTlv(next().asSequence())
            val sigAlg = X509SignatureAlgorithmDescription.decodeFromTlv(next().asSequence())
            val signature = next().asPrimitive()
            val certs = if (hasNext()) {
                next().asExplicitlyTagged().verifyTag(Tags.CERTS.tagValue)
                    .single().asSequence().children.map {
                        X509Certificate.decodeFromTlv(it.asSequence())
                    }
            } else null

            return BasicOCSPResponse(
                responseData,
                sigAlg,
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

        override fun doDecode(src: Asn1Sequence): ResponseBytes = src.decodeRethrowing {
            val oid = ObjectIdentifier.decodeFromTlv(next().asPrimitive())
            if (oid != KnownOIDs.ocspBasic) throw Asn1StructuralException("Invalid Basic OCSP Response.")

            val response = BasicOCSPResponse.decodeFromDer(next().asOctetString().content)
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

        override fun doDecode(src: Asn1Sequence): OCSPResponse = src.decodeRethrowing {
            val status = OCSPResponseStatus.parseStatus(next().asPrimitive())
            val response = if (hasNext())
                ResponseBytes.decodeFromTlv(next().asExplicitlyTagged().verifyTag(Tags.RESPONSE_BYTES.tagValue).single().asSequence())
            else null

            return OCSPResponse(status, response)
        }

        /**
         * Tries to decode [src] into an [OCSPResponse], by parsing the bytes directly as ASN.1 structure,
         * or by decoding from Base64, or by decoding to a String, stripping PEM headers
         * (`-----BEGIN OCSP RESPONSE-----`) and then decoding from Base64.
         */
        fun decodeFromByteArray(src: ByteArray): OCSPResponse? = catchingUnwrapped {
            OCSPResponse.decodeFromTlv(Asn1Element.parse(src).asSequence())
        }.getOrNull() ?: catchingUnwrapped {
            OCSPResponse.decodeFromTlv(Asn1Element.parse(src.decodeToByteArray(Base64())).asSequence())
        }.getOrNull() ?: OCSPResponse.decodeFromPem(src.decodeToString()).getOrNull()
    }
}