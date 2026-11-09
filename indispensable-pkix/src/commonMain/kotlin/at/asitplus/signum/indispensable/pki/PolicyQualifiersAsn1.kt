package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.SignumEncodingHelpers.encodeTo
import at.asitplus.signum.indispensable.pki.extn.*
import kotlinx.serialization.*
import kotlinx.serialization.encoding.*

/** ASN.1 adapters for understood qualifier OIDs; unrecognized payloads retain their original source. */
interface PolicyQualifierAsn1Provider {
    fun decodeFromAsn1(oid: ObjectIdentifier, value: Asn1Element): PolicyQualifierInfo?
    fun encodeToAsn1(value: PolicyQualifierInfo): Asn1Element?
}

@Serializable
private data class QualifierWire(val oid: ObjectIdentifier, val qualifier: Asn1Element)
@Serializable
private data class PolicyWire(val oid: ObjectIdentifier, val qualifiers: List<QualifierWire> = emptyList())
@Serializable
private data class NoticeWire(val noticeRef: NoticeReferenceWire? = null, val explicitText: Asn1String? = null)
@Serializable
private data class NoticeReferenceWire(val organization: Asn1String, val numbers: List<Asn1Integer>)

internal object PolicyInformationAsn1Serializer : KSerializer<PolicyInformation> {
    override val descriptor get() = PolicyWire.serializer().descriptor
    override fun deserialize(decoder: Decoder): PolicyInformation {
        val wire = decoder.decodeSerializableValue(PolicyWire.serializer())
        return PolicyInformation(wire.oid, wire.qualifiers.map { src ->
            decodeFrom<QualifierWire, PolicyQualifierInfo> {
                try {
                    ServiceLoader.load<PolicyQualifierAsn1Provider>().get(it) { decodeFromAsn1(it.oid, it.qualifier) }
                } catch (failure: UnsupportedCryptoException) { OpaquePolicyQualifierInfo(it.oid, failure) }
            }(src)
        })
    }
    override fun serialize(encoder: Encoder, value: PolicyInformation) {
        val qualifiers = value.policyQualifiers.map { q ->
            q.encodeTo<QualifierWire, PolicyQualifierInfo> {
                QualifierWire(it.oid, ServiceLoader.load<PolicyQualifierAsn1Provider>().get(it, PolicyQualifierAsn1Provider::encodeToAsn1))
            }
        }
        encoder.encodeSerializableValue(PolicyWire.serializer(), PolicyWire(value.oid, qualifiers))
    }
}

internal object BuiltinPolicyQualifiers : PolicyQualifierAsn1Provider {
    override fun decodeFromAsn1(oid: ObjectIdentifier, value: Asn1Element): PolicyQualifierInfo? = when (oid) {
        KnownOIDs.cps -> CpsUri(Signum.Der.decodeFromTlv(Asn1String.IA5.serializer(), value).value)
        KnownOIDs.unotice -> Signum.Der.decodeFromTlv(NoticeWire.serializer(), value).let { notice ->
            UserNotice(notice.noticeRef?.let { NoticeReference(it.organization.value, it.numbers.map { n -> n.toBigInteger() }) }, notice.explicitText?.value)
        }
        else -> null
    }
    override fun encodeToAsn1(value: PolicyQualifierInfo): Asn1Element? = when (value) {
        is CpsUri -> Signum.Der.encodeToTlv(Asn1String.IA5.serializer(), Asn1String.IA5(value.uri.toString()))
        is UserNotice -> Signum.Der.encodeToTlv(NoticeWire.serializer(), NoticeWire(
            value.noticeRef?.let { NoticeReferenceWire(Asn1String.UTF8(it.organization), it.noticeNumbers.map { n -> n.toAsn1Integer() }) },
            value.explicitText?.let { Asn1String.UTF8(it) },
        ))
        else -> null
    }
}
