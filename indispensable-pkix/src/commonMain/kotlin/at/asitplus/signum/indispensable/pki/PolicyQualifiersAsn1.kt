package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.SignumEncodingHelpers.encodeTo
import at.asitplus.signum.indispensable.pki.extn.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ListSerializer

/** ASN.1 adapters for understood qualifier OIDs; unrecognized payloads retain their original source. */
interface PolicyQualifierAsn1Provider {
    fun decodeFromAsn1(oid: ObjectIdentifier, value: Asn1Element): PolicyQualifierInfo?
    fun encodeToAsn1(value: PolicyQualifierInfo): Asn1Element?
}

internal fun decodeCertificatePolicies(bytes: ByteArray): List<PolicyInformation> =
    Signum.Der.decodeFromByteArray(ListSerializer(PolicyInformation.Asn1Representation.serializer()), bytes).map { wire ->
        PolicyInformation(wire.oid, wire.qualifiers.map { src ->
            decodeFrom<PolicyQualifierInfo.Companion.Asn1Representation, PolicyQualifierInfo> {
                try {
                    ServiceLoader.load<PolicyQualifierAsn1Provider>().get(it) { decodeFromAsn1(it.oid, it.qualifier) }
                } catch (failure: UnsupportedCryptoException) { PolicyQualifierInfo(it.oid, failure) }
            }(src)
        })
    }

internal fun encodeCertificatePolicies(policies: List<PolicyInformation>): ByteArray =
    Signum.Der.encodeToByteArray(ListSerializer(PolicyInformation.Asn1Representation.serializer()), policies.map { policy ->
        PolicyInformation.Asn1Representation(policy.oid, policy.policyQualifiers.map { q ->
            q.encodeTo<PolicyQualifierInfo.Companion.Asn1Representation, PolicyQualifierInfo> {
                PolicyQualifierInfo.Companion.Asn1Representation(it.oid, ServiceLoader.load<PolicyQualifierAsn1Provider>().get(it, PolicyQualifierAsn1Provider::encodeToAsn1))
            }
        })
    })

internal object BuiltinPolicyQualifiers : PolicyQualifierAsn1Provider {
    override fun decodeFromAsn1(oid: ObjectIdentifier, value: Asn1Element): PolicyQualifierInfo? =
        when (oid) {
            KnownOIDs.cps -> CpsUri(Signum.Der.decodeFromTlv(
                Asn1String.IA5.serializer(), value.assertTag(Asn1Element.Tag.STRING_IA5),
            ).value)
            KnownOIDs.unotice -> Signum.Der.decodeFromTlv(UserNotice.Asn1Representation.serializer(), value).let { notice ->
                UserNotice(notice.noticeRef?.let { NoticeReference(it.organization.value, it.numbers.map { n -> n.toBigInteger() }) }, notice.explicitText?.value)
            }
            else -> null
        }

    override fun encodeToAsn1(value: PolicyQualifierInfo): Asn1Element? = when (value) {
        is CpsUri -> Signum.Der.encodeToTlv(Asn1String.IA5.serializer(), Asn1String.IA5(value.uri.toString()))
        is UserNotice -> Signum.Der.encodeToTlv(UserNotice.Asn1Representation.serializer(), UserNotice.Asn1Representation(
            value.noticeRef?.let { NoticeReference.Asn1Representation(Asn1String.UTF8(it.organization), it.noticeNumbers.map { n -> n.toAsn1Integer() }) },
            value.explicitText?.let { Asn1String.UTF8(it) },
        ))
        else -> null
    }
}
