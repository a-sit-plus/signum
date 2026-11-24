package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.signum.Signum
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.SignumEncodingHelpers.encodeWith
import at.asitplus.signum.indispensable.pki.extn.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer

/** ASN.1 adapters for understood qualifier OIDs; unrecognized payloads retain their original source. */
interface PolicyQualifierAsn1Provider {
    fun decodeFromAsn1(value: Asn1PolicyQualifier): PolicyQualifierInfo?
    fun encodeToAsn1(value: PolicyQualifierInfo): Asn1PolicyQualifier?
}

/** ASN.1 schema from [RFC 5280, Section 4.2.1.4](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4). */
@Serializable
data class Asn1PolicyQualifier(override val oid: ObjectIdentifier, val qualifier: Asn1Element) : Identifiable

internal fun decodeCertificatePolicies(bytes: ByteArray): List<PolicyInformation> =
    Signum.Der.decodeFromByteArray(ListSerializer(PolicyInformation.Asn1Representation.serializer()), bytes).map { wire ->
        PolicyInformation(wire.oid, wire.qualifiers.map(decodeFrom<Asn1PolicyQualifier, PolicyQualifierInfo> { source ->
            try {
                ServiceLoader.load<PolicyQualifierAsn1Provider>().get(source, PolicyQualifierAsn1Provider::decodeFromAsn1)
            } catch (failure: UnsupportedCryptoException) {
                PolicyQualifierInfo.Unknown(source.oid, source, failure)
            }
        }))
    }

internal fun encodeCertificatePolicies(policies: List<PolicyInformation>): ByteArray =
    Signum.Der.encodeToByteArray(ListSerializer(PolicyInformation.Asn1Representation.serializer()), policies.map { policy ->
        PolicyInformation.Asn1Representation(policy.oid, policy.policyQualifiers.map { q ->
            q.encodeWith<PolicyQualifierAsn1Provider, Asn1PolicyQualifier, PolicyQualifierInfo> {
                encodeToAsn1(it)?.also { encoded ->
                    check(encoded.oid == it.oid) { "Encoded policy qualifier OID ${encoded.oid} does not match ${it.oid}" }
                }
            }
        })
    })

internal object BuiltinPolicyQualifiers : PolicyQualifierAsn1Provider {
    override fun decodeFromAsn1(value: Asn1PolicyQualifier): PolicyQualifierInfo? =
        when (value.oid) {
            KnownOIDs.cps -> CpsUri(Signum.Der.decodeFromTlv(
                Asn1String.IA5.serializer(), value.qualifier.assertTag(Asn1Element.Tag.STRING_IA5),
            ).value)
            KnownOIDs.unotice -> Signum.Der.decodeFromTlv(UserNotice.Asn1Representation.serializer(), value.qualifier).let { notice ->
                UserNotice(notice.noticeRef?.let { NoticeReference(it.organization.value, it.numbers.map { n -> n.toBigInteger() }) }, notice.explicitText?.value)
            }
            else -> null
        }

    override fun encodeToAsn1(value: PolicyQualifierInfo): Asn1PolicyQualifier? {
        val qualifier = when (value) {
            is CpsUri -> Signum.Der.encodeToTlv(Asn1String.IA5.serializer(), Asn1String.IA5(value.uri.toString()))
            is UserNotice -> Signum.Der.encodeToTlv(UserNotice.Asn1Representation.serializer(), UserNotice.Asn1Representation(
                value.noticeRef?.let { NoticeReference.Asn1Representation(Asn1String.UTF8(it.organization), it.noticeNumbers.map { n -> n.toAsn1Integer() }) },
                value.explicitText?.let { Asn1String.UTF8(it) },
            ))
            else -> return null
        }
        return Asn1PolicyQualifier(value.oid, qualifier)
    }
}
