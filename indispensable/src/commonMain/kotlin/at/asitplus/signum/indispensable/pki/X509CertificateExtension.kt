package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1PrimitiveOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Bool
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.pki.pkiExtensions.BasicConstraintsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.CertificatePoliciesExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.InhibitAnyPolicyExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsageExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.NameConstraintsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.PolicyConstraintsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.PolicyMappingsExtension
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update


/**
 * X.509 Certificate Extension
 */
open class X509CertificateExtension @Throws(Asn1Exception::class) private constructor(
    override val oid: ObjectIdentifier,
    val value: Asn1Element,
    val critical: Boolean = false
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    init {
        if (value.tag != Asn1Element.Tag.OCTET_STRING) throw Asn1TagMismatchException(Asn1Element.Tag.OCTET_STRING, value.tag)
    }

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1EncapsulatingOctetString
    ) : this(oid, value, critical)

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1PrimitiveOctetString
    ) : this(oid, value, critical)

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        if (critical) +Bool(true)
        +value
    }

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        private val _registeredExtensionDecoders = MutableStateFlow(
            mapOf<ObjectIdentifier, (Asn1Sequence, Asn1Element.Tag?) -> X509CertificateExtension>(
                KnownOIDs.basicConstraints_2_5_29_19 to { seq, tag -> BasicConstraintsExtension.decodeFromTlv(seq, tag) },
                KnownOIDs.nameConstraints_2_5_29_30 to { seq, tag -> NameConstraintsExtension.decodeFromTlv(seq, tag) },
                KnownOIDs.policyConstraints_2_5_29_36 to { seq, tag -> PolicyConstraintsExtension.decodeFromTlv(seq, tag) },
                KnownOIDs.certificatePolicies_2_5_29_32 to { seq, tag -> CertificatePoliciesExtension.decodeFromTlv(seq, tag) },
                KnownOIDs.policyMappings to { seq, tag -> PolicyMappingsExtension.decodeFromTlv(seq, tag) },
                KnownOIDs.inhibitAnyPolicy to { seq, tag -> InhibitAnyPolicyExtension.decodeFromTlv(seq, tag) },
                KnownOIDs.keyUsage to { seq, tag -> KeyUsageExtension.decodeFromTlv(seq, tag) }
            )
        )
        val registeredExtensionDecoders: Map<ObjectIdentifier, (Asn1Sequence, Asn1Element.Tag?) -> X509CertificateExtension>
            get() = _registeredExtensionDecoders.value

        fun register(
            oid: ObjectIdentifier,
            decoder: (Asn1Sequence, Asn1Element.Tag?) -> X509CertificateExtension
        ) {
            _registeredExtensionDecoders.update { it + (oid to decoder) }
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {

            val oid = next().asPrimitive().readOid()
            return registeredExtensionDecoders[oid]?.invoke(src, null) ?: decodeBase(src)
        }

        @Throws(Asn1Exception::class)
        fun decodeBase(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {
            val oid = next().asPrimitive().readOid()
            val critical =
                if (peek()?.tag == Asn1Element.Tag.BOOL) next().asPrimitive().content[0] == 0xff.toByte() else false

            val value = next()
            return X509CertificateExtension(oid, value, critical)
        }
    }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null) return false
        if (this::class != other::class) return false

        other as X509CertificateExtension

        if (oid != other.oid) return false
        if (critical != other.critical) return false
        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + critical.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }
}