package at.asitplus.signum.indispensable.pki.attestation

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decodeToEnum
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.signum.indispensable.pki.X509Certificate

/**
 * Attestation certificate extension [used by Google](https://source.android.com/docs/security/features/keystore/attestation#schema).
 * While we could use sophisticated sanity checks to ensure
 * that only valid extensions that conform to the schema in every aspect,
 * the reality is ugly, with device manufacturers being very  _creative_ about
 * how and what will be encoded into [softwareEnforced] and [hardwareEnforced].
 * Hence, we must be able to parse extensions that are structurally valid
 * at first glance, even when the actual values inside look like they have been through a meat grinder.
 * As long as those values we check for during attestation validation are there and contain the values
 * required for a successful assessment, we're golden!
 * Hence, barely any sanity checks are enforced.
 */
class AttestationKeyDescription(
    val attestationVersion: Int,
    val attestationSecurityLevel: SecurityLevel,
    val keyMintVersion: Int,
    val keyMintSecurityLevel: SecurityLevel,
    val attestationChallenge: ByteArray,
    val uniqueId: ByteArray,
    val softwareEnforced: AuthorizationList,
    val hardwareEnforced: AuthorizationList
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    /**
        alias for [keyMintVersion] for backwards compatibility for attestationVersion<=4
    */
    val keymasterVersion: Int get() = keyMintVersion

    /**
    alias for [keyMintSecurityLevel] for backwards compatibility for attestationVersion<=4
     */
    val keymasterSecurityLevel: SecurityLevel get() = keyMintSecurityLevel

    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(attestationVersion)
        +attestationSecurityLevel
        +Asn1.Int(keyMintVersion)
        +keyMintSecurityLevel
        +Asn1.OctetString(attestationChallenge)
        +Asn1.OctetString(uniqueId)
        +softwareEnforced
        +hardwareEnforced
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttestationKeyDescription) return false

        if (attestationVersion != other.attestationVersion) return false
        if (attestationSecurityLevel != other.attestationSecurityLevel) return false
        if (keyMintVersion != other.keyMintVersion) return false
        if (keyMintSecurityLevel != other.keyMintSecurityLevel) return false
        if (!attestationChallenge.contentEquals(other.attestationChallenge)) return false
        if (!uniqueId.contentEquals(other.uniqueId)) return false
        if (softwareEnforced != other.softwareEnforced) return false
        if (hardwareEnforced != other.hardwareEnforced) return false

        return true
    }

    override fun hashCode(): Int {
        var result = attestationVersion
        result = 31 * result + attestationSecurityLevel.hashCode()
        result = 31 * result + keyMintVersion
        result = 31 * result + keyMintSecurityLevel.hashCode()
        result = 31 * result + attestationChallenge.contentHashCode()
        result = 31 * result + uniqueId.contentHashCode()
        result = 31 * result + softwareEnforced.hashCode()
        result = 31 * result + hardwareEnforced.hashCode()
        return result
    }

    @OptIn(ExperimentalStdlibApi::class)
    override fun toString(): String {
        return "AttestationKeyDescription(attestationVersion=$attestationVersion, attestationSecurityLevel=$attestationSecurityLevel, keyMintVersion=$keyMintVersion" +
                ", keyMintSecurityLevel=$keyMintSecurityLevel, attestationChallenge=${attestationChallenge.toHexString()}, uniqueId=${uniqueId.toHexString()}, softwareEnforced=$softwareEnforced, hardwareEnforced=$hardwareEnforced)"
    }

    override val oid: ObjectIdentifier get() = AttestationKeyDescription.oid

    companion object : Identifiable, Asn1Decodable<Asn1Sequence, AttestationKeyDescription> {
        override val oid = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
        override fun doDecode(src: Asn1Sequence): AttestationKeyDescription {
            val version = src.nextChild().asPrimitive().decodeToInt()
            val attestationSecurityLevel =
                SecurityLevel.decodeFromTlv(src.nextChild().asPrimitive())
            val keyMintVersion = src.nextChild().asPrimitive().decodeToInt()
            val keyMintSecurityLevel = SecurityLevel.decodeFromTlv(src.nextChild().asPrimitive())
            val attestationChallenge = src.nextChild().asOctetString().content
            val uniqueId = src.nextChild().asOctetString().content
            val softwareEnforced = AuthorizationList.decodeFromTlv(src.nextChild().asSequence())
            val hardwareEnforced = AuthorizationList.decodeFromTlv(src.nextChild().asSequence())
            //if there's more, we don't are not allowed to care
            return AttestationKeyDescription(
                version,
                attestationSecurityLevel,
                keyMintVersion,
                keyMintSecurityLevel,
                attestationChallenge,
                uniqueId,
                softwareEnforced,
                hardwareEnforced
            )
        }
    }

    /**
     * Attestation security level [as defined by Google](https://source.android.com/docs/security/features/keystore/attestation#schema).
     */
    enum class SecurityLevel(val intValue: Int) : Asn1Encodable<Asn1Primitive> {
        SOFTWARE(0),
        TRUSTED_ENVIRONMENT(1),
        STRONGBOX(2);

        override fun encodeToTlv() =
            Asn1Primitive(BERTags.ENUMERATED, intValue.encodeToAsn1ContentBytes())

        companion object : Asn1Decodable<Asn1Primitive, SecurityLevel> {
            /**
             * returns the [SecurityLevel] represented by [intValue]
             */
            fun valueOf(intValue: Int) = entries.first { it.intValue == intValue }
            override fun doDecode(src: Asn1Primitive) = src.decodeToEnum<SecurityLevel>()
        }
    }
}

/**
 * Tries to parse an [AttestationKeyDescription] certificate extension, if present.
 * Never throws.
 */
val X509Certificate.androidAttestationExtension: AttestationKeyDescription?
    get() = tbsCertificate.extensions?.firstOrNull { it.oid == AttestationKeyDescription.oid }
        ?.let {
            catchingUnwrapped {
                AttestationKeyDescription.decodeFromTlv(
                    it.value.asEncapsulatingOctetString().children.first().asSequence()
                )
            }.getOrNull()
        }