package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension

/**
 * Defines the purpose of the key contained in the cert
 * */
data class KeyUsage(
    val keyUsage: Set<UsageBit>,
    override val critical: Boolean = true,
) : CertificateExtension {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.keyUsage
    }

    constructor(vararg usageBits: UsageBit) : this(usageBits.toSet())
}

/**
 * Bit index to mark key usage in a bit string.
 * [index] is [Long] to be directly usable with  [at.asitplus.awesn1.BitSet].
 */
enum class UsageBit(val index: Long) {
    DIGITAL_SIGNATURE(0),
    NON_REPUDIATION(1),
    KEY_ENCIPHERMENT(2),
    DATA_ENCIPHERMENT(3),
    KEY_AGREEMENT(4),
    KEY_CERT_SIGN(5),
    CRL_SIGN(6),
    ENCIPHER_ONLY(7),
    DECIPHER_ONLY(8)
    ;

    companion object {
        fun parseExtension(encodedValue: Asn1BitString): Set<UsageBit> {
            val result = mutableSetOf<UsageBit>()
            for (usage in entries) {
                if (usage.index < encodedValue.sizeBits) {
                    if (encodedValue[usage.index]) {
                        result.add(usage)
                    }
                }
            }
            return result
        }
    }
}
