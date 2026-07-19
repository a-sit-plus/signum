package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.encoding.parse
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Defines the purpose of the key contained in the cert
 * */
class KeyUsage internal constructor(
    asn1Representation: Awesn1X509CertificateExtension,
    val keyUsage: Set<UsageBit>,
) : X509CertificateExtension(asn1Representation) {

    constructor(vararg usageBits: UsageBit) : this(
        //TODO possibly nullable
        asn1Representation = Awesn1X509CertificateExtension(
            oid = KnownOIDs.keyUsage, critical = true,
            // extnValue is the DER of a BIT STRING (what fromAsn1Representation parses back) — NOT the
            // raw BitSet bytes, which would fail to re-decode and silently fall back to generic.
            value = Asn1BitString(BitSet().apply { usageBits.forEach { this.set(it.index) } }).encodeToTlv().derEncoded
        ),
        keyUsage = usageBits.toSet()
    )

    companion object : CertificateExtension.Descriptor, at.asitplus.awesn1.serialization.OidProvider<KeyUsage> {
        override val oid get() = KnownOIDs.keyUsage


        override fun fromAsn1Representation(src: Awesn1X509CertificateExtension): KeyUsage {
            val bitString = Asn1Element.parse(src.value).asPrimitive().asAsn1BitString()
            return KeyUsage(src, UsageBit.parseExtension(bitString))
        }
    }
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
            val booleans = encodedValue.toBitSet()
            val result = mutableSetOf<UsageBit>()
            for (usage in entries) {
                if (usage.index < booleans.length()) {
                    if (booleans[usage.index]) {
                        result.add(usage)
                    }
                }
            }
            return result
        }
    }
}
