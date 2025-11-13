package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1BitString
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1BitString
import at.asitplus.signum.indispensable.asn1.keyUsage
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
 * Defines the purpose of the key contained in the cert
 * */
class KeyUsageExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val keyUsage: Set<KeyUsage>
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        keyUsage: Set<KeyUsage>
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), keyUsage)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        override fun doDecode(src: Asn1Sequence): KeyUsageExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.keyUsage) throw Asn1StructuralException(message = "Expected KeyUsage extension (OID: ${KnownOIDs.keyUsage}), but found OID: ${base.oid}")

            val keyUsage = KeyUsage.parseExtension(
                base.value.asEncapsulatingOctetString()
                .single()
                .asPrimitive()
                .asAsn1BitString()
            )

            return KeyUsageExtension(base, keyUsage)
        }
    }
}

enum class KeyUsage(val bitNumber: Long) {
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
        fun parseExtension(encodedValue: Asn1BitString): Set<KeyUsage> {
            val booleans = encodedValue.toBitSet()
            val result = mutableSetOf<KeyUsage>()
            for (usage in entries) {
                if (usage.bitNumber < booleans.length()) {
                    if (booleans[usage.bitNumber]) {
                        result.add(usage)
                    }
                }
            }
            return result
        }
    }
}
