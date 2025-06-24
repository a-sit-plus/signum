package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1BitString
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

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
        override fun doDecode(src: Asn1Sequence): KeyUsageExtension {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.keyUsage) throw Asn1StructuralException(message = "This extension is not KeyUsage extension.")

            val inner = base.value.asEncapsulatingOctetString()
                .nextChildOrNull()
                ?.takeIf { it.tag == Asn1Element.Tag.BIT_STRING }
                ?.asPrimitive()
                ?: throw Asn1StructuralException("Invalid or missing BitString in KeyUsage extension.")

            val keyUsage = KeyUsage.parseExtension(Asn1BitString.decodeFromTlv(inner))

            if (base.value.asEncapsulatingOctetString().hasMoreChildren()) throw Asn1StructuralException("Invalid KeyUsageExtension found (>1 children): ${base.value.toDerHexString()}")

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
