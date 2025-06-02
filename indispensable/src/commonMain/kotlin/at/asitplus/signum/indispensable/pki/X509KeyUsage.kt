package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1BitString

enum class X509KeyUsage(val bitNumber: Long) {
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
        fun doDecode(encodedValue: Asn1BitString): Set<X509KeyUsage> {
            val booleans = encodedValue.toBitSet()
            val result = mutableSetOf<X509KeyUsage>()
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
