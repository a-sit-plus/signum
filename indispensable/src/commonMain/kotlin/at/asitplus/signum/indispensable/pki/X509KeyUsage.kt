package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1BitString

enum class X509KeyUsage(val bitNumber: Long, val description: String) {
    DIGITAL_SIGNATURE(0, "Digital Signature"),
    NON_REPUDIATION(1, "Non-repudiation"),
    KEY_ENCIPHERMENT(2, "Key Encipherment"),
    DATA_ENCIPHERMENT(3, "Data Encipherment"),
    KEY_AGREEMENT(4, "Key Agreement"),
    KEY_CERT_SIGN(5, "Key Certificate Sign"),
    CRL_SIGN(6, "CRL Sign"),
    ENCIPHER_ONLY(7, "Encipher Only"),
    DECIPHER_ONLY(8, "Decipher Only")

    ;

    companion object {
        fun decodeSet(encodedValue: Asn1BitString): Set<X509KeyUsage> {
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
