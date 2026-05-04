package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1PemDecodable
import at.asitplus.awesn1.Asn1PemEncodable
import at.asitplus.awesn1.Asn1Sequence


/**
 * Key agreement public value. Must be PEM encodable/decodable.
 */
sealed interface KeyAgreementPublicValue : Asn1PemEncodable<Asn1Sequence> {
    /**
     * ECDH key agreement public value. Is always an EC public key, thus comes with [asCryptoPublicKey]
     */
    interface ECDH: KeyAgreementPublicValue {
        /**
         * Returns this value ad a [CryptoPublicKey.EC]
         */
        fun asCryptoPublicKey(): CryptoPublicKey.EC
    }
    companion object : Asn1PemDecodable<Asn1Sequence, ECDH> {
        override fun doDecode(src: Asn1Sequence) = CryptoPublicKey.doDecode(src) as CryptoPublicKey.EC
        override val pemLabel: String
            get() = "PUBLIC KEY"
    }
}
